//! Governance gauges for alerting: held shared-guarantee receipts by state, the age of
//! the oldest, how full the fullest ledger is, and open escalations.
//!
//! The leader replica sweeps every tenant's exposure ledgers a page at a time and
//! publishes the gauges when a full pass completes, so a scrape never sees half a
//! pass. Other replicas export none of these series; alert rules aggregate with `max`,
//! which survives a leader change. Each hold is diagnosed (two reads) when first seen,
//! when its receipt flags change, and on every pass once an observation is recorded,
//! since those holds need a human and can still change state.
//!
//! Tenants are never labels. A hold older than [`HOLD_AGE_LOG_SECONDS`] is logged once,
//! with its tenant and resource digest but no arguments, so the SIEM can say whose it
//! is. Age is for paging only: elapsed time proves nothing about an effect, and no
//! state is resolved by waiting.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use contextos_contract::validation::{compare_contract_times, elapsed_millis};
use contextos_gateway::hold_census::{HOLD_STATES, HoldDiagnosis, receipt_fill};
use contextos_gateway::{Gateway, GatewayError};
use contextos_store::{AppendLog, DocumentStore};

use crate::metrics::Metrics;

/// A hold this old is logged once for the SIEM.
pub const HOLD_AGE_LOG_SECONDS: u64 = 900;

#[derive(Debug, Clone, Copy)]
pub struct SweepConfig {
    pub interval: Duration,
    /// Ledgers read per page.
    pub page: usize,
    /// Ledgers read per tick at most, across pages and tenants.
    pub ledgers_per_tick: usize,
}

impl Default for SweepConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(15),
            page: 100,
            ledgers_per_tick: 1000,
        }
    }
}

#[derive(Debug)]
struct Known {
    marks: (bool, bool, bool),
    diagnosis: HoldDiagnosis,
    logged: bool,
    pass: u64,
}

#[derive(Debug, Default)]
struct Totals {
    holds: BTreeMap<(String, &'static str), u64>,
    oldest: BTreeMap<String, String>,
    fill: BTreeMap<String, usize>,
    unreadable: u64,
}

/// One leader's sweep: where it is and what the current pass has seen.
#[derive(Debug)]
pub struct Census {
    tenants: Vec<String>,
    guarantees: Vec<String>,
    tenant_at: usize,
    cursor: Option<String>,
    pass: u64,
    known: HashMap<(String, String), Known>,
    totals: Totals,
}

fn unix_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

impl Census {
    #[must_use]
    pub fn new(mut tenants: Vec<String>, guarantees: Vec<String>) -> Self {
        tenants.sort();
        tenants.dedup();
        Self {
            tenants,
            guarantees,
            tenant_at: 0,
            cursor: None,
            pass: 0,
            known: HashMap::new(),
            totals: Totals::default(),
        }
    }

    /// Reads up to `config.ledgers_per_tick` ledgers. Returns the exposition text when
    /// this tick completed a pass.
    pub async fn step<S, L>(
        &mut self,
        gateway: &Gateway<S, L>,
        config: &SweepConfig,
    ) -> Result<Option<String>, GatewayError>
    where
        S: DocumentStore + 'static,
        L: AppendLog + 'static,
    {
        let mut budget = config.ledgers_per_tick.max(1);
        while let Some(tenant) = self.tenants.get(self.tenant_at).cloned() {
            if budget == 0 {
                return Ok(None);
            }
            let scan = config.page.clamp(1, budget);
            let page = gateway.census_page(&tenant, self.cursor.as_deref(), scan).await?;
            budget = budget.saturating_sub(scan);
            self.totals.unreadable += page.unreadable as u64;
            let now = gateway.now();
            for ledger in &page.ledgers {
                let fill = self.totals.fill.entry(ledger.guarantee_id.clone()).or_default();
                *fill = (*fill).max(ledger.live_receipts);
                for hold in &ledger.holds {
                    let key = (tenant.clone(), hold.reservation_id.clone());
                    let fresh = match self.known.get(&key) {
                        Some(k) => k.marks != hold.marks() || hold.observation_recorded,
                        None => true,
                    };
                    if fresh {
                        let diagnosis = gateway.diagnose_hold(&tenant, hold).await?;
                        let logged = self.known.get(&key).is_some_and(|k| k.logged);
                        self.known.insert(
                            key.clone(),
                            Known {
                                marks: hold.marks(),
                                diagnosis,
                                logged,
                                pass: self.pass,
                            },
                        );
                    }
                    let known = self.known.get_mut(&key).expect("just inserted");
                    known.pass = self.pass;
                    let state = known.diagnosis.state;
                    *self
                        .totals
                        .holds
                        .entry((ledger.guarantee_id.clone(), state))
                        .or_default() += 1;
                    let Some(started) = known.diagnosis.attempt_started_at.clone() else {
                        continue;
                    };
                    let age = elapsed_millis(&started, &now).unwrap_or(0) / 1000;
                    if age >= HOLD_AGE_LOG_SECONDS && !known.logged {
                        known.logged = true;
                        tracing::warn!(
                            tenant = %tenant,
                            guarantee = %ledger.guarantee_id,
                            resource_digest = %ledger.resource_digest,
                            reservation_id = %hold.reservation_id,
                            state,
                            age_seconds = age,
                            "shared-guarantee hold is aging; follow its next safe step"
                        );
                    }
                    let oldest = self
                        .totals
                        .oldest
                        .entry(ledger.guarantee_id.clone())
                        .or_insert_with(|| started.clone());
                    if compare_contract_times(&started, oldest) == Some(std::cmp::Ordering::Less) {
                        *oldest = started;
                    }
                }
            }
            self.cursor = page.next;
            if self.cursor.is_none() {
                self.tenant_at += 1;
            }
        }
        let mut escalations = 0;
        for tenant in &self.tenants {
            escalations += gateway.open_escalation_count(tenant).await?;
        }
        let text = self.render(&gateway.now(), escalations, unix_seconds());
        let pass = self.pass;
        self.known.retain(|_, k| k.pass == pass);
        self.pass += 1;
        self.tenant_at = 0;
        self.totals = Totals::default();
        Ok(Some(text))
    }

    /// The gauges as published before any hold is seen, for checks that alert rules
    /// only use metrics that exist.
    #[must_use]
    pub fn empty_exposition(guarantees: Vec<String>) -> String {
        Self::new(Vec::new(), guarantees).render("", 0, 0.0)
    }

    #[allow(clippy::cast_precision_loss)]
    fn render(&self, now: &str, escalations: usize, completed_at: f64) -> String {
        let mut out = String::new();
        out.push_str("# HELP contextos_shared_holds Held shared-guarantee receipts by diagnosed state, at the last full sweep (leader only).\n# TYPE contextos_shared_holds gauge\n");
        for guarantee in &self.guarantees {
            for state in HOLD_STATES {
                let n = self.totals.holds.get(&(guarantee.clone(), state)).copied().unwrap_or(0);
                let _ = writeln!(
                    out,
                    "contextos_shared_holds{{guarantee=\"{guarantee}\",state=\"{state}\"}} {n}"
                );
            }
        }
        out.push_str("# HELP contextos_shared_hold_oldest_seconds Age of the oldest held receipt's attempt (0 when none).\n# TYPE contextos_shared_hold_oldest_seconds gauge\n");
        for guarantee in &self.guarantees {
            let age = self
                .totals
                .oldest
                .get(guarantee)
                .and_then(|started| elapsed_millis(started, now))
                .map_or(0.0, |ms| ms as f64 / 1000.0);
            let _ = writeln!(
                out,
                "contextos_shared_hold_oldest_seconds{{guarantee=\"{guarantee}\"}} {age}"
            );
        }
        out.push_str("# HELP contextos_shared_receipts_fill_ratio Live receipts of the fullest ledger over the receipt cap.\n# TYPE contextos_shared_receipts_fill_ratio gauge\n");
        for guarantee in &self.guarantees {
            let fill = receipt_fill(self.totals.fill.get(guarantee).copied().unwrap_or(0));
            let _ = writeln!(
                out,
                "contextos_shared_receipts_fill_ratio{{guarantee=\"{guarantee}\"}} {fill}"
            );
        }
        let _ = write!(
            out,
            "# HELP contextos_shared_ledgers_unreadable Exposure ledgers the last sweep could not read.\n# TYPE contextos_shared_ledgers_unreadable gauge\ncontextos_shared_ledgers_unreadable {}\n\
             # HELP contextos_escalations_open Policy escalations awaiting a human, across tenants.\n# TYPE contextos_escalations_open gauge\ncontextos_escalations_open {escalations}\n\
             # HELP contextos_governance_sweep_completed_timestamp_seconds When the last full governance sweep completed.\n# TYPE contextos_governance_sweep_completed_timestamp_seconds gauge\ncontextos_governance_sweep_completed_timestamp_seconds {completed_at}\n",
            self.totals.unreadable
        );
        out
    }
}

/// Sweeps on the leader replica and publishes into `metrics`; a replica that loses
/// leadership stops exporting the gauges.
pub async fn run<S, L>(
    gateway: Arc<Gateway<S, L>>,
    metrics: Arc<Metrics>,
    leader: Arc<AtomicBool>,
    tenants: Vec<String>,
    config: SweepConfig,
) where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let mut ticker = tokio::time::interval(config.interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut census: Option<Census> = None;
    loop {
        ticker.tick().await;
        if !leader.load(Ordering::Relaxed) {
            if census.take().is_some() {
                metrics.set_governance(None);
            }
            continue;
        }
        let sweep = census.get_or_insert_with(|| Census::new(tenants.clone(), gateway.shared_guarantee_ids()));
        match sweep.step(&gateway, &config).await {
            Ok(Some(text)) => metrics.set_governance(Some(text)),
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(%error, "governance sweep failed; restarting the pass next interval");
                census = None;
            }
        }
    }
}

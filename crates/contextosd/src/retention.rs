//! Time-based retention of runs' personal content.
//!
//! With `[retention] run_content_days` set, the leader replica sweeps runs admitted
//! more than that many days ago and erases their personal content (the replay case and
//! compiled context; see [`contextos_gateway::Gateway::erase_run`]), recorded with the
//! retention policy as the reason. A run still in progress is skipped and revisited on a
//! later cycle, so a long run is never erased under its executor. Each tick handles one
//! page (`batch`) and resumes from where the previous one stopped; after the last page
//! the scan starts over. Off by default: nothing is erased unless retention is set.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use contextos_gateway::{ErasureError, Gateway, RunAdmission};
use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore, ScanCursor};
use serde::{Deserialize, Serialize};

/// The principal recorded on retention erasures.
pub const RETENTION_PRINCIPAL: &str = "contextos.retention";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionConfig {
    /// Erase a run's personal content this many days after admission; unset keeps it.
    #[serde(default)]
    pub run_content_days: Option<u32>,
    #[serde(default = "default_interval")]
    pub sweep_interval_ms: u64,
    #[serde(default = "default_batch")]
    pub batch: usize,
}

fn default_interval() -> u64 {
    60_000
}

fn default_batch() -> usize {
    500
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            run_content_days: None,
            sweep_interval_ms: default_interval(),
            batch: default_batch(),
        }
    }
}

impl RetentionConfig {
    pub(crate) fn check(&self) -> Result<(), String> {
        if self.run_content_days == Some(0) {
            return Err("retention run_content_days must be at least 1".into());
        }
        if !(1_000..=86_400_000).contains(&self.sweep_interval_ms) || !(1..=10_000).contains(&self.batch) {
            return Err("retention sweep_interval_ms must be in [1s, 1d] and batch in [1, 10000]".into());
        }
        Ok(())
    }
}

/// What one sweep did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Swept {
    pub erased: usize,
    pub still_running: usize,
}

/// Sweeps one page of runs admitted before `cutoff_us` after `cursor`; returns what it
/// did and where the next page starts (`None` once the scan is complete).
pub async fn sweep_once<S, L>(
    store: &S,
    gateway: &Gateway<S, L>,
    days: u32,
    cutoff_us: u64,
    cursor: Option<ScanCursor>,
    batch: usize,
) -> Result<(Swept, Option<ScanCursor>), String>
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let page = store
        .expiring(DocKind::ReplayCase, cutoff_us, cursor.as_ref(), batch)
        .await
        .map_err(|e| e.to_string())?;
    let mut swept = Swept::default();
    for (_, key) in &page {
        let admission_key = DocKey::new(&key.tenant_id, DocKind::RunAdmission, &key.id);
        let Some(stored) = store.get(&admission_key).await.map_err(|e| e.to_string())? else {
            continue;
        };
        let Ok(admission) = serde_json::from_value::<RunAdmission>(stored.body) else {
            continue;
        };
        let reason = format!("retention: run content kept {days} days");
        match gateway.erase_run(&admission, RETENTION_PRINCIPAL, &reason).await {
            Ok(_) => swept.erased += 1,
            Err(ErasureError::RunActive) => swept.still_running += 1,
            Err(error) => return Err(error.to_string()),
        }
    }
    let next = if page.len() < batch { None } else { page.last().cloned() };
    Ok((swept, next))
}

fn now_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
}

/// Sweeps on the leader replica at the configured interval.
pub async fn run<S, L>(store: Arc<S>, gateway: Arc<Gateway<S, L>>, leader: Arc<AtomicBool>, config: RetentionConfig)
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let Some(days) = config.run_content_days else { return };
    let keep_us = u64::from(days) * 86_400 * 1_000_000;
    let mut ticker = tokio::time::interval(Duration::from_millis(config.sweep_interval_ms));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut cursor = None;
    loop {
        ticker.tick().await;
        if !leader.load(Ordering::Relaxed) {
            cursor = None;
            continue;
        }
        let cutoff = now_us().saturating_sub(keep_us);
        match sweep_once(store.as_ref(), &gateway, days, cutoff, cursor.take(), config.batch).await {
            Ok((swept, next)) => {
                if swept.erased > 0 {
                    tracing::info!(
                        erased = swept.erased,
                        still_running = swept.still_running,
                        "retention sweep"
                    );
                }
                cursor = next;
            }
            Err(error) => tracing::warn!(%error, "retention sweep failed; retrying next interval"),
        }
    }
}

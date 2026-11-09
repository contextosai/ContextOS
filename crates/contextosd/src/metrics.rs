//! Prometheus text exposition for request counts and latency, and governance outcomes.
//!
//! Labels are bounded: capabilities and packs are the ones pinned at startup (anything
//! else is counted as `unpinned`), statuses and reason codes are the runtime's own.
//! Tenants are not a label; per-tenant evidence is in the audit chain.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Mutex;
use std::time::Duration;

const BUCKETS_MS: [f64; 12] = [
    0.5, 1.0, 2.5, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 5000.0,
];

/// Upper bounds (seconds) of approval decision times.
const DECISION_BUCKETS: [f64; 6] = [10.0, 30.0, 60.0, 300.0, 1800.0, 3600.0];

#[derive(Debug)]
struct Histogram<const N: usize = { BUCKETS_MS.len() }> {
    counts: [u64; N],
    sum_ms: f64,
    count: u64,
}

impl<const N: usize> Default for Histogram<N> {
    fn default() -> Self {
        Self {
            counts: [0; N],
            sum_ms: 0.0,
            count: 0,
        }
    }
}

#[derive(Debug, Default)]
pub struct Metrics {
    requests: Mutex<BTreeMap<(String, u16), u64>>,
    latency: Mutex<BTreeMap<String, Histogram>>,
    outcomes: Mutex<BTreeMap<(String, String), u64>>,
    refusals: Mutex<BTreeMap<String, u64>>,
    admissions: Mutex<BTreeMap<String, u64>>,
    decisions: Mutex<BTreeMap<String, u64>>,
    task_amendments: Mutex<BTreeMap<String, u64>>,
    agent_binding_mismatches: Mutex<BTreeMap<String, u64>>,
    user_binding_mismatches: Mutex<BTreeMap<String, u64>>,
    pack_intent_mismatches: Mutex<BTreeMap<String, u64>>,
    over_limit_imports: Mutex<BTreeMap<String, u64>>,
    approvals_requested: Counter,
    approvals_redeemed: Counter,
    /// Decision seconds of redeemed approvals, by [`DECISION_BUCKETS`].
    approval_decisions: Mutex<Histogram<{ DECISION_BUCKETS.len() }>>,
    notifications: Mutex<BTreeMap<(String, String), u64>>,
    audit_sinks: Mutex<BTreeMap<(String, String), u64>>,
    /// Gauges from the leader's last full governance sweep (see `governance_sweep`).
    governance: Mutex<Option<String>>,
    /// Gauges from this replica's last upstream drift check (see `upstream_check`).
    upstream: Mutex<Option<String>>,
}

/// The `contextos_replicas` gauge, which the `/metrics` handler appends.
#[must_use]
pub fn replicas_exposition(replicas: usize) -> String {
    format!(
        "# HELP contextos_replicas Live replicas sharing tenant limits.\n# TYPE contextos_replicas gauge\ncontextos_replicas {replicas}\n"
    )
}

/// One labelled counter: label value to count.
type Counter = Mutex<BTreeMap<String, u64>>;

fn bump<K: Ord>(map: &Mutex<BTreeMap<K, u64>>, key: K) {
    if let Ok(mut map) = map.lock() {
        *map.entry(key).or_default() += 1;
    }
}

impl Metrics {
    pub fn observe(&self, route: &str, status: u16, elapsed: Duration) {
        if let Ok(mut requests) = self.requests.lock() {
            *requests.entry((route.to_owned(), status)).or_default() += 1;
        }
        let ms = elapsed.as_secs_f64() * 1000.0;
        if let Ok(mut latency) = self.latency.lock() {
            let h = latency.entry(route.to_owned()).or_default();
            for (i, bound) in BUCKETS_MS.iter().enumerate() {
                if ms <= *bound {
                    h.counts[i] += 1;
                }
            }
            h.sum_ms += ms;
            h.count += 1;
        }
    }

    /// Counts a governed dispatch by capability (pinned, or `unpinned`) and status, and
    /// each reason code of one that did not complete.
    pub fn dispatch_outcome(&self, capability: &str, status: &str, reasons: &[String]) {
        bump(&self.outcomes, (capability.to_owned(), status.to_owned()));
        if !matches!(status, "completed" | "ok") {
            for reason in reasons {
                bump(&self.refusals, reason.clone());
            }
        }
    }

    /// Counts an approval a dispatch of `capability` asked for or redeemed, and the
    /// decision time of a redeemed one.
    #[allow(clippy::cast_precision_loss)]
    pub fn approval(&self, capability: &str, note: Option<&contextos_gateway::ApprovalNote>) {
        use contextos_gateway::ApprovalNote;
        match note {
            None => {}
            Some(ApprovalNote::Requested) => bump(&self.approvals_requested, capability.to_owned()),
            Some(ApprovalNote::Redeemed { decision_seconds }) => {
                bump(&self.approvals_redeemed, capability.to_owned());
                if let (Some(seconds), Ok(mut h)) = (decision_seconds, self.approval_decisions.lock()) {
                    let s = *seconds as f64;
                    for (i, bound) in DECISION_BUCKETS.iter().enumerate() {
                        if s <= *bound {
                            h.counts[i] += 1;
                        }
                    }
                    h.sum_ms += s;
                    h.count += 1;
                }
            }
        }
    }

    /// Counts an admitted run by the pack it was admitted on.
    pub fn admission(&self, pack: &str) {
        bump(&self.admissions, pack.to_owned());
    }

    /// Counts an amended task authorization by its change (`narrowed`, `widened`).
    pub fn task_amendment(&self, change: &str) {
        bump(&self.task_amendments, change.to_owned());
    }

    /// Counts a run admitted or refused whose agent its credential does not name, by
    /// binding mode (`observe` admits it, `required` refuses it).
    pub fn agent_binding_mismatch(&self, mode: &str) {
        bump(&self.agent_binding_mismatches, mode.to_owned());
    }

    /// Counts a run admitted or refused whose user its credential does not act for, by
    /// reason (`no_user`, `other_user`, `role_not_held`).
    pub fn user_binding_mismatch(&self, reason: &str) {
        bump(&self.user_binding_mismatches, reason.to_owned());
    }

    /// Counts a run admitted or refused whose intent its pack's rules do not name, by
    /// mode (`observe` admits it, `required` refuses it).
    pub fn pack_intent_mismatch(&self, mode: &str) {
        bump(&self.pack_intent_mismatches, mode.to_owned());
    }

    /// Counts an imported row that left its resource over the guarantee's limit.
    pub fn over_limit_import(&self, guarantee: &str) {
        bump(&self.over_limit_imports, guarantee.to_owned());
    }

    /// Counts a notification attempt by webhook and outcome (`delivered`, `failed`,
    /// `abandoned`).
    pub fn notification(&self, webhook: &str, outcome: &str) {
        bump(&self.notifications, (webhook.to_owned(), outcome.to_owned()));
    }

    /// Counts an audit sink batch by sink and outcome (`delivered`, `failed`).
    pub fn audit_sink(&self, sink: &str, outcome: &str) {
        bump(&self.audit_sinks, (sink.to_owned(), outcome.to_owned()));
    }

    /// Counts a recorded decision by its status.
    pub fn decision(&self, status: &str) {
        bump(&self.decisions, status.to_owned());
    }

    /// Replaces the governance gauges (`None` on a replica that is not the leader).
    pub fn set_governance(&self, exposition: Option<String>) {
        if let Ok(mut governance) = self.governance.lock() {
            *governance = exposition;
        }
    }

    /// Replaces the upstream drift gauges.
    pub fn set_upstream(&self, exposition: Option<String>) {
        if let Ok(mut upstream) = self.upstream.lock() {
            *upstream = exposition;
        }
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("# HELP contextos_http_requests_total HTTP requests by route and status.\n");
        out.push_str("# TYPE contextos_http_requests_total counter\n");
        if let Ok(requests) = self.requests.lock() {
            for ((route, status), n) in requests.iter() {
                let _ = writeln!(
                    out,
                    "contextos_http_requests_total{{route=\"{route}\",status=\"{status}\"}} {n}"
                );
            }
        }
        out.push_str("# HELP contextos_http_request_duration_ms Request latency in milliseconds.\n");
        out.push_str("# TYPE contextos_http_request_duration_ms histogram\n");
        if let Ok(latency) = self.latency.lock() {
            for (route, h) in latency.iter() {
                for (i, bound) in BUCKETS_MS.iter().enumerate() {
                    let _ = writeln!(
                        out,
                        "contextos_http_request_duration_ms_bucket{{route=\"{route}\",le=\"{bound}\"}} {}",
                        h.counts[i]
                    );
                }
                let _ = writeln!(
                    out,
                    "contextos_http_request_duration_ms_bucket{{route=\"{route}\",le=\"+Inf\"}} {}",
                    h.count
                );
                let _ = writeln!(
                    out,
                    "contextos_http_request_duration_ms_sum{{route=\"{route}\"}} {}",
                    h.sum_ms
                );
                let _ = writeln!(
                    out,
                    "contextos_http_request_duration_ms_count{{route=\"{route}\"}} {}",
                    h.count
                );
            }
        }
        out.push_str("# HELP contextos_dispatch_outcomes_total Governed tool dispatches by capability and status.\n");
        out.push_str("# TYPE contextos_dispatch_outcomes_total counter\n");
        if let Ok(outcomes) = self.outcomes.lock() {
            for ((capability, status), n) in outcomes.iter() {
                let _ = writeln!(
                    out,
                    "contextos_dispatch_outcomes_total{{capability=\"{capability}\",status=\"{status}\"}} {n}"
                );
            }
        }
        out.push_str("# HELP contextos_notifications_total Escalation notification attempts by webhook and outcome.\n");
        out.push_str("# TYPE contextos_notifications_total counter\n");
        if let Ok(notifications) = self.notifications.lock() {
            for ((webhook, outcome), n) in notifications.iter() {
                let _ = writeln!(
                    out,
                    "contextos_notifications_total{{webhook=\"{webhook}\",outcome=\"{outcome}\"}} {n}"
                );
            }
        }
        out.push_str("# HELP contextos_audit_sink_batches_total Audit sink batches by sink and outcome.\n");
        out.push_str("# TYPE contextos_audit_sink_batches_total counter\n");
        if let Ok(sinks) = self.audit_sinks.lock() {
            for ((sink, outcome), n) in sinks.iter() {
                let _ = writeln!(
                    out,
                    "contextos_audit_sink_batches_total{{sink=\"{sink}\",outcome=\"{outcome}\"}} {n}"
                );
            }
        }
        out.push_str("# HELP contextos_approval_decision_seconds Seconds from the gateway's approval request to the fastest approving decision, for redeemed approvals.\n");
        out.push_str("# TYPE contextos_approval_decision_seconds histogram\n");
        if let Ok(h) = self.approval_decisions.lock() {
            for (i, bound) in DECISION_BUCKETS.iter().enumerate() {
                let _ = writeln!(
                    out,
                    "contextos_approval_decision_seconds_bucket{{le=\"{bound}\"}} {}",
                    h.counts[i]
                );
            }
            let _ = writeln!(
                out,
                "contextos_approval_decision_seconds_bucket{{le=\"+Inf\"}} {}",
                h.count
            );
            let _ = writeln!(out, "contextos_approval_decision_seconds_sum {}", h.sum_ms);
            let _ = writeln!(out, "contextos_approval_decision_seconds_count {}", h.count);
        }
        let counters: [(&str, &str, &str, &Counter); 10] = [
            (
                "contextos_dispatch_refusals_total",
                "Reason codes of dispatches that did not complete.",
                "reason",
                &self.refusals,
            ),
            (
                "contextos_admissions_total",
                "Admitted runs by Context Pack release.",
                "pack",
                &self.admissions,
            ),
            (
                "contextos_decisions_total",
                "Recorded decisions by status.",
                "status",
                &self.decisions,
            ),
            (
                "contextos_task_authorization_amendments_total",
                "Amended task authorizations by change.",
                "change",
                &self.task_amendments,
            ),
            (
                "contextos_agent_binding_mismatches_total",
                "Runs whose declared agent their credential does not name, by binding mode.",
                "mode",
                &self.agent_binding_mismatches,
            ),
            (
                "contextos_user_binding_mismatches_total",
                "Runs whose declared user their credential does not act for, by reason.",
                "reason",
                &self.user_binding_mismatches,
            ),
            (
                "contextos_pack_intent_mismatches_total",
                "Runs whose intent their Context Pack's rules do not name, by mode.",
                "mode",
                &self.pack_intent_mismatches,
            ),
            (
                "contextos_shared_guarantee_over_limit_imports_total",
                "Imported rows that left a resource over its guarantee's limit, by guarantee.",
                "guarantee",
                &self.over_limit_imports,
            ),
            (
                "contextos_approvals_requested_total",
                "Approvals the gateway asked for, by capability.",
                "capability",
                &self.approvals_requested,
            ),
            (
                "contextos_approvals_redeemed_total",
                "Approvals redeemed for an operation, by capability.",
                "capability",
                &self.approvals_redeemed,
            ),
        ];
        for (name, help, label, map) in counters {
            let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} counter");
            if let Ok(map) = map.lock() {
                for (value, n) in map.iter() {
                    let _ = writeln!(out, "{name}{{{label}=\"{value}\"}} {n}");
                }
            }
        }
        for block in [&self.governance, &self.upstream] {
            if let Ok(block) = block.lock()
                && let Some(text) = block.as_deref()
            {
                out.push_str(text);
            }
        }
        out
    }
}

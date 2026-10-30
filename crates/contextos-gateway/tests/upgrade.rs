//! Upgrading a capability while an operation claimed under its old version is open.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use contextos_gateway::*;
use contextos_store::{MemoryLog, MemoryStore};
use support::*;

/// The next version of the test capability: same id, new definition.
fn upgraded() -> manifest::CapabilityManifest {
    let mut m = manifest();
    m.capability_version = "4".into();
    m.capability_ref = artifact("capability", "issue_refund@4");
    m
}

/// A gateway restarted on the same store with `pinned` and `retired` manifests.
fn restarted(
    h: &Harness,
    pinned: Option<manifest::CapabilityManifest>,
    retired: Option<manifest::CapabilityManifest>,
) -> Gateway<MemoryStore, MemoryLog> {
    let ports = Ports {
        clock: Arc::new(FixedClock),
        ids: Arc::new(SeqIds(AtomicU64::new(10_000))),
        authority: h.authority.clone(),
        policy: Arc::new(Policy("allow")),
        constraints: Arc::new(Constraints),
        approvals: h.approvals.clone(),
        idempotency: None,
        data_flow: None,
        boundary: None,
        memory: None,
    };
    let mut g = Gateway::new(h.store.clone(), h.audit.clone(), ports);
    g.register_adapter("adp_payments", h.adapter.clone());
    if let Some(m) = pinned {
        g.pin_capability(m).unwrap();
    }
    if let Some(m) = retired {
        g.retire_capability(m).unwrap();
    }
    g
}

fn not_applied() -> Resolution {
    Resolution::Assert {
        outcome: EffectOutcome::NotApplied,
        evidence_ref: artifact("provider_ledger_extract", "payments-2026-10-30"),
        principal_id: "ops_alice".into(),
    }
}

async fn unknown_operation(h: &Harness) -> String {
    let out = h
        .gateway
        .dispatch(&h.admission, &call("tc_1", Some("refund_ord_881")))
        .await
        .unwrap();
    assert_eq!(out.result["status"], "paused");
    out.report.operation_id.unwrap()
}

#[tokio::test]
async fn an_operation_claimed_before_an_upgrade_is_resolved_under_its_own_version() {
    let h = harness("allow", Behavior::Hang).await;
    let op_id = unknown_operation(&h).await;

    // Upgraded without the old version: the operation cannot be resolved.
    let bare = restarted(&h, Some(upgraded()), None);
    let refused = bare.reconcile(&h.admission, &op_id, not_applied()).await.unwrap();
    assert_eq!(refused.reason_codes, vec!["capability_not_pinned".to_owned()]);

    // With the old version retired, it is.
    let g = restarted(&h, Some(upgraded()), Some(manifest()));
    let resolved = g.reconcile(&h.admission, &op_id, not_applied()).await.unwrap();
    assert_eq!(resolved.status, "resolved");
    assert_eq!(resolved.outcome.as_deref(), Some("not_applied"));

    // The new version never takes over the old operation: a retry under it is a
    // different binding.
    let retry = g
        .dispatch(&h.admission, &call("tc_2", Some("refund_ord_881")))
        .await
        .unwrap();
    assert_eq!(retry.result["status"], "rejected");
    assert_eq!(retry.report.reason_codes, vec!["operation_binding_mismatch".to_owned()]);
    assert_eq!(h.adapter.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_retired_version_is_never_dispatched() {
    let h = harness("allow", Behavior::Confirm).await;
    let g = restarted(&h, None, Some(manifest()));
    let out = g
        .dispatch(&h.admission, &call("tc_1", Some("refund_ord_881")))
        .await
        .unwrap();
    assert_eq!(out.result["status"], "rejected");
    assert_eq!(h.adapter.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_retired_version_must_differ_from_every_other_version() {
    let h = harness("allow", Behavior::Confirm).await;
    let mut g = restarted(&h, Some(manifest()), None);
    assert!(g.retire_capability(manifest()).is_err());
    g.retire_capability(upgraded()).unwrap();
    assert!(g.retire_capability(upgraded()).is_err());
}

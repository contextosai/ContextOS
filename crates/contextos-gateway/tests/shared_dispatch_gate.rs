//! A store failure at the dispatch gate of a shared-guarantee attempt. The gate is
//! written before the shared receipt is marked started, so an attempt the failure
//! stopped before the provider call is provably not sent: reconciliation releases its
//! capacity instead of holding it until someone can prove a negative.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use contextos_contract::canonical::sha256_canonical;
use contextos_gateway::*;
use contextos_store::{DocKey, DocKind, DocumentStore, MemoryLog, MemoryStore};
use serde_json::{Value, json};
use support::*;

/// Fails the first dispatch-gate write, before or after it commits.
struct GateFaultStore {
    inner: Arc<MemoryStore>,
    armed: AtomicBool,
    after_commit: bool,
}

impl DocumentStore for GateFaultStore {
    async fn get(&self, k: &DocKey) -> Result<Option<contextos_store::Versioned>, contextos_store::StoreError> {
        self.inner.get(k).await
    }
    async fn create(&self, k: &DocKey, b: &Value) -> Result<contextos_store::Versioned, contextos_store::StoreError> {
        if k.kind != DocKind::DispatchGate || !self.armed.swap(false, Ordering::SeqCst) {
            return self.inner.create(k, b).await;
        }
        if self.after_commit {
            self.inner.create(k, b).await?;
        }
        Err(contextos_store::StoreError::Backend("injected gate failure".into()))
    }
    async fn compare_and_swap(
        &self,
        k: &DocKey,
        r: u64,
        b: &Value,
    ) -> Result<contextos_store::Versioned, contextos_store::StoreError> {
        self.inner.compare_and_swap(k, r, b).await
    }
    async fn compare_and_swap_encoded(
        &self,
        k: &DocKey,
        r: u64,
        b: Value,
        e: contextos_store::Encoded,
    ) -> Result<u64, contextos_store::StoreError> {
        self.inner.compare_and_swap_encoded(k, r, b, e).await
    }
    async fn expiring(
        &self,
        k: DocKind,
        t: u64,
        a: Option<&contextos_store::ScanCursor>,
        l: usize,
    ) -> Result<Vec<contextos_store::ScanCursor>, contextos_store::StoreError> {
        self.inner.expiring(k, t, a, l).await
    }
}

fn replica<S: DocumentStore + 'static>(h: &Harness, store: Arc<S>) -> Gateway<S, MemoryLog> {
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
    let mut g = Gateway::new(store, h.audit.clone(), ports);
    g.register_adapter("adp_payments", h.adapter.clone());
    g.pin_capability(manifest()).unwrap();
    g.set_shared_guarantees(vec![shared_rule()]).unwrap();
    g
}

fn refund(admission: &RunAdmission, operation: &str, amount: u64) -> Value {
    let mut v = call(operation, Some(operation));
    v["run_id"] = json!(admission.run_id);
    v["principal_chain"][0]["id"] = admission.actor["principal_id"].clone();
    v["args"]["amount_minor"] = json!(amount);
    v
}

#[tokio::test]
async fn shared_guarantee_gate_failure_leaves_a_releasable_hold() {
    for after_commit in [false, true] {
        let h = harness("allow", Behavior::Confirm).await;
        let store = Arc::new(GateFaultStore {
            inner: h.store.clone(),
            armed: true.into(),
            after_commit,
        });
        let failing = replica(&h, store);
        assert!(
            failing
                .dispatch(&h.admission, &refund(&h.admission, "gate_failed", 420_000))
                .await
                .is_err()
        );
        assert_eq!(h.adapter.calls.load(Ordering::SeqCst), 0);
        let digest = sha256_canonical(&json!("ord_881")).unwrap();
        let recovery = replica(&h, h.store.clone());
        let held = recovery
            .shared_exposure(TENANT, "refunds", &digest)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(held["held"], 420_000, "after_commit={after_commit}");

        // The receipt was never marked started, so absence can be asserted.
        let resolved = recovery
            .reconcile(
                &h.admission,
                "gate_failed",
                Resolution::Assert {
                    outcome: EffectOutcome::NotApplied,
                    evidence_ref: artifact("incident", "gate_failed"),
                    principal_id: "oncall".into(),
                },
            )
            .await
            .unwrap();
        assert_eq!(resolved.status, "resolved", "after_commit={after_commit}: {resolved:?}");
        let view = recovery
            .shared_exposure(TENANT, "refunds", &digest)
            .await
            .unwrap()
            .unwrap();
        assert_eq!((view["held"].as_u64(), view["committed"].as_u64()), (Some(0), Some(0)));

        // The released capacity is usable by another run, and the provider is called once.
        let other = independent_run(&h, "run_after_gate_failure").await;
        let next = recovery
            .dispatch(&other, &refund(&other, "after_gate_failure", 420_000))
            .await
            .unwrap();
        assert_eq!(next.result["status"], "completed");
        assert_eq!(h.adapter.calls.load(Ordering::SeqCst), 1);
    }
}

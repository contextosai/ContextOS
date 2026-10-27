//! Governed compensation: an applied effect is undone by a new operation that passes the
//! whole pipeline, linked to the original in the operation ledger.

mod support;

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use contextos_audit::verify_tenant_chain;
use contextos_gateway::*;
use contextos_store::{DocKey, DocKind, DocumentStore};
use serde_json::{Value, json};
use support::*;

/// A payments provider that records every call and answers each protocol tool with
/// scripted outcomes (confirmed once the script runs out).
#[derive(Default)]
struct Provider {
    calls: Mutex<Vec<(String, Value)>>,
    script: Mutex<HashMap<String, VecDeque<EffectOutcome>>>,
}

impl Provider {
    fn script(&self, tool: &str, outcomes: &[EffectOutcome]) {
        self.script
            .lock()
            .unwrap()
            .insert(tool.into(), outcomes.iter().copied().collect());
    }
    fn calls(&self) -> Vec<(String, Value)> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl Adapter for Provider {
    async fn invoke(&self, manifest: &CapabilityManifest, call: &AdapterCall) -> AdapterResponse {
        let tool = manifest.protocol_tool.clone();
        self.calls.lock().unwrap().push((tool.clone(), call.arguments.clone()));
        let outcome = self
            .script
            .lock()
            .unwrap()
            .get_mut(&tool)
            .and_then(VecDeque::pop_front)
            .unwrap_or(EffectOutcome::Confirmed);
        match outcome {
            EffectOutcome::Unknown => AdapterResponse::unknown(),
            outcome => AdapterResponse {
                outcome,
                definitive: true,
                output: serde_json::from_value(json!({"status": "ok"})).unwrap(),
                external_ref: (outcome == EffectOutcome::Confirmed).then(|| format!("rf_{}", call.operation_id)),
                cost_units: Some(40),
            },
        }
    }
}

const REVERSE: &str = "adp_payments.reverse_refund";

fn refund(compensation: Value) -> CapabilityManifest {
    let mut manifest = serde_json::to_value(manifest()).unwrap();
    manifest["compensation"] = compensation;
    serde_json::from_value(manifest).unwrap()
}

fn reverse() -> CapabilityManifest {
    let mut manifest = serde_json::to_value(manifest()).unwrap();
    manifest["capability_id"] = json!(REVERSE);
    manifest["protocol_tool"] = json!("refunds.reverse");
    manifest["desired_effect"] = json!("refund_reversed");
    manifest["action_risk"]["reversibility"] = json!("irreversible");
    manifest["destination_pointers"] = json!([]);
    manifest["recovery"] = json!({"strategy": "manual_reconcile", "max_attempts": 2, "retry_delays_seconds": [0]});
    serde_json::from_value(manifest).unwrap()
}

fn declared() -> Value {
    json!({"capability_id": REVERSE, "arguments": {
        "refund_ref": "/external_ref", "order_id": "/arguments/order_id", "amount_minor": "/arguments/amount_minor"}})
}

/// The harness with a compensable refund, its pinned and surfaced reversal, and a
/// scripted provider.
async fn setup(verdict: &'static str) -> (Harness, Arc<Provider>) {
    let mut h = harness(verdict, Behavior::Confirm).await;
    let provider = Arc::new(Provider::default());
    h.gateway.register_adapter("adp_payments", provider.clone());
    h.gateway.pin_capability(refund(declared())).unwrap();
    h.gateway.pin_capability(reverse()).unwrap();
    h.admission.surfaced_capabilities.insert(REVERSE.into());
    (h, provider)
}

fn refund_call(key: &str, amount: u64) -> Value {
    let mut envelope = call(&format!("tc_{key}"), Some(key));
    envelope["args"]["amount_minor"] = json!(amount);
    envelope
}

async fn effect(h: &Harness, operation_id: &str) -> Value {
    let listed = h.gateway.compensations(&h.admission).await.unwrap();
    listed["effects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["operation_id"] == operation_id)
        .cloned()
        .unwrap_or(Value::Null)
}

#[tokio::test]
async fn an_applied_effect_is_compensated_by_a_new_governed_operation() {
    let (h, provider) = setup("allow").await;
    let out = h
        .gateway
        .dispatch(&h.admission, &refund_call("refund_a", 420_000))
        .await
        .unwrap();
    assert_eq!(out.result["status"], "completed", "{:?}", out.report);
    assert_eq!(effect(&h, "refund_a").await["state"], "compensable");

    let out = h
        .gateway
        .compensate(&h.admission, "refund_a", "tc_undo", None)
        .await
        .unwrap();
    assert_eq!(out.result["status"], "completed", "{:?}", out.report);
    let compensation_id = compensation_operation_id("refund_a");
    assert_eq!(out.report.operation_id.as_deref(), Some(compensation_id.as_str()));
    assert_eq!(out.result["capability_id"], REVERSE);
    assert_eq!(out.result["metadata"]["compensates_operation_id"], "refund_a");
    // The reversal token comes from the ledger, the rest from the original call.
    assert_eq!(
        provider.calls()[1],
        (
            "refunds.reverse".to_owned(),
            json!({"refund_ref": "rf_refund_a", "order_id": "ord_881", "amount_minor": 420_000})
        )
    );
    // The kernel recorded the link; the original's history is unchanged.
    let key = operation_ledger_key(&h.admission, &compensation_id);
    let recorded = h.store.get(&key).await.unwrap().unwrap().body;
    assert_eq!(recorded["operations"].as_array().unwrap().len(), 1);
    assert_eq!(
        recorded["operations"][0]["intent"]["compensates_operation_id"],
        "refund_a"
    );
    assert_eq!(recorded["operations"][0]["outcome"], "confirmed");
    let original = ledger_of(&h, "refund_a").await;
    assert_eq!(original["operations"][0]["outcome"], "confirmed");
    assert_eq!(original["revision"], 2);

    let listed = effect(&h, "refund_a").await;
    assert_eq!(listed["state"], "compensated");
    assert_eq!(listed["compensation_outcome"], "confirmed");
    // Fresh budget: two governed calls were charged.
    let budget = ledger(&h, DocKind::BudgetLedger, &h.admission.budget_ledger_id).await;
    assert_eq!(budget["used"]["tool_calls"], 2);

    // At most once.
    let again = h
        .gateway
        .compensate(&h.admission, "refund_a", "tc_undo_2", None)
        .await
        .unwrap();
    assert_eq!(again.report.reason_codes, ["compensation_already_applied"]);
    assert_eq!(provider.calls().len(), 2);
    verify_tenant_chain(h.audit.log(), TENANT, &keys()).await.unwrap();
}

async fn ledger_of(h: &Harness, operation_id: &str) -> Value {
    let key = operation_ledger_key(&h.admission, operation_id);
    h.store.get(&key).await.unwrap().unwrap().body
}

#[tokio::test]
async fn compensation_needs_its_own_approval() {
    let (h, provider) = setup("require_approval").await;
    let first = h
        .gateway
        .dispatch(&h.admission, &refund_call("refund_a", 420_000))
        .await
        .unwrap();
    assert_eq!(first.result["status"], "paused");
    h.approvals.approve(first.report.action_digest.as_deref().unwrap());
    let applied = h
        .gateway
        .dispatch(&h.admission, &refund_call("refund_a", 420_000))
        .await
        .unwrap();
    assert_eq!(applied.result["status"], "completed", "{:?}", applied.report);

    // The original's approval does not cover its compensation.
    let out = h
        .gateway
        .compensate(&h.admission, "refund_a", "tc_undo", None)
        .await
        .unwrap();
    assert_eq!(out.result["status"], "paused");
    assert!(out.report.obligations.contains(&"await_approval".to_owned()));
    let digest = out.report.action_digest.clone().unwrap();
    assert_ne!(Some(&digest), applied.report.action_digest.as_ref());
    assert_eq!(provider.calls().len(), 1);
    h.approvals.approve(&digest);
    let out = h
        .gateway
        .compensate(&h.admission, "refund_a", "tc_undo", None)
        .await
        .unwrap();
    assert_eq!(out.result["status"], "completed", "{:?}", out.report);
    assert!(
        out.result["risk_tags"]
            .as_array()
            .unwrap()
            .contains(&json!("human_approved"))
    );
}

#[tokio::test]
async fn only_applied_declared_effects_can_be_compensated() {
    let (h, provider) = setup("allow").await;
    let none = h
        .gateway
        .compensate(&h.admission, "never_requested", "tc_x", None)
        .await
        .unwrap();
    assert_eq!(none.result["status"], "rejected");
    assert_eq!(none.report.reason_codes, ["compensation_not_declared"]);

    provider.script("refunds.create", &[EffectOutcome::NotApplied]);
    let out = h
        .gateway
        .dispatch(&h.admission, &refund_call("refund_b", 1_000))
        .await
        .unwrap();
    assert_eq!(out.result["status"], "failed");
    let out = h
        .gateway
        .compensate(&h.admission, "refund_b", "tc_y", None)
        .await
        .unwrap();
    assert_eq!(out.report.reason_codes, ["compensation_not_applicable"]);

    provider.script("refunds.create", &[EffectOutcome::Unknown]);
    let out = h
        .gateway
        .dispatch(&h.admission, &refund_call("refund_c", 2_000))
        .await
        .unwrap();
    assert_eq!(out.result["status"], "paused");
    let out = h
        .gateway
        .compensate(&h.admission, "refund_c", "tc_z", None)
        .await
        .unwrap();
    assert_eq!(out.result["status"], "paused");
    assert_eq!(out.report.reason_codes, ["compensation_original_unresolved"]);
    assert_eq!(out.report.obligations, ["reconcile_existing_operation"]);
    assert_eq!(effect(&h, "refund_c").await["state"], "unresolved");
    // Nothing was sent to undo an effect that is not known to have applied.
    assert!(provider.calls().iter().all(|(tool, _)| tool == "refunds.create"));
}

#[tokio::test]
async fn agents_cannot_claim_compensation_operation_ids() {
    let (h, provider) = setup("allow").await;
    let mut envelope = call("tc_forged", Some(&compensation_operation_id("refund_a")));
    envelope["capability_id"] = json!(REVERSE);
    envelope["args"] = json!({"refund_ref": "rf_guess", "order_id": "ord_881", "amount_minor": 1});
    let out = h.gateway.dispatch(&h.admission, &envelope).await.unwrap();
    assert_eq!(out.report.reason_codes, ["operation_id_reserved"]);
    assert_eq!(provider.calls().len(), 0);
}

#[tokio::test]
async fn an_effect_that_could_not_be_compensated_is_not_sent() {
    let mut h = harness("require_approval", Behavior::Confirm).await;
    let provider = Arc::new(Provider::default());
    h.gateway.register_adapter("adp_payments", provider.clone());
    let mut missing = declared();
    missing["arguments"]["reason"] = json!("/arguments/reason");
    h.gateway.pin_capability(refund(missing)).unwrap();
    let out = h
        .gateway
        .dispatch(&h.admission, &refund_call("refund_a", 1_000))
        .await
        .unwrap();
    assert_eq!(out.result["status"], "rejected");
    assert_eq!(out.report.reason_codes, ["compensation_binding_incomplete"]);
    assert_eq!(provider.calls().len(), 0);
    // Refused at the binding: no approval was requested and no budget reserved.
    assert_eq!(h.approvals.0.load(std::sync::atomic::Ordering::SeqCst), 0);
    let budget = ledger(&h, DocKind::BudgetLedger, &h.admission.budget_ledger_id).await;
    assert_eq!(budget["reservations"], json!([]));
}

#[tokio::test]
async fn a_failed_compensation_leaves_the_effect_compensable_and_retries_the_same_operation() {
    let (h, provider) = setup("allow").await;
    h.gateway
        .dispatch(&h.admission, &refund_call("refund_a", 5_000))
        .await
        .unwrap();
    provider.script("refunds.reverse", &[EffectOutcome::NotApplied]);
    let out = h
        .gateway
        .compensate(&h.admission, "refund_a", "tc_undo", None)
        .await
        .unwrap();
    assert_eq!(out.result["status"], "failed");
    let listed = effect(&h, "refund_a").await;
    assert_eq!(listed["state"], "compensable");
    assert_eq!(listed["compensation_outcome"], "not_applied");

    let out = h
        .gateway
        .compensate(&h.admission, "refund_a", "tc_undo_2", None)
        .await
        .unwrap();
    assert_eq!(out.result["status"], "completed", "{:?}", out.report);
    let ledger = ledger_of(&h, &compensation_operation_id("refund_a")).await;
    assert_eq!(ledger["operations"][0]["attempts"].as_array().unwrap().len(), 2);

    // An unresolved compensation is reconciled, not sent again.
    h.gateway
        .dispatch(&h.admission, &refund_call("refund_b", 6_000))
        .await
        .unwrap();
    provider.script("refunds.reverse", &[EffectOutcome::Unknown]);
    h.gateway
        .compensate(&h.admission, "refund_b", "tc_b", None)
        .await
        .unwrap();
    let out = h
        .gateway
        .compensate(&h.admission, "refund_b", "tc_b2", None)
        .await
        .unwrap();
    assert_eq!(out.report.reason_codes, ["compensation_unresolved"]);
    assert_eq!(effect(&h, "refund_b").await["state"], "compensating");
    let reversals = provider.calls().iter().filter(|(t, _)| t == "refunds.reverse").count();
    assert_eq!(reversals, 3);
}

#[tokio::test]
async fn a_saga_compensates_newest_first_and_stops_at_an_effect_in_doubt() {
    let (h, provider) = setup("allow").await;
    for (key, amount) in [("step_1", 1_000), ("step_2", 2_000), ("step_3", 3_000)] {
        let out = h
            .gateway
            .dispatch(&h.admission, &refund_call(key, amount))
            .await
            .unwrap();
        assert_eq!(out.result["status"], "completed");
    }
    let report = h.gateway.compensate_run(&h.admission, None).await.unwrap();
    assert_eq!(report["status"], "compensated", "{report}");
    let reversed: Vec<Value> = provider
        .calls()
        .iter()
        .filter(|(tool, _)| tool == "refunds.reverse")
        .map(|(_, args)| args["refund_ref"].clone())
        .collect();
    assert_eq!(reversed, [json!("rf_step_3"), json!("rf_step_2"), json!("rf_step_1")]);
    // Idempotent: nothing is left to compensate.
    let again = h.gateway.compensate_run(&h.admission, None).await.unwrap();
    assert_eq!(again["status"], "compensated");
    assert_eq!(again["steps"], json!([]));

    let (h, provider) = setup("allow").await;
    h.gateway
        .dispatch(&h.admission, &refund_call("step_1", 1_000))
        .await
        .unwrap();
    provider.script("refunds.create", &[EffectOutcome::Unknown]);
    h.gateway
        .dispatch(&h.admission, &refund_call("step_2", 2_000))
        .await
        .unwrap();
    let report = h.gateway.compensate_run(&h.admission, None).await.unwrap();
    assert_eq!(report["status"], "stopped");
    assert_eq!(
        report["stopped_at"],
        json!({"operation_id": "step_2", "reason": "unresolved"})
    );
    assert!(provider.calls().iter().all(|(tool, _)| tool == "refunds.create"));

    // An effect in doubt stops the saga even when it declares no compensation.
    let (h, provider) = setup("allow").await;
    h.gateway.open_run(&h.admission).await.unwrap();
    h.gateway
        .dispatch(&h.admission, &refund_call("step_1", 1_000))
        .await
        .unwrap();
    provider.script("refunds.reverse", &[EffectOutcome::Unknown]);
    let mut other = call("tc_other", Some("unrelated"));
    other["capability_id"] = json!(REVERSE);
    other["args"] = json!({"refund_ref": "rf_elsewhere", "order_id": "ord_881", "amount_minor": 7});
    let out = h.gateway.dispatch(&h.admission, &other).await.unwrap();
    assert_eq!(out.result["status"], "paused", "{:?}", out.report);
    let report = h.gateway.compensate_run(&h.admission, None).await.unwrap();
    assert_eq!(
        report["stopped_at"],
        json!({"operation_id": "unrelated", "reason": "unresolved"})
    );
    assert_eq!(provider.calls().len(), 2);
}

#[tokio::test]
async fn erasure_removes_compensation_records() {
    let (h, _) = setup("allow").await;
    let generation = match h.gateway.open_run(&h.admission).await.unwrap() {
        Ownership::Current(g) => g,
        Ownership::Refused(r) => panic!("{r}"),
    };
    h.gateway
        .dispatch(&h.admission, &refund_call("refund_a", 1_000))
        .await
        .unwrap();
    h.gateway.fail_run(&h.admission, generation).await.unwrap();
    let erased = h
        .gateway
        .erase_run(&h.admission, "ops", "subject request")
        .await
        .unwrap();
    assert!(
        erased["erased"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["document"] == "compensation"),
        "{erased}"
    );
    let index = DocKey::new(TENANT, DocKind::Compensation, format!("run:{}", h.admission.run_id));
    let index = h.store.get(&index).await.unwrap().unwrap().body;
    let key = DocKey::new(TENANT, DocKind::Compensation, index["keys"][0].as_str().unwrap());
    let record = h.store.get(&key).await.unwrap().unwrap().body;
    assert_eq!(record["erased"], true);
    assert!(record.get("arguments").is_none());
    assert_eq!(
        h.gateway.compensations(&h.admission).await.unwrap()["effects"],
        json!([])
    );
}

#[tokio::test]
async fn manifests_declare_compensation_only_where_it_is_meaningful() {
    let mut h = harness("allow", Behavior::Confirm).await;
    let mut irreversible = serde_json::to_value(refund(declared())).unwrap();
    irreversible["action_risk"]["reversibility"] = json!("irreversible");
    let irreversible: CapabilityManifest = serde_json::from_value(irreversible).unwrap();
    assert!(matches!(
        h.gateway.pin_capability(irreversible),
        Err(GatewayError::Manifest(ManifestError::Compensation(..)))
    ));
    for compensation in [
        json!({"capability_id": "adp_payments.issue_refund", "arguments": {}}),
        json!({"capability_id": REVERSE, "arguments": {"refund_ref": "/output/refund_id"}}),
        json!({"capability_id": REVERSE, "arguments": {"refund_ref": "/arguments"}}),
    ] {
        assert!(
            matches!(
                h.gateway.pin_capability(refund(compensation.clone())),
                Err(GatewayError::Manifest(ManifestError::Compensation(..)))
            ),
            "{compensation}"
        );
    }
}

#[tokio::test]
async fn a_compensation_that_may_not_be_retried_is_escalated_not_looped() {
    let mut h = harness("allow", Behavior::Confirm).await;
    let provider = Arc::new(Provider::default());
    h.gateway.register_adapter("adp_payments", provider.clone());
    h.gateway.pin_capability(refund(declared())).unwrap();
    let mut once = serde_json::to_value(reverse()).unwrap();
    once["recovery"] = json!({"strategy": "manual_reconcile", "max_attempts": 1, "retry_delays_seconds": []});
    h.gateway.pin_capability(serde_json::from_value(once).unwrap()).unwrap();
    h.admission.surfaced_capabilities.insert(REVERSE.into());
    h.gateway
        .dispatch(&h.admission, &refund_call("refund_a", 5_000))
        .await
        .unwrap();
    provider.script("refunds.reverse", &[EffectOutcome::NotApplied]);
    let out = h
        .gateway
        .compensate(&h.admission, "refund_a", "tc_1", None)
        .await
        .unwrap();
    assert_eq!(out.result["status"], "failed");
    assert_eq!(effect(&h, "refund_a").await["state"], "compensation_exhausted");
    let out = h
        .gateway
        .compensate(&h.admission, "refund_a", "tc_2", None)
        .await
        .unwrap();
    assert_eq!(out.report.reason_codes, ["compensation_exhausted"]);
    assert_eq!(out.report.obligations, ["escalate"]);
    let saga = h.gateway.compensate_run(&h.admission, None).await.unwrap();
    assert_eq!(
        saga["stopped_at"],
        json!({"operation_id": "refund_a", "reason": "compensation_exhausted"})
    );
    assert_eq!(provider.calls().len(), 2);
}

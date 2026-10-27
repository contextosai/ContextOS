//! Shared findings: provenance from the operation ledger, falsification by evidence,
//! suspect dependents and peeked notices, within one root's team.
use std::sync::Arc;

use async_trait::async_trait;
use contextos_audit::{AuditSigner, AuditWriter};
use contextos_gateway::{
    ApprovalProvider, AuthorityFacts, AuthorityProvider, Clock, ConstraintProvider, FindingInput, Gateway, IdSource,
    PolicyProvider, PortError, Ports, RunAdmission, operation_ledger_key,
};
use contextos_store::{DocKey, DocKind, DocumentStore, MemoryLog, MemoryStore};
use serde_json::{Value, json};

const TENANT: &str = "team";

struct Fixed;
impl Clock for Fixed {
    fn now(&self) -> String {
        "2030-01-01T00:00:00Z".into()
    }
}
impl IdSource for Fixed {
    fn new_id(&self, prefix: &str) -> String {
        format!("{prefix}_1")
    }
}
#[async_trait]
impl AuthorityProvider for Fixed {
    async fn authority(&self, _: &RunAdmission, _: &Value) -> Result<AuthorityFacts, PortError> {
        Err(PortError::new("unused", "findings do not authorize tools"))
    }
}
#[async_trait]
impl ConstraintProvider for Fixed {
    async fn observations(&self, _: &RunAdmission, _: &[Value], _: &str) -> Result<Vec<Value>, PortError> {
        Err(PortError::new("unused", "not called"))
    }
}
#[async_trait]
impl ApprovalProvider for Fixed {
    async fn approval(&self, _: &RunAdmission, _: &str) -> Result<Option<Value>, PortError> {
        Err(PortError::new("unused", "not called"))
    }
    async fn request(&self, _: &RunAdmission, _: &Value, _: &str) -> Result<String, PortError> {
        Err(PortError::new("unused", "not called"))
    }
}
#[async_trait]
impl PolicyProvider for Fixed {
    async fn outcomes(&self, _: &RunAdmission, _: &Value) -> Result<Vec<Value>, PortError> {
        Err(PortError::new("unused", "not called"))
    }
}

struct Team {
    store: Arc<MemoryStore>,
    gateway: Gateway<MemoryStore, MemoryLog>,
    root: RunAdmission,
    a: RunAdmission,
    b: RunAdmission,
    outsider: RunAdmission,
}

async fn admit(store: &MemoryStore, id: &str, principal: &str, root: Option<&str>) -> RunAdmission {
    let admission: RunAdmission = serde_json::from_value(json!({
        "tenant_id": TENANT, "run_id": id, "trace_id": "trace", "contract": {}, "contract_id": "contract",
        "required_controls": [], "actor": {}, "policy_refs": [], "policy_outcomes": [], "profile_refs": [],
        "release_refs": [], "surfaced_capabilities": [], "evidence": {}, "operation_ledger_id": id,
        "budget_ledger_id": id, "executor_generation": 2, "deadline": "2030-01-01T01:00:00Z",
        "gateway_observer": {}, "admitted_by": principal,
        "lineage": root.map(|r| json!({"delegation_id": id, "root_run_id": r, "parent_run_id": r,
            "effect_policy": "isolate_until_accepted", "links": []})),
    }))
    .unwrap();
    store
        .create(
            &DocKey::new(TENANT, DocKind::RunAdmission, id),
            &serde_json::to_value(&admission).unwrap(),
        )
        .await
        .unwrap();
    store
        .create(
            &DocKey::new(TENANT, DocKind::RunState, id),
            &json!({"status": "running", "executor_generation": 2}),
        )
        .await
        .unwrap();
    admission
}

async fn team() -> Team {
    let store = Arc::new(MemoryStore::new());
    let root = admit(&store, "root", "coordinator", None).await;
    let a = admit(&store, "worker-a", "principal-a", Some("root")).await;
    let b = admit(&store, "worker-b", "principal-b", Some("root")).await;
    let outsider = admit(&store, "elsewhere", "principal-x", None).await;
    let ports = Ports {
        clock: Arc::new(Fixed),
        ids: Arc::new(Fixed),
        authority: Arc::new(Fixed),
        constraints: Arc::new(Fixed),
        approvals: Arc::new(Fixed),
        policy: Arc::new(Fixed),
        idempotency: None,
        data_flow: None,
        boundary: None,
        memory: None,
    };
    let audit = Arc::new(AuditWriter::new(
        MemoryLog::new(),
        AuditSigner::from_seed("findings", [7; 32]),
    ));
    Team {
        gateway: Gateway::new(store.clone(), audit, ports),
        store,
        root,
        a,
        b,
        outsider,
    }
}

/// An operation as the gateway records it, with `outcome`.
async fn recorded(t: &Team, run: &RunAdmission, operation_id: &str, outcome: &str) {
    let finality = if outcome == "unknown" {
        "provisional"
    } else {
        "definitive"
    };
    let body = json!({"operations": [{
        "intent": {"operation_id": operation_id, "action_digest": format!("sha256:{}", "d".repeat(64)),
            "capability_ref": {"artifact_type": "capability", "artifact_id": "run_tests"}},
        "attempts": [{"attempt_id": "attempt_1", "dispatch_state": "settled"}],
        "observations": [{"attempt_id": "attempt_1", "outcome": outcome, "finality": finality,
            "evidence_ref": {"artifact_type": "effect_observation", "artifact_id": "observation_1",
                "sha256": format!("sha256:{}", "e".repeat(64))},
            "observed_at": "2030-01-01T00:00:00Z"}],
        "outcome": outcome, "conflict": false,
    }]});
    t.store
        .create(&operation_ledger_key(run, operation_id), &body)
        .await
        .unwrap();
}

fn finding(value: Value) -> FindingInput {
    serde_json::from_value(value).unwrap()
}

#[tokio::test]
async fn observed_findings_take_their_basis_from_the_operation_ledger() {
    let t = team().await;
    recorded(&t, &t.a, "tests_1", "confirmed").await;
    recorded(&t, &t.a, "deploy_1", "unknown").await;
    recorded(&t, &t.outsider, "theirs", "confirmed").await;

    // A peer cites another team member's recorded call; the runtime fills the basis.
    let published = t
        .gateway
        .publish_finding(
            &t.b,
            "principal-b",
            2,
            finding(json!({"finding_id": "suite_green", "kind": "observed",
                "statement": "The parser suite passes on main.",
                "basis": {"run_id": "worker-a", "operation_id": "tests_1"}})),
        )
        .await
        .unwrap();
    let basis = &published["finding"]["basis"];
    assert_eq!(basis["run_id"], "worker-a");
    assert_eq!(basis["action_digest"], format!("sha256:{}", "d".repeat(64)));
    assert_eq!(basis["observation_ref"]["artifact_id"], "observation_1");
    assert_eq!(published["data_only"], true);

    let refused = |run: &'static str, op: &'static str| {
        let t = &t;
        async move {
            t.gateway
                .publish_finding(
                    &t.b,
                    "principal-b",
                    2,
                    finding(
                        json!({"finding_id": format!("f_{op}"), "kind": "observed", "statement": "x",
                        "basis": {"run_id": run, "operation_id": op}}),
                    ),
                )
                .await
                .unwrap_err()
                .code()
        }
    };
    assert_eq!(refused("worker-a", "deploy_1").await, "basis_unconfirmed");
    assert_eq!(refused("worker-a", "never").await, "basis_not_found");
    assert_eq!(refused("elsewhere", "theirs").await, "basis_outside_team");
    // The caller cannot supply the basis facts itself.
    assert!(
        serde_json::from_value::<FindingInput>(json!({"finding_id": "forged", "kind": "observed",
        "statement": "x", "basis": {"operation_id": "tests_1", "action_digest": "sha256:forged"}}))
        .is_err()
    );
    // Membership is the admitting principal, as on the work board.
    let stranger = t
        .gateway
        .publish_finding(
            &t.b,
            "principal-a",
            2,
            finding(json!({"finding_id": "c", "kind": "claim", "statement": "x"})),
        )
        .await
        .unwrap_err();
    assert_eq!(stranger.code(), "work_forbidden");
}

#[tokio::test]
async fn a_falsified_finding_flags_its_dependents_and_notifies_the_team() {
    let t = team().await;
    let g = &t.gateway;
    let publish = |run: &RunAdmission, principal: &str, value: Value| {
        let (run, principal) = (run.clone(), principal.to_owned());
        async move { g.publish_finding(&run, &principal, 2, finding(value)).await }
    };
    publish(
        &t.a,
        "principal-a",
        json!({"finding_id": "root_cause", "kind": "claim",
        "statement": "The outage is caused by the cache TTL."}),
    )
    .await
    .unwrap();
    publish(
        &t.root,
        "coordinator",
        json!({"finding_id": "fix", "kind": "claim",
        "statement": "Lower the TTL to 30s.", "depends_on": ["root_cause"]}),
    )
    .await
    .unwrap();

    // Worker b disagrees, but must show a recorded observation to falsify a's claim.
    let unsupported = g
        .invalidate_finding(&t.b, "principal-b", 2, "root_cause", "I doubt it", None)
        .await
        .unwrap_err();
    assert_eq!(unsupported.code(), "refutation_required");
    recorded(&t, &t.b, "replay_1", "confirmed").await;
    publish(
        &t.b,
        "principal-b",
        json!({"finding_id": "replay", "kind": "observed",
        "statement": "Replaying traffic with the TTL at 30s still fails.",
        "basis": {"operation_id": "replay_1"}, "refutes": "root_cause"}),
    )
    .await
    .unwrap();
    let done = g
        .invalidate_finding(
            &t.b,
            "principal-b",
            2,
            "root_cause",
            "Replay disproves it",
            Some("replay"),
        )
        .await
        .unwrap();
    assert_eq!(done["finding"]["status"], "invalidated");
    assert_eq!(done["suspect"], json!(["fix"]));

    let listed = g.findings(&t.root, "coordinator", 2, None, 100).await.unwrap();
    let fix = listed["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["finding_id"] == "fix")
        .unwrap();
    assert_eq!(fix["status"], "suspect");
    assert_eq!(fix["suspect_because"], json!(["root_cause"]));

    // Everyone but the falsifier sees it, on its next tool result, until acknowledged.
    let on_result = g.notices_for_result(&t.a, "principal-a", 2).await.unwrap();
    assert_eq!(on_result["pending"], 1);
    assert_eq!(on_result["notices"][0]["kind"], "finding_invalidated");
    assert_eq!(on_result["notices"][0]["suspect"], json!(["fix"]));
    assert!(g.notices_for_result(&t.b, "principal-b", 2).await.is_none());
    assert!(
        g.notices_for_result(&t.a, "principal-b", 2).await.is_none(),
        "not the run's principal"
    );
    assert!(
        g.notices_for_result(&t.a, "principal-a", 1).await.is_none(),
        "a stale executor"
    );
    assert!(
        g.notices_for_result(&t.a, "principal-a", 2).await.is_some(),
        "peeking does not consume"
    );
    let seq = on_result["notices"][0]["seq"].as_u64().unwrap();
    let acked = g.acknowledge_notices(&t.a, "principal-a", 2, seq).await.unwrap();
    assert_eq!(acked["pending"], 0);
    assert!(g.notices_for_result(&t.a, "principal-a", 2).await.is_none());
    assert_eq!(g.notices(&t.root, "coordinator", 2, 10).await.unwrap()["pending"], 1);
}

#[tokio::test]
async fn erasing_the_root_tombstones_its_findings() {
    let t = team().await;
    t.gateway
        .publish_finding(
            &t.a,
            "principal-a",
            2,
            finding(json!({"finding_id": "x", "kind": "claim", "statement": "Personal detail"})),
        )
        .await
        .unwrap();
    let state = DocKey::new(TENANT, DocKind::RunState, "root");
    let current = t.store.get(&state).await.unwrap().unwrap();
    t.store
        .compare_and_swap(
            &state,
            current.revision,
            &json!({"status": "completed", "executor_generation": 2}),
        )
        .await
        .unwrap();
    let erased = t.gateway.erase_run(&t.root, "operator", "retention").await.unwrap();
    assert!(
        erased["erased"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["document"] == "findings"),
        "{erased}"
    );
    let stored = t
        .store
        .get(&DocKey::new(TENANT, DocKind::Findings, "root"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.body["erased"], true);
    assert!(t.gateway.notices_for_result(&t.a, "principal-a", 2).await.is_none());
}

#[tokio::test]
async fn a_team_out_of_room_for_findings_can_still_falsify_and_acknowledge() {
    let t = team().await;
    let g = &t.gateway;
    // Long statements of characters JSON must escape, until publication is refused.
    let statement = "\"\\".repeat(1024);
    let mut published = Vec::new();
    loop {
        let id = format!("f{}", published.len());
        let out = g
            .publish_finding(
                &t.a,
                "principal-a",
                2,
                finding(json!({"finding_id": id, "kind": "claim", "statement": statement,
                    "depends_on": published.last().map_or_else(Vec::new, |p: &String| vec![p.clone()]),
                    "urgent": true})),
            )
            .await;
        match out {
            Ok(_) => published.push(id),
            Err(e) => {
                assert_eq!(e.code(), "findings_full");
                break;
            }
        }
    }
    assert!(published.len() > 50, "{}", published.len());
    // Every finding can still be withdrawn, each cascading over the chain behind it.
    for id in &published {
        g.invalidate_finding(&t.a, "principal-a", 2, id, &"r".repeat(256), None)
            .await
            .unwrap();
    }
    let latest = g.notices(&t.b, "principal-b", 2, 1).await.unwrap()["latest_seq"].clone();
    g.acknowledge_notices(&t.b, "principal-b", 2, latest.as_u64().unwrap())
        .await
        .unwrap();
}

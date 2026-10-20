//! Audit chain integrity under concurrency and tampering; DecisionRecord assembly.

use std::sync::Arc;

use contextos_audit::{
    AuditEntry, AuditSigner, AuditWriter, DecisionDraft, DecisionError, KeyRing, assemble_decision, replay_packet,
    verify_chain, verify_tenant_chain,
};
use contextos_contract::types::{
    BudgetUsage, ContextPack, DecisionActor, DecisionActorType, DecisionLineage, DecisionStatus, InvokeRequest,
    RunContext,
};
use contextos_kernel::{CompileDeps, ContextPackCompiler};
use contextos_store::{AppendLog, MemoryLog};
use serde_json::{Value, json};

fn signer() -> AuditSigner {
    AuditSigner::from_seed("audit-key-2026-10", [7; 32])
}

fn keys() -> KeyRing {
    let mut ring = KeyRing::new();
    ring.insert("audit-key-2026-10", signer().verifying_key());
    ring
}

fn time(i: u64) -> String {
    format!("2026-10-20T10:{:02}:{:02}Z", i / 60, i % 60)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_appends_form_one_verified_chain() {
    let writer = Arc::new(AuditWriter::new(MemoryLog::new(), signer()));
    let mut tasks = Vec::new();
    for i in 0..48 {
        let writer = writer.clone();
        tasks.push(tokio::spawn(async move {
            // Same emission time for all writers keeps ordering valid under any interleaving.
            writer
                .append("tenant_acme_prod", "run_transition", json!({"i": i}), &time(1))
                .await
                .unwrap()
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    assert_eq!(
        verify_tenant_chain(writer.log(), "tenant_acme_prod", &keys())
            .await
            .unwrap(),
        48
    );
    // Other tenants have independent chains.
    assert_eq!(
        verify_tenant_chain(writer.log(), "tenant_other", &keys())
            .await
            .unwrap(),
        0
    );
}

async fn chain(n: u64) -> Vec<AuditEntry> {
    let writer = AuditWriter::new(MemoryLog::new(), signer());
    for i in 0..n {
        writer
            .append("tenant_acme_prod", "event", json!({"i": i}), &time(i))
            .await
            .unwrap();
    }
    writer
        .log()
        .range("tenant_acme_prod", 1, 100)
        .await
        .unwrap()
        .into_iter()
        .map(|row| serde_json::from_value(row.body).unwrap())
        .collect()
}

#[tokio::test]
async fn tampering_is_detected() {
    let entries = chain(12).await;
    verify_chain(&entries, None, &keys()).unwrap();

    let mut edited = entries.clone();
    edited[5].payload = json!({"i": 999});
    assert!(
        verify_chain(&edited, None, &keys())
            .unwrap_err()
            .to_string()
            .contains("payload digest")
    );

    let mut deleted = entries.clone();
    deleted.remove(6);
    assert!(verify_chain(&deleted, None, &keys()).is_err());

    let mut reordered = entries.clone();
    reordered.swap(3, 4);
    assert!(verify_chain(&reordered, None, &keys()).is_err());

    let mut resigned = entries.clone();
    let forged = AuditSigner::from_seed("audit-key-2026-10", [9; 32]);
    let head = &entries[3];
    resigned[4] = contextos_audit::next_entry(
        Some(head),
        "tenant_acme_prod",
        "event",
        json!({"forged": true}),
        &time(4),
        &forged,
    )
    .unwrap();
    assert!(
        verify_chain(&resigned, None, &keys())
            .unwrap_err()
            .to_string()
            .contains("signature")
    );

    let mut rotated = keys();
    rotated.remove("audit-key-2026-10");
    assert!(verify_chain(&entries, None, &rotated).is_err());

    // A segment verifies against its trusted anchor.
    verify_chain(&entries[6..], Some(&entries[5]), &keys()).unwrap();
    assert!(verify_chain(&entries[6..], None, &keys()).is_err());
}

fn compiled_refund(with_evidence: bool) -> (contextos_contract::types::CompiledContext, ContextPack) {
    let path = format!("{}/../../conformance/vectors/compiler.json", env!("CARGO_MANIFEST_DIR"));
    let vectors: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let case = vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "grid:support.refund:true:4200:support_agent")
        .unwrap();
    let pack: ContextPack = serde_json::from_value(case["pack"].clone()).unwrap();
    let request: InvokeRequest = serde_json::from_value(case["request"].clone()).unwrap();
    let run: RunContext = serde_json::from_value(case["run_context"].clone()).unwrap();
    let evidence = if with_evidence {
        case["deps"]["evidence"].as_array().unwrap().clone()
    } else {
        vec![]
    };
    let deps = CompileDeps {
        evidence,
        ..CompileDeps::default()
    };
    let compiled = ContextPackCompiler::new(pack.clone())
        .unwrap()
        .compile(&request, &run, &deps)
        .unwrap();
    (compiled, pack)
}

fn draft(compiled: &contextos_contract::types::CompiledContext, status: DecisionStatus) -> DecisionDraft<'_> {
    DecisionDraft {
        record_id: "dr_refund_1".into(),
        decision_key: "support.refund.execute".into(),
        decision_version: "1.0.0".into(),
        timestamp: "2026-10-20T10:00:00Z".into(),
        status,
        actor: DecisionActor {
            actor_type: DecisionActorType::Agent,
            id: "agt_support".into(),
        },
        trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".into(),
        compiled,
        allowed_outcomes: None,
        outcome: None,
        outputs: None,
        intent_ref: Some("support.refund".into()),
        subject_ids: None,
        policy_decisions: vec![],
        approvals: vec![],
        tool_lineage: vec![],
        budget_usage: BudgetUsage {
            tokens: 812,
            tool_calls: 1,
            cost_usd_cents: 0.4,
            wall_clock_ms: 950,
        },
        lineage: DecisionLineage {
            pack_version: "ctxpack.support@5.2.0".into(),
            ..DecisionLineage::default()
        },
        scorecard: None,
        confidence: None,
        rationale: None,
    }
}

#[tokio::test]
async fn open_evidence_gate_blocks_commit_and_records_are_chained() {
    let (open, _) = compiled_refund(false);
    // Without retrieved evidence, order_lookup and policy.eval are unresolved: the gate is open.
    let gate = open
        .runtime_controls
        .evidence_gates
        .iter()
        .find(|g| g.decision_key == "support.refund.execute")
        .unwrap();
    assert!(!gate.commit_allowed);
    assert_eq!(
        assemble_decision(draft(&open, DecisionStatus::Decided)).unwrap_err(),
        DecisionError::EvidenceGateOpen("support.refund.execute".into())
    );

    let (compiled, pack) = compiled_refund(true);
    let gate = compiled
        .runtime_controls
        .evidence_gates
        .iter()
        .find(|g| g.decision_key == "support.refund.execute")
        .unwrap();
    assert!(gate.commit_allowed);
    assemble_decision(draft(&compiled, DecisionStatus::Decided)).unwrap();

    let spec = &pack.decision_layer.decision_specs[0];
    let mut escalated = draft(&compiled, DecisionStatus::Escalated);
    escalated.allowed_outcomes = Some(&spec.allowed_outcomes);
    escalated.outcome = Some("escalated".into());
    let record = assemble_decision(escalated).unwrap();
    assert_eq!(
        record.context_snapshot_hash.as_deref(),
        Some(compiled.context_ledger.compiled_context_hash.as_str())
    );

    let mut bogus = draft(&compiled, DecisionStatus::Escalated);
    bogus.allowed_outcomes = Some(&spec.allowed_outcomes);
    bogus.outcome = Some("refund_everything".into());
    assert!(matches!(
        assemble_decision(bogus),
        Err(DecisionError::OutcomeNotAllowed(_))
    ));

    let writer = AuditWriter::new(MemoryLog::new(), signer());
    let recorded = writer
        .record_decision("tenant_acme_prod", record, "2026-10-20T10:00:01Z")
        .await
        .unwrap();
    let audit = recorded.audit.clone().unwrap();
    assert_eq!(audit.signed_by.as_deref(), Some("audit-key-2026-10"));
    assert_eq!(
        verify_tenant_chain(writer.log(), "tenant_acme_prod", &keys())
            .await
            .unwrap(),
        1
    );

    let packet = replay_packet(&recorded, "rp_1".into(), "ctxpack.support@5.2.0".into(), None).unwrap();
    assert_eq!(
        packet.compiled_context_hash,
        compiled.context_ledger.compiled_context_hash
    );
    assert_eq!(packet.expected.status, "ESCALATED");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn group_commit_never_forks_across_writers() {
    use std::sync::Arc;
    let log = Arc::new(contextos_store::MemoryLog::new());
    // Two writers over one log behave like two replicas over one database.
    let writers = [
        Arc::new(AuditWriter::new(log.clone(), AuditSigner::from_seed("w1", [1; 32]))),
        Arc::new(AuditWriter::new(log.clone(), AuditSigner::from_seed("w2", [2; 32]))),
    ];
    let mut tasks = Vec::new();
    for i in 0..400_u32 {
        let writer = writers[(i % 2) as usize].clone();
        tasks.push(tokio::spawn(async move {
            // Timestamps arrive out of order; the chain still never goes backwards.
            let at = format!("2026-10-20T10:00:{:02}Z", 59 - (i % 60));
            writer
                .append("tenant_a", "event", serde_json::json!({"i": i}), &at)
                .await
                .unwrap()
        }));
    }
    let mut sequences = Vec::new();
    for task in tasks {
        sequences.push(task.await.unwrap().sequence);
    }
    sequences.sort_unstable();
    assert_eq!(
        sequences,
        (1..=400).collect::<Vec<u64>>(),
        "every append got its own place"
    );
    let mut keys = KeyRing::new();
    keys.insert("w1", AuditSigner::from_seed("w1", [1; 32]).verifying_key());
    keys.insert("w2", AuditSigner::from_seed("w2", [2; 32]).verifying_key());
    assert_eq!(verify_tenant_chain(&log, "tenant_a", &keys).await.unwrap(), 400);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn append_all_keeps_entries_consecutive_and_in_order() {
    use std::sync::Arc;
    let writer = Arc::new(AuditWriter::new(MemoryLog::new(), AuditSigner::from_seed("w", [4; 32])));
    let mut tasks = Vec::new();
    for i in 0..50_u32 {
        let writer = writer.clone();
        tasks.push(tokio::spawn(async move {
            if i % 5 == 0 {
                let items = (0..3)
                    .map(|j| {
                        (
                            format!("group_{j}"),
                            json!({"i": i, "j": j}),
                            "2026-10-20T10:00:00Z".to_owned(),
                        )
                    })
                    .collect();
                let entries = writer.append_all("tenant_g", items).await.unwrap();
                let sequences: Vec<u64> = entries.iter().map(|e| e.sequence).collect();
                assert_eq!(
                    entries.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>(),
                    ["group_0", "group_1", "group_2"]
                );
                assert_eq!(
                    sequences,
                    (sequences[0]..sequences[0] + 3).collect::<Vec<_>>(),
                    "consecutive"
                );
            } else {
                writer
                    .append("tenant_g", "single", json!({"i": i}), "2026-10-20T10:00:00Z")
                    .await
                    .unwrap();
            }
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    let mut keys = KeyRing::new();
    keys.insert("w", AuditSigner::from_seed("w", [4; 32]).verifying_key());
    assert_eq!(
        verify_tenant_chain(writer.log(), "tenant_g", &keys).await.unwrap(),
        40 + 10 * 3
    );
}

//! A result-screening provider decides what of a confirmed effect's output the agent
//! sees; the effect itself stands either way.

mod support;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use contextos_gateway::result_screening::ResultScreeningProvider;
use contextos_gateway::*;
use contextos_store::{AppendLog, MemoryLog, MemoryStore};
use serde_json::{Value, json};
use support::*;

/// Answers each screening with the verdict the test sets (`None`: unreachable).
struct Screen(Mutex<Option<Value>>);

#[async_trait]
impl ResultScreeningProvider for Screen {
    async fn screen(&self, _: &RunAdmission, _: &CapabilityManifest, output: &Value) -> Result<Value, PortError> {
        assert!(output["refund_id"].is_string(), "the provider sees the output");
        self.0
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| PortError::new("result_screening", "unreachable"))
    }
}

fn screened_gateway(h: &Harness, screen: Arc<Screen>) -> Gateway<MemoryStore, MemoryLog> {
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
    g.pin_capability(manifest()).unwrap();
    g.set_result_screening(screen);
    g
}

async fn screened(h: &Harness, g: &Gateway<MemoryStore, MemoryLog>, id: &str) -> DispatchOutcome {
    g.dispatch(&h.admission, &call(id, Some(&format!("refund_{id}"))))
        .await
        .unwrap()
}

async fn audited(h: &Harness, kind: &str) -> Vec<Value> {
    h.audit
        .log()
        .range(&h.admission.tenant_id, 1, 1000)
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.body["kind"] == kind)
        .map(|r| r.body["payload"].clone())
        .collect()
}

#[tokio::test]
async fn screening_passes_redacts_or_withholds_and_fails_closed() {
    let h = harness("allow", Behavior::Confirm).await;
    let screen = Arc::new(Screen(Mutex::new(Some(json!({"verdict": "pass"})))));
    let g = screened_gateway(&h, screen.clone());

    let passed = screened(&h, &g, "tc_1").await;
    assert_eq!(passed.report.status, "completed");
    assert!(passed.result["output"]["refund_id"].is_string(), "{}", passed.result);

    *screen.0.lock().unwrap() =
        Some(json!({"verdict": "redact", "pointers": ["/refund_id"], "reason_codes": ["secret_detected"]}));
    let redacted = screened(&h, &g, "tc_2").await;
    assert_eq!(
        redacted.result["output"]["refund_id"], "[redacted]",
        "{}",
        redacted.result
    );
    assert!(redacted.report.reason_codes.contains(&"result_redacted".to_owned()));

    *screen.0.lock().unwrap() = Some(json!({"verdict": "withhold", "reason_codes": ["prompt_injection"]}));
    let withheld = screened(&h, &g, "tc_3").await;
    assert_eq!(withheld.report.status, "completed", "the effect stands");
    assert!(
        withheld.result["output"]
            .as_object()
            .is_none_or(serde_json::Map::is_empty),
        "{}",
        withheld.result
    );
    assert!(
        withheld
            .report
            .obligations
            .contains(&"verify_effect_out_of_band".to_owned())
    );

    // Unreachable or malformed: withheld, never passed through.
    *screen.0.lock().unwrap() = None;
    let unavailable = screened(&h, &g, "tc_4").await;
    assert!(unavailable.report.reason_codes.contains(&"result_withheld".to_owned()));
    *screen.0.lock().unwrap() = Some(json!({"verdict": "allow"}));
    let malformed = screened(&h, &g, "tc_5").await;
    assert!(malformed.report.reason_codes.contains(&"result_withheld".to_owned()));
    assert_eq!(
        h.adapter.calls.load(Ordering::SeqCst),
        5,
        "every effect was applied once"
    );

    // Every non-pass verdict is audited with pointers and reasons, never content.
    let entries = audited(&h, "result_screened").await;
    let verdicts: Vec<&str> = entries.iter().filter_map(|e| e["verdict"].as_str()).collect();
    assert_eq!(verdicts, ["redact", "withhold", "withhold", "withhold"]);
    assert_eq!(entries[0]["pointers"], json!(["/refund_id"]));
    assert_eq!(entries[2]["reason_codes"], json!(["result_screening_unavailable"]));
    assert!(!json!(entries).to_string().contains("rf_"), "no output in the chain");
}

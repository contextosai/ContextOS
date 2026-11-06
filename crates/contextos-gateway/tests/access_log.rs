//! A call that fails on infrastructure still leaves its access line, with
//! `status="error"`, so dashboards counting access lines count it.
//!
//! Its own test binary: tracing caches which callsites are enabled process-wide, so a
//! capturing subscriber shares a process with other tests unreliably.

mod support;

use std::io::Write;
use std::sync::{Arc, Mutex};

use contextos_gateway::*;
use contextos_store::MemoryStore;
use serde_json::Value;
use support::outcome::*;
use support::*;

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn an_infrastructure_failure_leaves_an_error_access_line() {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_current_span(true)
        .with_env_filter("off,contextos_gateway=info,contextos::access=info")
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let store = Arc::new(MemoryStore::new());
    let admission = admitted(&store).await;
    let audit = audit();
    let adapter = provider(EffectOutcome::Confirmed, None);
    // The store fails at the call's first write.
    let crashing = Arc::new(CrashStore::new(store.clone(), 0, false));
    let gateway = process(crashing, &audit, adapter.clone(), 10_000, NOW);
    let error = gateway
        .dispatch(&admission, &refund_call("run_1", "infra_refund"))
        .await
        .expect_err("the store is down");
    assert!(matches!(error, GatewayError::Store(_)), "{error}");
    assert_eq!(adapter.calls(), 0);

    let lines: Vec<Value> = String::from_utf8(captured.0.lock().unwrap().clone())
        .unwrap()
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|l| l["target"] == "contextos::access")
        .collect();
    assert_eq!(lines.len(), 1, "{lines:#?}");
    let fields = &lines[0]["fields"];
    assert_eq!(fields["status"], "error");
    assert_eq!(fields["reason_codes"], "store_unavailable");
    assert_eq!(fields["run_id"], "run_1");
    assert_eq!(fields["capability_id"], "adp_payments.issue_refund");
    assert_eq!(lines[0]["span"]["error.type"], "infrastructure");
}

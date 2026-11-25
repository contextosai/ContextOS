//! Audit sinks deliver every tenant's chain in order, signed, masked where configured,
//! and never skip an entry: a refused batch is delivered again before anything later.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use contextos_audit::{AuditEntry, verify_chain_withheld};
use contextosd::audit_sink_formats::SinkFormat;
use contextosd::audit_sinks::{AuditSinkConfig, Exporter, Sink, Start};
use serde_json::{Value, json};

use crate::harness::*;

type Received = Arc<Mutex<Vec<(HeaderMap, Value)>>>;

const SECRET: &str = "sink-secret-0123456789abcdef0123456789ab";
const MASK_KEY: &str = "mask-key-0123456789abcdef0123456789abcd";

async fn receiver(failing: Arc<AtomicBool>) -> (String, Received) {
    let received: Received = Arc::default();
    let seen = received.clone();
    let base = serve(Router::new().route(
        "/collector",
        post(move |headers: HeaderMap, body: String| {
            let seen = seen.clone();
            let failing = failing.clone();
            async move {
                if failing.load(Ordering::SeqCst) {
                    return StatusCode::SERVICE_UNAVAILABLE;
                }
                seen.lock()
                    .unwrap()
                    .push((headers, serde_json::from_str(&body).unwrap()));
                StatusCode::OK
            }
        }),
    ))
    .await;
    (format!("{base}/collector"), received)
}

fn sink(url: &str, kinds: &[&str], batch: usize) -> Sink {
    Sink::new(
        AuditSinkConfig {
            id: "siem".into(),
            url: url.into(),
            secret_env: "UNUSED".into(),
            kinds: kinds.iter().map(|k| (*k).to_owned()).collect(),
            mask: vec!["email".into(), "/card/*".into()],
            mask_key_env: Some("UNUSED".into()),
            batch,
            start: Start::Genesis,
            format: SinkFormat::Contextos,
            token_env: None,
        },
        SECRET.as_bytes(),
        Some(MASK_KEY.as_bytes()),
    )
    .unwrap()
}

fn delivered(received: &Received) -> Vec<Value> {
    received
        .lock()
        .unwrap()
        .iter()
        .flat_map(|(_, body)| body["entries"].as_array().cloned().unwrap_or_default())
        .collect()
}

#[tokio::test]
async fn the_whole_chain_is_delivered_masked_and_still_verifies() {
    let failing = Arc::new(AtomicBool::new(true));
    let (url, received) = receiver(failing.clone()).await;
    let w = world(&ALL_CONTROLS).await;
    let now = || w.state.gateway.as_ref().unwrap().now();
    let audit = &w.state.audit;
    for (kind, payload) in [
        (
            "escalation_opened",
            json!({"escalation_id": "esc_1", "email": "a@example.com"}),
        ),
        (
            "operator_note",
            json!({"note": "n", "card": {"pan": "4111", "last4": "1111"}}),
        ),
        (
            "escalation_opened",
            json!({"escalation_id": "esc_2", "email": "a@example.com"}),
        ),
    ] {
        audit.append(TENANT, kind, payload, &now()).await.unwrap();
    }
    let exporter = |batch| {
        Exporter::new(
            w.state.store.clone(),
            w.state.audit.clone(),
            w.state.metrics.clone(),
            vec![sink(&url, &[], batch)],
            vec![TENANT.into()],
            true,
        )
    };

    // A refused batch moves nothing; the next attempt starts from the same entry.
    exporter(2).tick().await;
    assert!(received.lock().unwrap().is_empty());
    failing.store(false, Ordering::SeqCst);
    exporter(2).tick().await;
    let entries = delivered(&received);
    let sequences: Vec<u64> = entries.iter().map(|e| e["sequence"].as_u64().unwrap()).collect();
    let head = sequences.len() as u64;
    assert!(head >= 3);
    assert_eq!(
        sequences,
        (1..=head).collect::<Vec<_>>(),
        "in order, from genesis, once"
    );
    // Every request is signed, in batches of at most 2.
    for (headers, body) in received.lock().unwrap().iter() {
        let header = headers["contextos-signature"].to_str().unwrap();
        let t: u64 = header.split(',').next().unwrap()[2..].parse().unwrap();
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, SECRET.as_bytes());
        let expected = contextosd::notifications::signature(&key, t, &serde_json::to_vec(body).unwrap());
        assert_eq!(header, expected);
        assert!(body["entries"].as_array().unwrap().len() <= 2);
        assert_eq!(body["tenant_id"], TENANT);
    }

    // Masked fields are tokens; equal values give equal tokens; the rest is intact.
    let opened: Vec<&Value> = entries.iter().filter(|e| e["kind"] == "escalation_opened").collect();
    let token = opened[0]["payload"]["email"].as_str().unwrap();
    assert!(token.starts_with("masked:hmac-sha256:"), "{token}");
    assert_eq!(opened[1]["payload"]["email"], token);
    assert_eq!(opened[0]["payload"]["escalation_id"], "esc_1");
    assert_eq!(opened[0]["masked"]["paths"], json!(["/email"]));
    let note = entries.iter().find(|e| e["kind"] == "operator_note").unwrap();
    assert_eq!(note["masked"]["paths"], json!(["/card/last4", "/card/pan"]));
    assert!(!serde_json::to_string(&entries).unwrap().contains("a@example.com"));

    // The delivered copy verifies: every spine and signature, unmasked payloads in full.
    let withheld: Vec<bool> = entries.iter().map(|e| e.get("masked").is_some()).collect();
    let chain: Vec<AuditEntry> = serde_json::from_value(Value::Array(entries.clone())).unwrap();
    verify_chain_withheld(&chain, None, &w.state.audit_keys, &withheld).unwrap();
    // Treating a masked copy as complete fails: its payload no longer matches.
    assert!(contextos_audit::verify_chain(&chain, None, &w.state.audit_keys).is_err());

    // Only what follows is delivered next.
    audit
        .append(TENANT, "operator_note", json!({"note": "later"}), &now())
        .await
        .unwrap();
    exporter(2).tick().await;
    let all = delivered(&received);
    assert_eq!(all.len() as u64, head + 1);
    assert_eq!(all.last().unwrap()["payload"]["note"], "later");
    assert!(
        w.state
            .metrics
            .render()
            .contains("contextos_audit_sink_batches_total{sink=\"siem\",outcome=\"failed\"} 1")
    );
}

#[tokio::test]
async fn kinds_limit_what_is_delivered_but_not_where_the_cursor_stands() {
    let (url, received) = receiver(Arc::new(AtomicBool::new(false))).await;
    let w = world(&ALL_CONTROLS).await;
    let now = || w.state.gateway.as_ref().unwrap().now();
    w.state
        .audit
        .append(TENANT, "operator_note", json!({}), &now())
        .await
        .unwrap();
    w.state
        .audit
        .append(TENANT, "escalation_opened", json!({"escalation_id": "e"}), &now())
        .await
        .unwrap();
    let mut exporter = Exporter::new(
        w.state.store.clone(),
        w.state.audit.clone(),
        w.state.metrics.clone(),
        vec![sink(&url, &["escalation_opened"], 100)],
        vec![TENANT.into()],
        true,
    );
    exporter.tick().await;
    exporter.tick().await;
    let entries = delivered(&received);
    assert_ne!(entries.len(), 0);
    assert!(entries.iter().all(|e| e["kind"] == "escalation_opened"));
    assert_eq!(
        entries.iter().filter(|e| e["payload"]["escalation_id"] == "e").count(),
        1
    );
}

/// An Elasticsearch `_bulk` endpoint: checks the API key, records each created `_id`, and
/// fails one item the first time, as a mapping error would.
async fn bulk_receiver(fail_once: Arc<AtomicBool>) -> (String, Arc<Mutex<Vec<String>>>) {
    let ids: Arc<Mutex<Vec<String>>> = Arc::default();
    let seen = ids.clone();
    let base = serve(Router::new().route(
        "/audit/_bulk",
        post(move |headers: HeaderMap, body: String| {
            let seen = seen.clone();
            let fail_once = fail_once.clone();
            async move {
                if headers["authorization"] != "ApiKey es-token" || headers["content-type"] != "application/x-ndjson" {
                    return (StatusCode::UNAUTHORIZED, String::new());
                }
                let fail = fail_once.swap(false, Ordering::SeqCst);
                let mut items = Vec::new();
                for (i, line) in body.lines().enumerate().filter(|(i, _)| i % 2 == 0) {
                    let action: Value = serde_json::from_str(line).unwrap();
                    let id = action["create"]["_id"].as_str().unwrap().to_owned();
                    let status = if fail && i == 0 { 400 } else { 201 };
                    if status == 201 {
                        let mut seen = seen.lock().unwrap();
                        if seen.contains(&id) {
                            items.push(json!({"create": {"_id": id, "status": 409}}));
                            continue;
                        }
                        seen.push(id.clone());
                    }
                    items.push(json!({"create": {"_id": id, "status": status}}));
                }
                (StatusCode::OK, json!({"errors": fail, "items": items}).to_string())
            }
        }),
    ))
    .await;
    (format!("{base}/audit/_bulk"), ids)
}

#[tokio::test]
async fn an_elastic_bulk_sink_creates_each_entry_once_and_retries_a_failed_item() {
    let fail_once = Arc::new(AtomicBool::new(true));
    let (url, ids) = bulk_receiver(fail_once.clone()).await;
    let w = world(&ALL_CONTROLS).await;
    let now = || w.state.gateway.as_ref().unwrap().now();
    for n in 0..3 {
        w.state
            .audit
            .append(TENANT, "operator_note", json!({"n": n}), &now())
            .await
            .unwrap();
    }
    let sink = Sink::with_token(
        AuditSinkConfig {
            id: "elastic".into(),
            url,
            secret_env: "UNUSED".into(),
            kinds: vec![],
            mask: vec![],
            mask_key_env: None,
            batch: 100,
            start: Start::Genesis,
            format: SinkFormat::ElasticBulk,
            token_env: Some("UNUSED".into()),
        },
        SECRET.as_bytes(),
        None,
        Some("es-token".into()),
    )
    .unwrap();
    let mut exporter = Exporter::new(
        w.state.store.clone(),
        w.state.audit.clone(),
        w.state.metrics.clone(),
        vec![sink],
        vec![TENANT.into()],
        true,
    );
    exporter.tick().await;
    // One item failed: the batch was not accepted, so the cursor did not move.
    assert!(!fail_once.load(Ordering::SeqCst));
    let first = ids.lock().unwrap().len();
    // Redelivered after the backoff: the failed item is created, the rest are 409s.
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    exporter.tick().await;
    let ids = ids.lock().unwrap().clone();
    assert_eq!(ids.len(), first + 1, "{ids:?}");
    let mut unique = ids.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), ids.len());
    assert!(ids.iter().all(|id| id.starts_with(&format!("{TENANT}:"))));
}

#[test]
fn a_siem_format_without_its_token_is_refused() {
    let config = AuditSinkConfig {
        id: "splunk".into(),
        url: "https://splunk.example.com:8088/services/collector/event".into(),
        secret_env: "UNUSED".into(),
        kinds: vec![],
        mask: vec![],
        mask_key_env: None,
        batch: 100,
        start: Start::Genesis,
        format: SinkFormat::SplunkHec,
        token_env: None,
    };
    assert!(Sink::with_token(config.clone(), SECRET.as_bytes(), None, None).is_err());
    assert!(Sink::with_token(config, SECRET.as_bytes(), None, Some("hec".into())).is_ok());
}

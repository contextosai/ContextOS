//! Memory operations and recall.

use std::sync::Arc;
use std::time::Duration;

use contextos_store::{MemoryLog, MemoryStore};
use contextosd::router;
use serde_json::{Value, json};

use crate::harness::*;

#[tokio::test]
async fn memory_operations_need_a_memory_policy_service() {
    let w = world(&ALL_CONTROLS).await;
    let http = executor_client(2);
    assert_eq!(
        http.post(format!("{}/v1/runs", w.base))
            .bearer_auth("acme-key")
            .json(&run_body("run_mem", 1200))
            .send()
            .await
            .unwrap()
            .status(),
        201
    );
    let refused = http
        .post(format!("{}/v1/runs/run_mem/memory", w.base))
        .bearer_auth("acme-key")
        .json(&json!({"record": {"record_id": "m1", "contract_id": "contract_run_mem", "run_id": "run_mem", "tenant_id": TENANT}}))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 422);
    let decision: Value = refused.json().await.unwrap();
    assert_eq!(decision["reason_codes"], json!(["memory_policy_unavailable"]));
    let missing = http
        .get(format!("{}/v1/memory/m1", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 404, "nothing was stored");
}

#[tokio::test]
async fn recalled_memory_must_be_promoted_current_and_unchanged() {
    use contextos_store::{DocKey, DocKind, DocumentStore as _};
    let (mut config, _) = world_setup(&ALL_CONTROLS).await;
    // A memory-governance service is configured; verification reads only stored state.
    config.providers.as_mut().unwrap().memory =
        Some(serde_json::from_value(json!({"url": "http://127.0.0.1:9"})).unwrap());
    let store = Arc::new(MemoryStore::new());
    let state = replica_state(&config, store.clone(), Arc::new(MemoryLog::new()));
    let base = serve(router(state, Duration::from_secs(10))).await;
    let content = "customer:cus_77 prefers_communication_channel=email";
    let promoted = |operation: &str, until: &str, text: &str| {
        json!({"record": {"operation": operation, "retention_expires_at": until, "readers": ["usr_771"],
            "memory_ref": {"artifact_id": format!("key:{text}"), "sha256": contextos_contract::canonical::sha256_text(text)}}})
    };
    for (id, record) in [
        ("mem_ok", promoted("promote", "2099-01-01T00:00:00Z", content)),
        ("mem_deleted", promoted("delete", "2099-01-01T00:00:00Z", content)),
        ("mem_expired", promoted("promote", "2000-01-01T00:00:00Z", content)),
        ("mem_proposed", promoted("propose", "2099-01-01T00:00:00Z", content)),
        ("mem_unreadable", {
            let mut r = promoted("promote", "2099-01-01T00:00:00Z", content);
            r["record"]["readers"] = json!(["usr_someone_else"]);
            r
        }),
    ] {
        store
            .create(&DocKey::new(TENANT, DocKind::MemoryRecord, id), &record)
            .await
            .unwrap();
    }
    let plain = reqwest::Client::new();
    let admit = |run: &'static str, memory_ref: &'static str, text: &'static str| {
        let (plain, url) = (plain.clone(), format!("{base}/v1/runs"));
        async move {
            let mut body = run_body(run, 1200);
            body["deps"]["promoted_memory"] =
                json!([{"memory_ref": memory_ref, "content": text, "freshness": "current", "source_refs": []}]);
            plain
                .post(url)
                .bearer_auth("acme-key")
                .json(&body)
                .send()
                .await
                .unwrap()
        }
    };
    let ok = admit("run_mem_ok", "mem_ok", content).await;
    assert_eq!(ok.status(), 201, "{}", ok.text().await.unwrap());
    for (run, memory_ref, text) in [
        (
            "run_mem_changed",
            "mem_ok",
            "customer:cus_77 prefers_communication_channel=sms",
        ),
        ("run_mem_deleted", "mem_deleted", content),
        ("run_mem_expired", "mem_expired", content),
        ("run_mem_proposed", "mem_proposed", content),
        ("run_mem_unknown", "mem_nope", content),
        ("run_mem_unreadable", "mem_unreadable", content),
    ] {
        let refused = admit(run, memory_ref, text).await;
        assert_eq!(refused.status(), 422, "{run}");
        assert_eq!(
            refused.json::<Value>().await.unwrap()["error"]["code"],
            "memory_unverified",
            "{run}"
        );
    }

    // Two promoted values for one memory key cannot be recalled together.
    let other = "customer:cus_77 prefers_communication_channel=sms";
    for (id, text) in [("mem_pref_email", content), ("mem_pref_sms", other)] {
        let mut record = promoted("promote", "2099-01-01T00:00:00Z", text);
        record["record"]["memory_ref"]["artifact_id"] = json!("pref:cus_77:channel");
        store
            .create(&DocKey::new(TENANT, DocKind::MemoryRecord, id), &record)
            .await
            .unwrap();
    }
    let mut body = run_body("run_mem_conflict", 1200);
    body["deps"]["promoted_memory"] = json!([
        {"memory_ref": "mem_pref_email", "content": content, "freshness": "current", "source_refs": []},
        {"memory_ref": "mem_pref_sms", "content": other, "freshness": "current", "source_refs": []}]);
    let conflict = plain
        .post(format!("{base}/v1/runs"))
        .bearer_auth("acme-key")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(conflict.status(), 422);
    assert_eq!(
        conflict.json::<Value>().await.unwrap()["error"]["code"],
        "memory_conflict"
    );

    // A memory whose key a newer promotion holds is superseded and cannot be recalled.
    store
        .create(
            &DocKey::new(
                TENANT,
                DocKind::MemoryKey,
                contextos_contract::canonical::sha256_text(&format!("\u{0}\u{0}key:{content}")),
            ),
            &json!({"record_id": "mem_newer"}),
        )
        .await
        .unwrap();
    let superseded = admit("run_mem_superseded", "mem_ok", content).await;
    assert_eq!(superseded.status(), 422);
    assert_eq!(
        superseded.json::<Value>().await.unwrap()["error"]["code"],
        "memory_superseded"
    );
}

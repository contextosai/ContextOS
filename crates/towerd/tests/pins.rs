//! After a restart, the chain Tower reads again must pass through the entry it pinned:
//! a rewritten or truncated history marks the source broken; the same history, grown,
//! passes and moves the pin forward.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use contextos_audit::AuditSigner;
use contextos_store::{MemoryLog, MemoryStore};
use contextosd::auth::hash_api_key;
use serde_json::json;
use tokio::sync::RwLock;
use towerd::collector;
use towerd::fleet::Fleet;
use towerd::pins::{Pins, StorePins};
use towerd::source::Source;

const TENANT: &str = "tenant_acme_prod";
const AT: &str = "2026-10-21T10:00:00.000000Z";

/// A runtime whose chain records one admission per run id, signed with the same key as
/// every other runtime here: the same source, with a given history.
async fn runtime(runs: &[&str]) -> String {
    let config = contextosd::Config::parse(&format!(
        r#"
        [server]
        listen = "127.0.0.1:0"
        mode = "development"
        [store]
        kind = "memory"
        [audit]
        signing_seed_env = "UNUSED"
        key_id = "rt-audit"
        [support]
        implementation_id = "contextos-rs"
        implementation_version = "0.1.0"
        profiles = ["contextos.core"]
        controls = ["identity.authenticated", "authority.scoped", "policy.fail_visible", "context.integrity", "audit.correlated"]
        [[api_keys]]
        key_sha256 = "{reader}"
        tenant_id = "{TENANT}"
        principal_id = "svc_tower"
        scopes = ["audit:read"]
        "#,
        reader = hash_api_key("reader-key"),
    ))
    .unwrap();
    let pack = std::fs::read_to_string(format!(
        "{}/../../examples/support-refund/pack.json",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let (pack_ref, loaded) = contextosd::load_pack(&pack).unwrap();
    let state = contextosd::build_state(
        &config,
        Arc::new(MemoryStore::new()),
        MemoryLog::new(),
        AuditSigner::from_seed("rt-audit", [3; 32]),
        HashMap::from([(pack_ref, loaded)]),
        None,
    )
    .unwrap();
    for run in runs {
        let payload = json!({"run_id": run, "agent_id": "agt_support", "pack_ref": "ctxpack.support@5.2.0"});
        state.audit.append(TENANT, "run_admitted", payload, AT).await.unwrap();
    }
    let app = contextosd::router(state, Duration::from_secs(5));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

fn source(url: &str) -> Source {
    let config = towerd::Config::parse(&format!(
        r#"
        [server]
        listen = "127.0.0.1:0"
        development = true
        [journal]
        signing_seed_env = "UNUSED"
        key_id = "tower-journal"
        [[sources]]
        id = "eu-support"
        url = "{url}"
        token_env = "UNUSED"
        "#
    ))
    .unwrap();
    Source::with_tokens(config.sources[0].clone(), "reader-key".into(), None)
}

/// A fresh Tower process reading `url` with the pins it kept: whether the source is
/// still readable, and why not.
async fn restart(url: &str, pins: &StorePins<MemoryStore>) -> (bool, Option<String>) {
    let fleet = RwLock::new(Fleet::new(50, 24));
    let mut pin = pins.get("eu-support").await.unwrap();
    let (mut keys, mut anchor, mut refreshed) = (None, None, None);
    let readable = collector::sync_pinned(
        &source(url),
        &fleet,
        &mut keys,
        &mut anchor,
        &mut refreshed,
        &mut pin,
        Some(pins),
    )
    .await;
    let reason = fleet.read().await.sources["eu-support"]
        .broken
        .as_ref()
        .and_then(|b| b["reason"].as_str().map(str::to_owned));
    (readable, reason)
}

#[tokio::test]
async fn a_restart_cannot_hide_a_rewritten_or_truncated_history() {
    let pins = StorePins::new(Arc::new(MemoryStore::new()));
    let original = runtime(&["r1", "r2", "r3"]).await;

    // First contact pins the last verified entry.
    assert_eq!(restart(&original, &pins).await, (true, None));
    let pinned = pins.get("eu-support").await.unwrap().expect("pinned");
    assert!(pinned.sequence >= 3, "{pinned:?}");

    // The same history read again passes the pin.
    assert_eq!(restart(&original, &pins).await, (true, None));

    // Same key, same length, different entries: rewritten.
    let rewritten = runtime(&["r1", "x2", "x3"]).await;
    assert_eq!(
        restart(&rewritten, &pins).await,
        (false, Some("history_rewritten".into()))
    );

    // The chain now ends before the pinned entry: truncated.
    let truncated = runtime(&["r1"]).await;
    assert_eq!(
        restart(&truncated, &pins).await,
        (false, Some("history_truncated".into()))
    );
    assert_eq!(
        pins.get("eu-support").await.unwrap(),
        Some(pinned.clone()),
        "a broken read moves no pin"
    );

    // The same history, grown: passes, and the pin moves forward.
    let grown = runtime(&["r1", "r2", "r3", "r4"]).await;
    assert_eq!(restart(&grown, &pins).await, (true, None));
    let moved = pins.get("eu-support").await.unwrap().unwrap();
    assert_eq!(moved.sequence, pinned.sequence + 1);
}

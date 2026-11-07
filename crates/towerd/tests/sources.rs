//! Runtime sources managed from the console, against a real `contextosd` with two
//! tenants: probing, adding, pausing, re-verifying, re-keying and removing; every
//! replica converging from the store; and keys never leaving their references.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use contextos_audit::AuditSigner;
use contextos_store::{AppendLog, DocumentStore, MemoryLog, MemoryStore};
use contextosd::auth::hash_api_key;
use serde_json::{Value, json};
use towerd::source::Source;
use towerd::{Config, Tower, api, sources_admin};

const AT: &str = "2026-10-21T10:00:00.000000Z";
/// Every raw key in this test; none may appear in any response or journal entry.
const SECRETS: [&str; 5] = [
    "reader-key",
    "beta-reader",
    "beta-reader-two",
    "beta-control",
    "acme-control",
];

type Runtime = Arc<contextosd::AppState<MemoryStore, MemoryLog>>;

async fn runtime() -> (String, Runtime) {
    let key = |raw: &str, tenant: &str, scopes: &str| {
        format!(
            "[[api_keys]]\nkey_sha256 = \"{}\"\ntenant_id = \"{tenant}\"\nprincipal_id = \"p_{}\"\nscopes = {scopes}\n",
            hash_api_key(raw),
            raw.replace('-', "_")
        )
    };
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
        controls = ["identity.authenticated"]
        {}{}{}{}{}
        "#,
        key("reader-key", "tenant_acme_prod", r#"["audit:read"]"#),
        key("acme-control", "tenant_acme_prod", r#"["control"]"#),
        key("beta-reader", "tenant_beta", r#"["audit:read"]"#),
        key("beta-reader-two", "tenant_beta", r#"["audit:read"]"#),
        key("beta-control", "tenant_beta", r#"["control"]"#),
    ))
    .unwrap();
    let state = contextosd::build_state(
        &config,
        Arc::new(MemoryStore::new()),
        MemoryLog::new(),
        AuditSigner::from_seed("rt-audit", [3; 32]),
        HashMap::new(),
        None,
    )
    .unwrap();
    for (tenant, run, agent) in [
        ("tenant_acme_prod", "r1", "agt_support"),
        ("tenant_beta", "b1", "agt_beta"),
        ("tenant_beta", "b2", "agt_beta"),
    ] {
        admit(&state, tenant, run, agent).await;
    }
    let app = contextosd::router(state.clone(), Duration::from_secs(5));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), state)
}

async fn admit<S: DocumentStore, L: AppendLog>(
    state: &contextosd::AppState<S, L>,
    tenant: &str,
    run: &str,
    agent: &str,
) {
    let payload = json!({"run_id": run, "trace_id": format!("trace_{run}"), "agent_id": agent,
        "pack_ref": "ctxpack.support@5.2.0", "profiles": ["contextos.core"], "required_controls": [],
        "release_refs": [], "surfaced_capabilities": [], "admitted_by": "svc_orchestrator"});
    state.audit.append(tenant, "run_admitted", payload, AT).await.unwrap();
}

async fn tower(runtime: &str) -> (String, Arc<Tower<MemoryStore, MemoryLog>>) {
    let config = Config::parse(&format!(
        r#"
        [server]
        listen = "127.0.0.1:0"
        development = true
        [journal]
        signing_seed_env = "UNUSED"
        key_id = "tower-journal"
        [collector]
        poll_ms = 50
        [[sources]]
        id = "eu-support"
        url = "{runtime}"
        token_env = "UNUSED"
        [[api_keys]]
        key_sha256 = "{viewer}"
        principal_id = "ciso"
        roles = ["viewer"]
        [[api_keys]]
        key_sha256 = "{operator}"
        principal_id = "oncall"
        roles = ["operator"]
        [[api_keys]]
        key_sha256 = "{admin}"
        principal_id = "platform-admin"
        roles = ["admin"]
        "#,
        viewer = hash_api_key("viewer"),
        operator = hash_api_key("operator"),
        admin = hash_api_key("admin"),
    ))
    .unwrap();
    let source = Source::with_tokens(config.sources[0].clone(), "reader-key".into(), None);
    let tower = Arc::new(
        Tower::assemble(
            config,
            vec![Arc::new(source)],
            Arc::new(MemoryStore::new()),
            MemoryLog::new(),
            AuditSigner::from_seed("tower-journal", [4; 32]),
            None,
        )
        .unwrap(),
    );
    sources_admin::reconcile(&tower).await.unwrap();
    let app = api::router(tower.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), tower)
}

/// Every response body seen, to check that no key ever leaves Tower.
#[derive(Default)]
struct Seen(std::sync::Mutex<Vec<String>>);

impl Seen {
    async fn call(&self, base: &str, method: &str, path: &str, key: &str, body: Option<Value>) -> (u16, Value) {
        let http = reqwest::Client::new();
        let url = format!("{base}{path}");
        let mut request = if method == "GET" { http.get(url) } else { http.post(url) }.bearer_auth(key);
        if let Some(b) = body {
            request = request.json(&b);
        }
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        let text = response.text().await.unwrap();
        self.0.lock().unwrap().push(text.clone());
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    fn assert_no_secrets(&self) {
        for text in self.0.lock().unwrap().iter() {
            for secret in SECRETS {
                assert!(!text.contains(&format!("\"{secret}\"")), "{secret} leaked in {text}");
            }
        }
    }
}

fn key_file(name: &str, value: &str) -> String {
    let dir = std::env::temp_dir().join(format!("towerd-sources-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, format!("{value}\n")).unwrap();
    path.to_str().unwrap().to_owned()
}

async fn row(seen: &Seen, base: &str, id: &str) -> Value {
    let (status, health) = seen.call(base, "GET", "/api/sources/health", "admin", None).await;
    assert_eq!(status, 200);
    health["sources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == id)
        .cloned()
        .unwrap_or(Value::Null)
}

async fn until(seen: &Seen, base: &str, id: &str, what: impl Fn(&Value) -> bool) -> Value {
    for _ in 0..100 {
        let r = row(seen, base, id).await;
        if what(&r) {
            return r;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!(
        "source {id} never reached the expected state: {}",
        row(seen, base, id).await
    );
}

/// Runs folded for the beta tenant's agents: an entry folded twice would count twice.
fn runs(fleet: &towerd::fleet::Fleet) -> u64 {
    fleet
        .agents
        .values()
        .filter(|a| a.tenants.contains("tenant_beta"))
        .map(|a| a.runs)
        .sum()
}

#[tokio::test]
async fn console_sources_are_probed_added_paused_retried_rekeyed_and_removed() {
    let (rt_url, rt) = runtime().await;
    let (base, tower) = tower(&rt_url).await;
    let seen = Seen::default();
    let read = key_file("beta-read", "beta-reader");
    let beta = json!({"id": "beta", "url": rt_url, "token_file": read, "control_token_file": key_file("beta-control", "beta-control"),
        "business_unit": "Beta"});

    // Only admins manage sources; the probe changes nothing.
    let (status, _) = seen
        .call(&base, "POST", "/api/sources/probe", "operator", Some(beta.clone()))
        .await;
    assert_eq!(status, 403);
    let (status, probe) = seen
        .call(&base, "POST", "/api/sources/probe", "admin", Some(beta.clone()))
        .await;
    assert_eq!(status, 200, "{probe}");
    assert_eq!(probe["tenant_id"], "tenant_beta");
    assert_eq!(probe["can_revoke"], true);
    assert_eq!(probe["warnings"], json!([]));
    assert!(row(&seen, &base, "beta").await.is_null());

    // A tenant already governed, an unreadable key, a control key of another tenant.
    let dup = json!({"id": "dup", "url": rt_url, "token_file": key_file("acme-read", "reader-key")});
    let (status, refused) = seen.call(&base, "POST", "/api/sources/probe", "admin", Some(dup)).await;
    assert_eq!(
        (status, refused["error"]["code"].as_str()),
        (409, Some("tenant_governed"))
    );
    let unset = json!({"id": "nokey", "url": rt_url, "token_env": "TOWER_TEST_KEY_NOT_SET_ANYWHERE"});
    let (status, refused) = seen
        .call(&base, "POST", "/api/sources/probe", "admin", Some(unset))
        .await;
    assert_eq!(
        (status, refused["error"]["code"].as_str()),
        (422, Some("source_key_unavailable"))
    );
    let mixed = json!({"id": "mixed", "url": rt_url, "token_file": read, "control_token_file": key_file("acme-control", "acme-control")});
    let (status, refused) = seen
        .call(&base, "POST", "/api/sources/probe", "admin", Some(mixed))
        .await;
    assert_eq!(
        (status, refused["error"]["code"].as_str()),
        (422, Some("source_tenant_mismatch"))
    );
    let both = json!({"id": "both", "url": rt_url, "token_file": read, "token_env": "X"});
    assert_eq!(
        seen.call(&base, "POST", "/api/sources/probe", "admin", Some(both))
            .await
            .0,
        422
    );

    // Added with a reason, it collects.
    let (status, _) = seen
        .call(
            &base,
            "POST",
            "/api/sources",
            "admin",
            Some(json!({"source": beta, "reason": " "})),
        )
        .await;
    assert_eq!(status, 422);
    let (status, added) = seen
        .call(
            &base,
            "POST",
            "/api/sources",
            "admin",
            Some(json!({"source": beta, "reason": "Beta goes live"})),
        )
        .await;
    assert_eq!(status, 201, "{added}");
    assert_eq!(added["source"]["origin"], "console");
    let (status, _) = seen
        .call(
            &base,
            "POST",
            "/api/sources",
            "admin",
            Some(json!({"source": beta, "reason": "again"})),
        )
        .await;
    assert_eq!(status, 409);
    let r = until(&seen, &base, "beta", |r| {
        r["verified_to"] == 2 && r["state"] == "current"
    })
    .await;
    assert_eq!(
        (r["tenant_id"].as_str(), r["can_revoke"].as_bool()),
        (Some("tenant_beta"), Some(true))
    );
    assert_eq!(r["added_by"], "platform-admin");
    assert_eq!(r["keys"]["token_file"], read);
    let (_, as_viewer) = seen.call(&base, "GET", "/api/sources/health", "viewer", None).await;
    assert!(
        as_viewer["sources"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r.get("keys").is_none())
    );

    // Paused, it stops reading; resumed, it catches up.
    let reason = json!({"reason": "maintenance window"});
    let (status, paused) = seen
        .call(&base, "POST", "/api/sources/beta/pause", "admin", Some(reason.clone()))
        .await;
    assert_eq!((status, paused["source"]["state"].as_str()), (200, Some("paused")));
    assert_eq!(
        seen.call(&base, "POST", "/api/sources/beta/pause", "admin", Some(reason.clone()))
            .await
            .0,
        409
    );
    admit(&rt, "tenant_beta", "b3", "agt_beta").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(row(&seen, &base, "beta").await["verified_to"], 2);
    seen.call(&base, "POST", "/api/sources/beta/resume", "admin", Some(reason.clone()))
        .await;
    until(&seen, &base, "beta", |r| r["verified_to"] == 3).await;
    assert_eq!(runs(&*tower.fleet.read().await), 3);

    // A broken chain stays stopped until an admin retries; the retry continues from the
    // last verified entry, folding nothing twice.
    seen.call(&base, "POST", "/api/sources/beta/pause", "admin", Some(reason.clone()))
        .await;
    tower.fleet.write().await.source("beta").broken = Some(json!({"sequence": 3, "reason": "injected"}));
    seen.call(&base, "POST", "/api/sources/beta/resume", "admin", Some(reason.clone()))
        .await;
    let r = until(&seen, &base, "beta", |r| r["state"] == "broken").await;
    assert_eq!(r["collecting"], false);
    admit(&rt, "tenant_beta", "b4", "agt_beta").await;
    let (status, _) = seen
        .call(
            &base,
            "POST",
            "/api/sources/beta/retry",
            "admin",
            Some(json!({"reason": ""})),
        )
        .await;
    assert_eq!(status, 422, "a retry needs a reason");
    let (status, _) = seen
        .call(
            &base,
            "POST",
            "/api/sources/beta/retry",
            "admin",
            Some(json!({"reason": "keys checked"})),
        )
        .await;
    assert_eq!(status, 200);
    until(&seen, &base, "beta", |r| {
        r["verified_to"] == 4 && r["state"] == "current"
    })
    .await;
    assert_eq!(runs(&*tower.fleet.read().await), 4, "no entry folded twice");

    // A rotated key file is read again on reload.
    std::fs::write(&read, "beta-reader-two").unwrap();
    let (status, _) = seen
        .call(
            &base,
            "POST",
            "/api/sources/beta/reload",
            "admin",
            Some(json!({"reason": "rotated"})),
        )
        .await;
    assert_eq!(status, 200);
    admit(&rt, "tenant_beta", "b5", "agt_beta").await;
    until(&seen, &base, "beta", |r| {
        r["verified_to"] == 5 && r["last_error"].is_null()
    })
    .await;

    // Configured sources are removed in towerd.toml; console ones from the console.
    let (status, refused) = seen
        .call(
            &base,
            "POST",
            "/api/sources/eu-support/remove",
            "admin",
            Some(reason.clone()),
        )
        .await;
    assert_eq!(
        (status, refused["error"]["code"].as_str()),
        (409, Some("source_in_config"))
    );
    assert_eq!(
        seen.call(
            &base,
            "POST",
            "/api/sources/beta/explode",
            "admin",
            Some(reason.clone())
        )
        .await
        .0,
        404
    );
    assert_eq!(
        seen.call(&base, "POST", "/api/sources/nope/pause", "admin", Some(reason.clone()))
            .await
            .0,
        404
    );
    let (status, _) = seen
        .call(&base, "POST", "/api/sources/beta/remove", "admin", Some(reason))
        .await;
    assert_eq!(status, 200);
    assert!(row(&seen, &base, "beta").await.is_null());
    assert!(tower.sources.get("beta").is_none());

    // Every change is journalled with who and why; no key appears anywhere.
    let (_, journal) = seen.call(&base, "GET", "/api/journal?limit=100", "viewer", None).await;
    let kinds: Vec<&str> = journal["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["kind"].as_str())
        .collect();
    for kind in [
        "source_added",
        "source_paused",
        "source_resumed",
        "source_retried",
        "source_keys_reloaded",
        "source_removed",
    ] {
        assert!(kinds.contains(&kind), "{kind} not journalled: {kinds:?}");
    }
    let added = journal["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["kind"] == "source_added")
        .unwrap();
    assert_eq!(added["payload"]["by"], "platform-admin");
    assert_eq!(added["payload"]["tenant_id"], "tenant_beta");
    seen.assert_no_secrets();
}

#[tokio::test]
async fn every_replica_converges_on_the_stored_sources() {
    let (rt_url, _rt) = runtime().await;
    let (base, tower) = tower(&rt_url).await;
    let seen = Seen::default();
    // Another replica wrote these: a source this replica can run, one whose key it
    // cannot read, and a pause of a configured source.
    let config = |id: &str, file: String| json!({"id": id, "url": rt_url, "token_file": file});
    let record = |id: &str, file: String| json!({"config": config(id, file), "tenant_id": "tenant_beta", "added_by": "other", "added_at": AT, "reason": "x"});
    let items = json!({
        "console": {"beta": record("beta", key_file("conv-read", "beta-reader")),
                    "ghost": record("ghost", "/nonexistent/towerd/key".into())},
        "controls": {"eu-support": {"paused": true, "by": "other", "reason": "x"}},
    });
    tower
        .records
        .change(sources_admin::COLLECTION, "test_seed", json!({}), AT, |stored| {
            *stored = items.clone();
            Ok(())
        })
        .await
        .unwrap();
    sources_admin::reconcile(&tower).await.unwrap();

    until(&seen, &base, "beta", |r| {
        r["verified_to"] == 2 && r["origin"] == "console"
    })
    .await;
    let ghost = row(&seen, &base, "ghost").await;
    assert_eq!(ghost["state"], "unavailable");
    assert!(
        ghost["last_error"]
            .as_str()
            .unwrap()
            .contains("/nonexistent/towerd/key")
    );
    assert_eq!(row(&seen, &base, "eu-support").await["state"], "paused");
    assert!(tower.sources.active().iter().all(|s| s.id() != "eu-support"));

    // Removed elsewhere: gone here at the next reconciliation.
    tower
        .records
        .change(sources_admin::COLLECTION, "test_seed", json!({}), AT, |stored| {
            stored["console"].as_object_mut().unwrap().remove("beta");
            Ok(())
        })
        .await
        .unwrap();
    sources_admin::reconcile(&tower).await.unwrap();
    assert!(tower.sources.get("beta").is_none());
    seen.assert_no_secrets();
}

#[test]
fn source_definitions_name_exactly_one_reference_per_key() {
    let parse = |source: &str| {
        Config::parse(&format!(
            "[server]\nlisten = \"127.0.0.1:0\"\n[journal]\nsigning_seed_env = \"S\"\nkey_id = \"k\"\n[[sources]]\nid = \"a\"\n{source}"
        ))
    };
    assert!(parse("url = \"https://rt.example\"\ntoken_file = \"/run/secrets/a\"").is_ok());
    assert!(
        parse("url = \"https://rt.example\"\ntoken_env = \"A_KEY\"\ncontrol_token_file = \"/run/secrets/c\"").is_ok()
    );
    for bad in [
        "url = \"https://rt.example\"",
        "url = \"https://rt.example\"\ntoken_env = \"A\"\ntoken_file = \"/k\"",
        "url = \"https://rt.example\"\ntoken_file = \"relative/key\"",
        "url = \"https://rt.example\"\ntoken_file = \"/run/../etc/key\"",
        "url = \"https://rt.example\"\ntoken_env = \"lower\"",
        "url = \"http://rt.example\"\ntoken_env = \"A\"",
        "url = \"https://user:pw@rt.example\"\ntoken_env = \"A\"",
        "url = \"https://rt.example\"\ntoken_env = \"A\"\ncontrol_token_env = \"C\"\ncontrol_token_file = \"/c\"",
    ] {
        assert!(parse(bad).is_err(), "accepted: {bad}");
    }
}

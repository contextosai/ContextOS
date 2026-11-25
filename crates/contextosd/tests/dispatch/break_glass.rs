//! Break-glass: during an incident a separate credential lifts a change window for a
//! named capability, for a short time; every call it lets through is audited.

use contextos_gateway::break_glass::BreakGlassPolicy;
use contextos_gateway::change_windows::ChangeWindow;
use contextosd::auth::hash_api_key;
use contextosd::config::{ApiKey, Config};
use serde_json::{Value, json};

use crate::harness::*;

const REFUND: &str = "adp_payments.issue_refund";

async fn post(w: &World, path: &str, key: &str, body: Value) -> (u16, Value) {
    let response = reqwest::Client::new()
        .post(format!("{}{path}", w.base))
        .bearer_auth(key)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    (status, response.json().await.unwrap_or(Value::Null))
}

async fn kinds(w: &World, kind: &str) -> Vec<Value> {
    let entries: Value = reqwest::Client::new()
        .get(format!("{}/v1/audit/entries?from=1&limit=1000", w.base))
        .bearer_auth("acme-key")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    entries["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["kind"] == kind)
        .map(|e| e["payload"].clone())
        .collect()
}

fn grant(ttl: u64) -> Value {
    json!({"capabilities": [REFUND], "lifts": ["change_windows"], "ttl_seconds": ttl,
        "justification": "INC-311: refunds for the failed payout run must go out during the freeze",
        "incident_ref": "INC-311"})
}

async fn frozen_world(break_glass: bool) -> World {
    world_with(&ALL_CONTROLS, 1, |c| {
        c.guards.change_windows = vec![
            serde_json::from_value::<ChangeWindow>(json!({"name": "freeze",
            "capabilities": [REFUND], "from": "2000-01-01T00:00:00Z", "until": "2999-01-01T00:00:00Z"}))
            .unwrap(),
        ];
        if break_glass {
            c.guards.break_glass =
                Some(serde_json::from_value::<BreakGlassPolicy>(json!({"max_ttl_seconds": 900})).unwrap());
        }
        c.api_keys.push(ApiKey {
            key_sha256: hash_api_key("bg-key"),
            tenant_id: TENANT.into(),
            principal_id: "oncall_lead".into(),
            scopes: vec!["break_glass".into(), "control".into()],
            agent_ids: None,
        });
    })
    .await
}

#[tokio::test]
async fn a_grant_lifts_a_freeze_for_its_capability_until_closed() {
    let w = frozen_world(true).await;
    assert_eq!(admit(&w, &run_body("run_bg", 1200)).await.status(), 201);
    let refused = dispatch(&w, "run_bg", &refund("run_bg", "r1", "ord_881", "cus_77", 100)).await;
    assert!(
        refused["report"]["reason_codes"]
            .to_string()
            .contains("change_window_closed"),
        "{refused}"
    );

    // Only the break-glass credential opens a grant, named, justified and short.
    assert_eq!(post(&w, "/v1/break-glass", "ops-key", grant(600)).await.0, 403);
    assert_eq!(
        post(&w, "/v1/break-glass", "bg-key", grant(3600)).await.0,
        422,
        "beyond max_ttl_seconds"
    );
    let mut wildcard = grant(600);
    wildcard["capabilities"] = json!(["*"]);
    assert_eq!(post(&w, "/v1/break-glass", "bg-key", wildcard).await.0, 422);
    let mut lifts_more = grant(600);
    lifts_more["lifts"] = json!(["approvals"]);
    assert_eq!(
        post(&w, "/v1/break-glass", "bg-key", lifts_more).await.0,
        422,
        "approvals are never lifted"
    );
    let (status, opened) = post(&w, "/v1/break-glass", "bg-key", grant(600)).await;
    assert_eq!(status, 201, "{opened}");
    let id = opened["grant_id"].as_str().unwrap().to_owned();

    let through = dispatch(&w, "run_bg", &refund("run_bg", "r2", "ord_882", "cus_77", 100)).await;
    assert_eq!(through["report"]["status"], "completed", "{through}");
    let used = kinds(&w, "break_glass_used").await;
    assert_eq!(used.len(), 1);
    assert_eq!(used[0]["grant_id"], id.as_str());
    assert_eq!(used[0]["lifted"], "change_windows");
    assert_eq!(used[0]["window"], "freeze");
    assert_eq!(kinds(&w, "break_glass_opened").await[0]["incident_ref"], "INC-311");

    let (status, closed) = post(&w, &format!("/v1/break-glass/{id}/close"), "bg-key", json!({})).await;
    assert_eq!(status, 200, "{closed}");
    let again = dispatch(&w, "run_bg", &refund("run_bg", "r3", "ord_883", "cus_77", 100)).await;
    assert!(
        again["report"]["reason_codes"]
            .to_string()
            .contains("change_window_closed"),
        "{again}"
    );
    assert_eq!(kinds(&w, "break_glass_closed").await.len(), 1);
}

#[tokio::test]
async fn break_glass_is_off_unless_configured_and_never_held_by_an_agent_credential() {
    let w = frozen_world(false).await;
    assert_eq!(post(&w, "/v1/break-glass", "bg-key", grant(600)).await.0, 501);
    let (config, _) = world_setup(&ALL_CONTROLS).await;
    let both = format!(
        "{}\n[[api_keys]]\nkey_sha256 = \"{}\"\ntenant_id = \"{TENANT}\"\nprincipal_id = \"svc_agent\"\nscopes = [\"dispatch\", \"break_glass\"]",
        config.source,
        hash_api_key("both-key")
    );
    let error = Config::parse(&both).err().unwrap().to_string();
    assert!(error.contains("break-glass"), "{error}");
    assert!(
        Config::parse(&format!(
            "{}\n[guards.break_glass]\nmax_ttl_seconds = 7200",
            config.source
        ))
        .is_err()
    );
}

#[tokio::test]
async fn a_grant_lifts_an_open_breaker_but_never_a_revocation() {
    use contextos_gateway::circuit_breakers::{BreakerCount, BreakerRule, BreakerScope, BreakerTrip};
    let rule = |trip| BreakerRule {
        id: "refund_rate".into(),
        scope: BreakerScope::Agent,
        count: BreakerCount::Effects,
        capabilities: vec![REFUND.into()],
        threshold: 1,
        window_seconds: 3600,
        trip,
    };
    for (trip, lifted) in [(BreakerTrip::Refuse, true), (BreakerTrip::Revoke, false)] {
        let w = world_with(&ALL_CONTROLS, 1, |c| {
            c.guards.circuit_breakers = vec![rule(trip)];
            c.guards.break_glass = Some(serde_json::from_value::<BreakGlassPolicy>(json!({})).unwrap());
            c.api_keys.push(ApiKey {
                key_sha256: hash_api_key("bg-key"),
                tenant_id: TENANT.into(),
                principal_id: "oncall_lead".into(),
                scopes: vec!["break_glass".into()],
                agent_ids: None,
            });
        })
        .await;
        assert_eq!(admit(&w, &run_body("run_a", 1200)).await.status(), 201);
        let first = dispatch(&w, "run_a", &refund("run_a", "r1", "ord_881", "cus_77", 100)).await;
        assert_eq!(first["report"]["status"], "completed", "{first}");
        let stopped = dispatch(&w, "run_a", &refund("run_a", "r2", "ord_882", "cus_77", 100)).await;
        assert_ne!(stopped["report"]["status"], "completed", "{stopped}");
        let mut g = grant(600);
        g["lifts"] = json!(["circuit_breakers"]);
        assert_eq!(post(&w, "/v1/break-glass", "bg-key", g).await.0, 201);
        let after = dispatch(&w, "run_a", &refund("run_a", "r3", "ord_883", "cus_77", 100)).await;
        if lifted {
            assert_eq!(after["report"]["status"], "completed", "{after}");
            assert_eq!(kinds(&w, "break_glass_used").await[0]["breaker"], "refund_rate");
        } else {
            // The breaker revoked the agent: a revocation needs a restore, not break-glass.
            assert_ne!(after["report"]["status"], "completed", "{after}");
            assert_eq!(kinds(&w, "break_glass_used").await, Vec::<Value>::new());
        }
    }
}

//! A run's declared user must be the user its caller's delegated token acts for, as
//! Keycloak's token exchange delegation issues them (`sub` the user, `act` the agent).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use contextos_store::DocumentStore as _;
use contextosd::oidc::{DelegationConfig, OidcConfig};
use contextosd::user_binding::{self, UserBinding};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Value, json};

use crate::harness::*;

struct Realm {
    pkcs8: Vec<u8>,
    issuer: String,
    jwks_url: String,
}

impl Realm {
    async fn start() -> Self {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
        let public = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
            .unwrap()
            .public_key()
            .as_ref()
            .to_vec();
        let jwks = json!({"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "k1", "alg": "EdDSA", "use": "sig",
            "x": URL_SAFE_NO_PAD.encode(public)}]});
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = axum::Router::new().route(
            "/realms/acme/protocol/openid-connect/certs",
            axum::routing::get(move || {
                let jwks = jwks.clone();
                async move { axum::Json(jwks) }
            }),
        );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            pkcs8: pkcs8.as_ref().to_vec(),
            issuer: format!("{base}/realms/acme"),
            jwks_url: format!("{base}/realms/acme/protocol/openid-connect/certs"),
        }
    }

    /// The issuer as a Keycloak realm with organizations and delegation is configured.
    fn config(&self) -> OidcConfig {
        let mut config: OidcConfig = toml::from_str(&format!(
            r#"
            issuer = "{}"
            audience = "contextosd"
            jwks_url = "{}"
            tenants = ["{TENANT}"]
            tenant_claim = "organization"
            agent_claim = "azp"
            algorithms = ["EdDSA"]
            [tenant_map]
            acme = "{TENANT}"
            [agents]
            support-agent = ["agt_support"]
            "#,
            self.issuer, self.jwks_url
        ))
        .unwrap();
        config.delegation = Some(DelegationConfig {
            actor_claim: "act".into(),
            actor_agent_claim: Some("client_id".into()),
            user_roles_claim: Some("realm_access.roles".into()),
            max_chain: 4,
        });
        config
    }

    /// A token the agent obtained by exchanging `user`'s token, with `roles`.
    fn delegated(&self, user: &str, roles: &[&str]) -> String {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        self.sign(
            &json!({"iss": self.issuer, "aud": "contextosd", "sub": user, "azp": "support-agent",
            "organization": {"acme": {"id": "7d1c"}}, "realm_access": {"roles": roles},
            "scope": "openid admit dispatch", "act": {"sub": "sa-support-agent", "client_id": "support-agent"},
            "iat": now, "exp": now + 300}),
        )
    }

    /// A token passed through several actors: `actors[0]` acts now, each later one
    /// before it (RFC 8693 nested `act`).
    fn chained(&self, user: &str, roles: &[&str], actors: &[&str]) -> String {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut act = Value::Null;
        for (i, actor) in actors.iter().enumerate().rev() {
            let mut hop = json!({"sub": actor});
            if i == 0 {
                hop["client_id"] = json!("support-agent");
            }
            if !act.is_null() {
                hop["act"] = act;
            }
            act = hop;
        }
        self.sign(
            &json!({"iss": self.issuer, "aud": "contextosd", "sub": user, "azp": "support-agent",
            "organization": {"acme": {"id": "7d1c"}}, "realm_access": {"roles": roles},
            "scope": "openid admit dispatch", "act": act, "iat": now, "exp": now + 300}),
        )
    }

    /// The agent's own client-credentials token: no user.
    fn service(&self) -> String {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        self.sign(
            &json!({"iss": self.issuer, "aud": "contextosd", "sub": "sa-support-agent", "azp": "support-agent",
            "organization": ["acme"], "scope": "admit dispatch", "iat": now, "exp": now + 300}),
        )
    }

    fn sign(&self, claims: &Value) -> String {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("k1".into());
        jsonwebtoken::encode(&header, claims, &EncodingKey::from_ed_der(&self.pkcs8)).unwrap()
    }
}

async fn world_for(realm: &Realm) -> World {
    let w = world_with(&ALL_CONTROLS, 1, |c| {
        c.oidc.push(realm.config());
        c.guards.user_binding = Some(UserBinding::Required);
        for key in &mut c.api_keys {
            key.scopes.retain(|s| s != "admit");
        }
    })
    .await;
    for _ in 0..100 {
        if reqwest::get(format!("{}/readyz", w.base)).await.unwrap().status() == 200 {
            return w;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("realm keys never loaded");
}

/// The user and role the test run declares.
fn declared() -> (String, String) {
    let user = &run_body("run_x", 1200)["run_context"]["user"];
    (
        user["user_id"].as_str().unwrap().into(),
        user["role"].as_str().unwrap().into(),
    )
}

async fn admit(w: &World, token: &str, run_id: &str) -> (u16, Value) {
    let response = reqwest::Client::new()
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth(token)
        .json(&run_body(run_id, 1200))
        .send()
        .await
        .unwrap();
    (response.status().as_u16(), response.json().await.unwrap_or(Value::Null))
}

async fn admitted(w: &World, run_id: &str) -> Value {
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
        .find(|e| e["kind"] == "run_admitted" && e["payload"]["run_id"] == run_id)
        .map(|e| e["payload"].clone())
        .unwrap()
}

#[tokio::test]
async fn required_binding_admits_only_runs_for_the_delegating_user_and_role() {
    let realm = Realm::start().await;
    let w = world_for(&realm).await;
    let (user, role) = declared();

    for (token, reason) in [
        (realm.delegated("u-someone-else", &[&role]), "other_user"),
        (realm.delegated(&user, &["offline_access"]), "role_not_held"),
        (realm.service(), "no_user"),
    ] {
        let (status, body) = admit(&w, &token, &format!("run_{reason}")).await;
        assert_eq!(status, 403, "{reason}: {body}");
        assert_eq!(body["error"]["code"], "user_not_bound");
        assert_eq!(body["error"]["detail"], reason);
    }

    let (status, body) = admit(&w, &realm.delegated(&user, &[&role, "offline_access"]), "run_bound").await;
    assert_eq!(status, 201, "{body}");
    let entry = admitted(&w, "run_bound").await;
    assert_eq!(entry["admitted_by"], "sa-support-agent", "the caller is the actor");
    assert_eq!(entry["user_binding"]["bound"], true);
    assert_eq!(entry["user_binding"]["roles_checked"], true);
    assert_eq!(entry["user_binding"]["source"], format!("oidc:{}#act", realm.issuer));
    assert_eq!(entry["agent_binding"]["bound"], true, "act.client_id names agt_support");
    assert_eq!(
        entry["agent_binding"]["source"],
        format!("oidc:{}#act.client_id", realm.issuer)
    );
    assert!(
        !entry.to_string().contains(&user),
        "the audit does not hold the user id"
    );

    let metrics = reqwest::get(format!("{}/metrics", w.base))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    for reason in ["other_user", "role_not_held", "no_user"] {
        assert!(
            metrics.contains(&format!(
                "contextos_user_binding_mismatches_total{{reason=\"{reason}\"}} 1\n"
            )),
            "{reason}"
        );
    }
}

#[tokio::test]
async fn observed_binding_admits_and_counts_a_run_without_a_user() {
    let w = world(&ALL_CONTROLS).await;
    assert_eq!(w.state.user_binding, UserBinding::Observe, "the default");
    let response = reqwest::Client::new()
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&run_body("run_observed_user", 1200))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);
    let binding = &admitted(&w, "run_observed_user").await["user_binding"];
    assert_eq!(binding["mode"], "observe");
    assert_eq!(binding["bound"], false);
    assert_eq!(binding["reason"], "no_user");
}

#[tokio::test]
async fn required_binding_needs_every_admitting_credential_to_name_a_user() {
    let realm = Realm::start().await;
    let (mut config, _) = world_setup(&ALL_CONTROLS).await;
    config.guards.user_binding = Some(UserBinding::Required);
    let refused = user_binding::check(&config).unwrap_err();
    assert!(refused.contains("[oidc.delegation]"), "{refused}");
    config.oidc.push(realm.config());
    let refused = user_binding::check(&config).unwrap_err();
    assert!(refused.contains("svc_orchestrator"), "an admitting api key: {refused}");
    for key in &mut config.api_keys {
        key.scopes.retain(|s| s != "admit");
    }
    assert!(user_binding::check(&config).is_ok());
    let mut plain = realm.config();
    plain.delegation = None;
    config.oidc.push(plain);
    assert!(
        user_binding::check(&config)
            .unwrap_err()
            .contains("needs [oidc.delegation]")
    );
}

async fn revoke(w: &World, path: &str, kind: &str, target: &str) {
    let response = reqwest::Client::new()
        .post(format!("{}/v1/revocations{path}", w.base))
        .bearer_auth("ops-key")
        .json(&json!({"kind": kind, "target": target, "reason": "incident 4712"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "{kind} {target}");
}

#[tokio::test]
async fn a_delegation_chain_is_recorded_and_any_link_of_it_can_be_revoked() {
    let realm = Realm::start().await;
    let w = world_for(&realm).await;
    let (user, role) = declared();
    let chain = ["sa-support-agent", "assistant-a"];
    let token = realm.chained(&user, &[&role], &chain);

    let (status, body) = admit(&w, &token, "run_chain").await;
    assert_eq!(status, 201, "{body}");
    let entry = admitted(&w, "run_chain").await;
    assert_eq!(
        entry["admitted_by"], "sa-support-agent",
        "the current actor is the caller"
    );
    assert_eq!(entry["delegation"]["depth"], 2);
    let digest = entry["delegation"]["chain_digest"].as_str().unwrap().to_owned();
    assert!(digest.starts_with("sha256:"));
    for secret in [user.as_str(), "assistant-a"] {
        assert!(!entry.to_string().contains(secret), "the audit holds no identities");
    }
    // The run keeps the chain and the user's roles, for revocation and privilege checks.
    let stored = w
        .state
        .store
        .get(&contextos_store::DocKey::new(
            TENANT,
            contextos_store::DocKind::RunAdmission,
            "run_chain",
        ))
        .await
        .unwrap()
        .unwrap()
        .body;
    assert_eq!(stored["delegation_chain"]["actors"], json!(chain));
    assert_eq!(stored["delegation_chain"]["user_roles"], json!([role]));
    assert_eq!(stored["delegation_chain"]["digest"], digest.as_str());

    // Revoking the earlier actor stops the run's effects, though it never called.
    revoke(&w, "", "principal", "assistant-a").await;
    let http = executor_client(body["executor_generation"].as_u64().unwrap());
    let blocked: Value = http
        .post(format!("{}/v1/runs/run_chain/tool-calls", w.base))
        .bearer_auth(&token)
        .json(&tool_call("run_chain", "tc_1", 120_000))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        blocked["report"]["reason_codes"],
        json!(["revoked_principal"]),
        "{blocked}"
    );
    revoke(&w, "/restore", "principal", "assistant-a").await;

    // Revoking the user stops new runs acting for them, through any path.
    revoke(&w, "", "user", &user).await;
    let direct = realm.delegated(&user, &[&role]);
    let (status, refused) = admit(&w, &direct, "run_after_user").await;
    assert_eq!(status, 403, "{refused}");
    assert_eq!(refused["error"]["detail"], json!(["revoked_user"]));
    revoke(&w, "/restore", "user", &user).await;

    // Revoking one exact path leaves the others.
    revoke(&w, "", "delegation", &digest).await;
    let (status, refused) = admit(&w, &token, "run_same_path").await;
    assert_eq!(status, 403, "{refused}");
    assert_eq!(refused["error"]["detail"], json!(["revoked_delegation"]));
    assert_eq!(admit(&w, &direct, "run_other_path").await.0, 201);

    // A chain longer than max_chain (4) is not a credential.
    let long = realm.chained(&user, &[&role], &["sa-support-agent", "a2", "a3", "a4", "a5"]);
    assert_eq!(admit(&w, &long, "run_long").await.0, 401);
}

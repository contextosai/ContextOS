//! Conformance with the token shapes Microsoft Entra ID and Okta issue, signed locally:
//! the configurations in docs/integrations/entra-id.md and okta.md admit runs from
//! them, bind the agent, and refuse tokens from another tenant or authorization server.
//!
//! The claims follow the providers' references: Entra v2 access tokens (`tid`, `azp`,
//! `roles`, `idtyp`), Okta custom authorization server access tokens (`cid`, `scp` as
//! an array) and Okta's token exchange for AI agents (`act.sub` naming the agent, with
//! `sub_profile`). Only the signing algorithm differs (EdDSA here, RS256 there).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use contextosd::oidc::OidcConfig;
use contextosd::user_binding::UserBinding;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Value, json};

use crate::harness::*;

const ENTRA_TENANT: &str = "72f988bf-86f1-41af-91ab-2d7cd011db47";
const ENTRA_API: &str = "6e74172b-be56-4843-9ff4-e66a39bb12e3";
const ENTRA_AGENT_APP: &str = "a3f1c2d4-0b1e-4c5f-9a8b-7c6d5e4f3a21";

struct Keys {
    pkcs8: Vec<u8>,
    jwks_url: String,
}

impl Keys {
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
            "/keys",
            axum::routing::get(move || {
                let jwks = jwks.clone();
                async move { axum::Json(jwks) }
            }),
        );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            pkcs8: pkcs8.as_ref().to_vec(),
            jwks_url: format!("{base}/keys"),
        }
    }

    fn sign(&self, claims: &Value) -> String {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("k1".into());
        jsonwebtoken::encode(&header, claims, &EncodingKey::from_ed_der(&self.pkcs8)).unwrap()
    }
}

fn times() -> (u64, u64) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    (now, now + 300)
}

/// docs/integrations/entra-id.md, with the test's key location and algorithm.
fn entra(keys: &Keys) -> OidcConfig {
    toml::from_str(&format!(
        r#"
        issuer = "https://login.microsoftonline.com/{ENTRA_TENANT}/v2.0"
        audience = "{ENTRA_API}"
        jwks_url = "{}"
        tenants = ["{TENANT}"]
        tenant_claim = "tid"
        scope_claim = "roles"
        agent_claim = "azp"
        algorithms = ["EdDSA"]
        [tenant_map]
        "{ENTRA_TENANT}" = "{TENANT}"
        [agents]
        "{ENTRA_AGENT_APP}" = ["agt_support"]
        "#,
        keys.jwks_url
    ))
    .unwrap()
}

/// docs/integrations/okta.md, with the test's key location and algorithm.
fn okta(keys: &Keys) -> OidcConfig {
    toml::from_str(&format!(
        r#"
        issuer = "https://acme.okta.com/oauth2/aus1agents"
        audience = "api://contextos"
        jwks_url = "{}"
        tenants = ["{TENANT}"]
        tenant_claim = "iss"
        scope_claim = "scp"
        agent_claim = "cid"
        algorithms = ["EdDSA"]
        [tenant_map]
        "https://acme.okta.com/oauth2/aus1agents" = "{TENANT}"
        [agents]
        "0oa-support-agent" = ["agt_support"]
        [delegation]
        actor_claim = "act"
        "#,
        keys.jwks_url
    ))
    .unwrap()
}

async fn world_for(config: OidcConfig, binding: UserBinding) -> World {
    let w = world_with(&ALL_CONTROLS, 1, |c| {
        c.oidc.push(config);
        c.guards.user_binding = Some(binding);
    })
    .await;
    for _ in 0..100 {
        if reqwest::get(format!("{}/readyz", w.base)).await.unwrap().status() == 200 {
            return w;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("issuer keys never loaded");
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
async fn an_entra_app_only_token_admits_runs_for_its_agent_and_tenant() {
    let keys = Keys::start().await;
    let w = world_for(entra(&keys), UserBinding::Observe).await;
    let (iat, exp) = times();
    let token = |tid: &str, roles: &[&str]| {
        keys.sign(&json!({
            "aud": ENTRA_API, "iss": format!("https://login.microsoftonline.com/{ENTRA_TENANT}/v2.0"),
            "iat": iat, "nbf": iat, "exp": exp, "ver": "2.0",
            "tid": tid, "azp": ENTRA_AGENT_APP, "azpacr": "1", "idtyp": "app",
            "oid": "1f2e3d4c-5b6a-4789-8a9b-0c1d2e3f4a5b", "sub": "1f2e3d4c-5b6a-4789-8a9b-0c1d2e3f4a5b",
            "roles": roles,
        }))
    };

    let (status, body) = admit(&w, &token(ENTRA_TENANT, &["admit", "dispatch"]), "run_entra").await;
    assert_eq!(status, 201, "{body}");
    let entry = admitted(&w, "run_entra").await;
    assert_eq!(entry["admitted_by"], "1f2e3d4c-5b6a-4789-8a9b-0c1d2e3f4a5b");
    assert_eq!(entry["agent_binding"]["bound"], true, "azp names agt_support");
    // An app-only token names no user: user binding observes it.
    assert_eq!(entry["user_binding"]["reason"], "no_user");

    // Another tenant, or app roles that do not grant admit: refused.
    assert_eq!(
        admit(
            &w,
            &token("00000000-0000-0000-0000-000000000000", &["admit"]),
            "run_other"
        )
        .await
        .0,
        401
    );
    assert_eq!(
        admit(&w, &token(ENTRA_TENANT, &["dispatch"]), "run_no_admit").await.0,
        403
    );
}

#[tokio::test]
async fn okta_service_and_exchanged_agent_tokens_admit_runs() {
    let keys = Keys::start().await;
    let w = world_for(okta(&keys), UserBinding::Observe).await;
    let (iat, exp) = times();
    let iss = "https://acme.okta.com/oauth2/aus1agents";

    // Client credentials: `sub` is the client, scopes are an array.
    let service = keys.sign(&json!({"ver": 1, "jti": "AT.1", "iss": iss, "aud": "api://contextos",
        "iat": iat, "exp": exp, "cid": "0oa-support-agent", "sub": "0oa-support-agent",
        "scp": ["admit", "dispatch"]}));
    let (status, body) = admit(&w, &service, "run_okta_service").await;
    assert_eq!(status, 201, "{body}");
    assert_eq!(admitted(&w, "run_okta_service").await["agent_binding"]["bound"], true);

    // Token exchange for an AI agent: `sub` is the user, `act.sub` the agent.
    let user = run_body("run_x", 1200)["run_context"]["user"]["user_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let exchanged = keys.sign(&json!({"ver": 1, "jti": "AT.2", "iss": iss, "aud": "api://contextos",
        "iat": iat, "exp": exp, "cid": "0oa-support-agent", "uid": "00u-user", "sub": user,
        "scp": ["admit", "dispatch"],
        "act": {"sub": "0oa-support-agent", "sub_profile": "ai_agent"}}));
    let (status, body) = admit(&w, &exchanged, "run_okta_user").await;
    assert_eq!(status, 201, "{body}");
    let entry = admitted(&w, "run_okta_user").await;
    assert_eq!(entry["admitted_by"], "0oa-support-agent", "the caller is the actor");
    assert_eq!(entry["user_binding"]["bound"], true, "{entry}");

    // Another authorization server of the same org is not this tenant's.
    let other = keys.sign(
        &json!({"iss": "https://acme.okta.com/oauth2/default", "aud": "api://contextos",
        "iat": iat, "exp": exp, "cid": "0oa-support-agent", "sub": "0oa-support-agent", "scp": ["admit"]}),
    );
    assert_eq!(admit(&w, &other, "run_okta_other").await.0, 401);
}

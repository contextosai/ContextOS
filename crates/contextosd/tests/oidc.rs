//! OIDC caller authentication against a locally served JWKS.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use contextos_audit::AuditSigner;
use contextos_store::{MemoryLog, MemoryStore};
use contextosd::{Config, build_state, router};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Value, json};

struct Issuer {
    pkcs8: Vec<u8>,
    public: Vec<u8>,
}

impl Issuer {
    fn new() -> Self {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        Self {
            public: pair.public_key().as_ref().to_vec(),
            pkcs8: pkcs8.as_ref().to_vec(),
        }
    }

    fn jwks(&self) -> Value {
        json!({"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "k1", "alg": "EdDSA", "use": "sig",
            "x": URL_SAFE_NO_PAD.encode(&self.public)}]})
    }

    fn sign(&self, kid: &str, claims: &Value) -> String {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(kid.into());
        jsonwebtoken::encode(&header, claims, &EncodingKey::from_ed_der(&self.pkcs8)).unwrap()
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn claims() -> Value {
    json!({"iss": "https://login.example.test", "aud": "contextosd", "sub": "svc_orchestrator",
        "tenant_id": "tenant_acme_prod", "scope": "audit:read admin", "iat": now(), "exp": now() + 300})
}

async fn serve(app: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

async fn start(issuer: &Issuer) -> String {
    start_with(issuer, "").await.0
}

/// Serves a runtime trusting `issuer`, with `extra` added to its `[[oidc]]` table.
async fn start_with(issuer: &Issuer, extra: &str) -> (String, Arc<contextosd::AppState<MemoryStore, MemoryLog>>) {
    let jwks = issuer.jwks();
    let jwks_base = serve(axum::Router::new().route(
        "/jwks.json",
        axum::routing::get(move || {
            let jwks = jwks.clone();
            async move { axum::Json(jwks) }
        }),
    ))
    .await;
    let config = Config::parse(&format!(
        r#"
        [server]
        listen = "127.0.0.1:0"
        mode = "development"
        [store]
        kind = "memory"
        [audit]
        signing_seed_env = "UNUSED"
        key_id = "audit-test"
        [support]
        implementation_id = "contextos-rs"
        implementation_version = "0.1.0"
        profiles = ["contextos.core"]
        controls = []
        [[oidc]]
        issuer = "https://login.example.test"
        audience = "contextosd"
        jwks_url = "{jwks_base}/jwks.json"
        tenants = ["tenant_acme_prod"]
        algorithms = ["EdDSA"]
        {extra}
        "#
    ))
    .unwrap();
    let state = build_state(
        &config,
        Arc::new(MemoryStore::new()),
        MemoryLog::new(),
        AuditSigner::from_seed("audit-test", [5; 32]),
        HashMap::new(),
        None,
    )
    .unwrap();
    let base = serve(router(state.clone(), Duration::from_secs(5))).await;
    let http = reqwest::Client::new();
    for _ in 0..100 {
        if http.get(format!("{base}/readyz")).send().await.unwrap().status() == 200 {
            return (base, state);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("issuer keys never loaded");
}

async fn audit_status(base: &str, token: &str) -> u16 {
    reqwest::Client::new()
        .get(format!("{base}/v1/audit/verify"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

#[tokio::test]
async fn verified_tokens_authenticate_and_everything_else_is_refused() {
    let issuer = Issuer::new();
    let base = start(&issuer).await;

    assert_eq!(audit_status(&base, &issuer.sign("k1", &claims())).await, 200);

    let mut wrong_audience = claims();
    wrong_audience["aud"] = json!("someone-else");
    assert_eq!(audit_status(&base, &issuer.sign("k1", &wrong_audience)).await, 401);

    let mut wrong_issuer = claims();
    wrong_issuer["iss"] = json!("https://evil.example.test");
    assert_eq!(audit_status(&base, &issuer.sign("k1", &wrong_issuer)).await, 401);

    let mut expired = claims();
    expired["exp"] = json!(now() - 3600);
    assert_eq!(audit_status(&base, &issuer.sign("k1", &expired)).await, 401);

    let mut not_yet = claims();
    not_yet["nbf"] = json!(now() + 3600);
    assert_eq!(audit_status(&base, &issuer.sign("k1", &not_yet)).await, 401);

    let mut foreign_tenant = claims();
    foreign_tenant["tenant_id"] = json!("tenant_other");
    assert_eq!(
        audit_status(&base, &issuer.sign("k1", &foreign_tenant)).await,
        401,
        "issuer may not assert a tenant it is not configured for"
    );

    let mut no_subject = claims();
    no_subject.as_object_mut().unwrap().remove("sub");
    assert_eq!(audit_status(&base, &issuer.sign("k1", &no_subject)).await, 401);

    let mut no_scope = claims();
    no_scope["scope"] = json!(["compile"]);
    assert_eq!(audit_status(&base, &issuer.sign("k1", &no_scope)).await, 403);

    assert_eq!(audit_status(&base, &issuer.sign("unknown", &claims())).await, 401);
    assert_eq!(
        audit_status(&base, &Issuer::new().sign("k1", &claims())).await,
        401,
        "signed by a different key"
    );

    // Algorithm confusion: an HMAC token keyed with the issuer's public key.
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("k1".into());
    let forged = jsonwebtoken::encode(&header, &claims(), &EncodingKey::from_secret(&issuer.public)).unwrap();
    assert_eq!(audit_status(&base, &forged).await, 401);

    // Tampered payload with the original signature.
    let token = issuer.sign("k1", &claims());
    let parts: Vec<&str> = token.split('.').collect();
    let mut elevated = claims();
    elevated["tenant_id"] = json!("tenant_acme_prod");
    elevated["scope"] = json!("audit:read compile admit dispatch");
    let tampered = format!(
        "{}.{}.{}",
        parts[0],
        URL_SAFE_NO_PAD.encode(elevated.to_string()),
        parts[2]
    );
    assert_eq!(audit_status(&base, &tampered).await, 401);
}

#[test]
fn configuration_refuses_unsafe_issuers() {
    let base = r#"
        [server]
        listen = "127.0.0.1:0"
        [store]
        kind = "memory"
        [audit]
        signing_seed_env = "UNUSED"
        key_id = "k"
        [support]
        implementation_id = "x"
        implementation_version = "1"
        profiles = []
        controls = []
        [[oidc]]
        issuer = "https://login.example.test"
        audience = "contextosd"
    "#;
    let with = |extra: &str| Config::parse(&format!("{base}{extra}"));
    assert!(with("jwks_url = \"https://login.example.test/jwks\"\ntenants = [\"t\"]").is_ok());
    assert!(
        with("jwks_url = \"http://login.example.test/jwks\"\ntenants = [\"t\"]").is_err(),
        "plain HTTP outside development"
    );
    assert!(with("jwks_url = \"https://login.example.test/jwks\"\ntenants = []").is_err());
    assert!(
        with("jwks_url = \"https://login.example.test/jwks\"\ntenants = [\"t\"]\nalgorithms = [\"HS256\"]").is_err()
    );
    assert!(
        with("jwks_url = \"https://login.example.test/jwks\"\ntenants = [\"t\"]\nalgorithms = [\"none\"]").is_err()
    );
}

#[tokio::test]
async fn an_agent_claim_names_the_agents_a_token_is_issued_for() {
    let issuer = Issuer::new();
    let (_, state) = start_with(&issuer, "agent_claim = \"sub\"").await;
    let caller = |claims: &Value| {
        state
            .auth
            .authenticate(Some(&format!("Bearer {}", issuer.sign("k1", claims))))
    };
    let mut svid = claims();
    svid["sub"] = json!("spiffe://contextos.test/agents/support");
    let found = caller(&svid).unwrap();
    assert_eq!(
        found.agents,
        Some(vec!["spiffe://contextos.test/agents/support".to_owned()])
    );
    assert_eq!(
        found.agent_source.as_deref(),
        Some("oidc:https://login.example.test#sub")
    );

    // A mapping table translates claim values; a value it does not list names no agent.
    let issuer = Issuer::new();
    let (_, state) = start_with(
        &issuer,
        "agent_claim = \"azp\"\n[oidc.agents]\nsupport-client = [\"agt_support\", \"agt_support_v2\"]",
    )
    .await;
    let caller = |claims: &Value| {
        state
            .auth
            .authenticate(Some(&format!("Bearer {}", issuer.sign("k1", claims))))
    };
    let mut mapped = claims();
    mapped["azp"] = json!("support-client");
    assert_eq!(
        caller(&mapped).unwrap().agents,
        Some(vec!["agt_support".to_owned(), "agt_support_v2".to_owned()])
    );
    mapped["azp"] = json!("billing-client");
    assert_eq!(caller(&mapped).unwrap().agents, Some(Vec::new()));
    assert_eq!(caller(&claims()).unwrap().agents, Some(Vec::new()), "no azp claim");
}

/// Serves a Keycloak-shaped realm: OpenID Provider Metadata naming `metadata_issuer`
/// and the realm's certs. Returns the realm's issuer URL.
async fn realm(issuer: &Issuer, metadata_issuer: Option<&str>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let realm = format!("http://{}/realms/acme", listener.local_addr().unwrap());
    let metadata = json!({"issuer": metadata_issuer.unwrap_or(&realm),
        "jwks_uri": format!("{realm}/protocol/openid-connect/certs")});
    let jwks = issuer.jwks();
    let app = axum::Router::new()
        .route(
            "/realms/acme/.well-known/openid-configuration",
            axum::routing::get(move || {
                let metadata = metadata.clone();
                async move { axum::Json(metadata) }
            }),
        )
        .route(
            "/realms/acme/protocol/openid-connect/certs",
            axum::routing::get(move || {
                let jwks = jwks.clone();
                async move { axum::Json(jwks) }
            }),
        );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    realm
}

fn discovering(realm: &str, extra: &str) -> Arc<contextosd::oidc::OidcIssuer> {
    let config: contextosd::oidc::OidcConfig = toml::from_str(&format!(
        "issuer = \"{realm}\"\naudience = \"contextosd\"\ntenants = [\"tenant_acme_prod\"]\nalgorithms = [\"EdDSA\"]\n{extra}"
    ))
    .unwrap();
    Arc::new(contextosd::oidc::OidcIssuer::new(config, true).unwrap())
}

#[tokio::test]
async fn keys_are_discovered_from_the_issuers_metadata() {
    let issuer = Issuer::new();
    let realm_url = realm(&issuer, None).await;
    let found = discovering(&realm_url, "");
    found.refresh_once().await.unwrap();
    assert!(found.ready());
    let mut token = claims();
    token["iss"] = json!(realm_url);
    let caller = contextosd::oidc::authenticate_jwt(&[found], &issuer.sign("k1", &token)).unwrap();
    assert_eq!(caller.principal_id, "svc_orchestrator");

    // Metadata naming another issuer is not trusted.
    let impostor = realm(&issuer, Some("https://login.example.test")).await;
    let refused = discovering(&impostor, "");
    assert!(refused.refresh_once().await.unwrap_err().contains("different issuer"));
    assert!(!refused.ready());
}

#[tokio::test]
async fn organizations_map_to_exactly_one_tenant() {
    let issuer = Issuer::new();
    let (_, state) = start_with(
        &issuer,
        "tenant_claim = \"organization\"\n[oidc.tenant_map]\nacme = \"tenant_acme_prod\"",
    )
    .await;
    let tenant = |organization: Value| {
        let mut token = claims();
        token["organization"] = organization;
        state
            .auth
            .authenticate(Some(&format!("Bearer {}", issuer.sign("k1", &token))))
            .map(|c| c.tenant_id)
    };
    for shape in [
        json!("acme"),
        json!(["acme"]),
        json!({"acme": {"id": "7d1c"}}),
        json!(["acme", "globex"]),
    ] {
        assert_eq!(tenant(shape.clone()).as_deref(), Some("tenant_acme_prod"), "{shape}");
    }
    assert_eq!(
        tenant(json!("tenant_acme_prod")),
        None,
        "only mapped values name tenants"
    );
    assert_eq!(tenant(json!(["globex"])), None);
    assert_eq!(tenant(json!([])), None);
}

#[tokio::test]
async fn delegated_tokens_name_the_actor_as_caller_and_the_subject_as_user() {
    let issuer = Issuer::new();
    let (_, state) = start_with(
        &issuer,
        "agent_claim = \"azp\"\n[oidc.delegation]\nactor_agent_claim = \"client_id\"\nuser_roles_claim = \"realm_access.roles\"",
    )
    .await;
    let caller = |token: &Value| {
        state
            .auth
            .authenticate(Some(&format!("Bearer {}", issuer.sign("k1", token))))
    };
    let mut delegated = claims();
    delegated["sub"] = json!("u-alice");
    delegated["azp"] = json!("login-app");
    delegated["act"] = json!({"sub": "sa-support", "client_id": "support-agent"});
    delegated["realm_access"] = json!({"roles": ["support_agent"]});
    let found = caller(&delegated).unwrap();
    assert_eq!(found.principal_id, "sa-support");
    assert_eq!(
        found.agents,
        Some(vec!["support-agent".to_owned()]),
        "from act, not azp"
    );
    let user = found.user.unwrap();
    assert_eq!(user.user_id, "u-alice");
    assert_eq!(user.roles, Some(vec!["support_agent".to_owned()]));

    // An ordinary token names no user, and its agent comes from agent_claim.
    let mut service = claims();
    service["azp"] = json!("support-agent");
    let found = caller(&service).unwrap();
    assert_eq!((found.principal_id.as_str(), found.user), ("svc_orchestrator", None));
    assert_eq!(found.agents, Some(vec!["support-agent".to_owned()]));

    // A malformed actor is refused, never read as an ordinary token.
    for act in [
        json!("sa-support"),
        json!({"client_id": "x"}),
        json!({"sub": ""}),
        json!({"sub": "u-alice"}),
    ] {
        delegated["act"] = act.clone();
        assert!(caller(&delegated).is_none(), "{act}");
    }
}

#[tokio::test]
async fn without_delegation_an_actor_claim_changes_nothing() {
    let issuer = Issuer::new();
    let (_, state) = start_with(&issuer, "").await;
    let mut token = claims();
    token["act"] = json!({"sub": "sa-support"});
    let found = state
        .auth
        .authenticate(Some(&format!("Bearer {}", issuer.sign("k1", &token))))
        .unwrap();
    assert_eq!((found.principal_id.as_str(), found.user), ("svc_orchestrator", None));
}

#[test]
fn configuration_refuses_bad_paths_and_tenant_maps() {
    let parse = |extra: &str| {
        toml::from_str::<contextosd::oidc::OidcConfig>(&format!(
            "issuer = \"https://kc.example/realms/acme\"\naudience = \"a\"\ntenants = [\"t\"]\n{extra}"
        ))
        .unwrap()
        .check(false)
    };
    assert!(parse("").is_ok(), "discovery from an https issuer");
    assert!(parse("tenant_claim = \"organization\"\n[tenant_map]\nacme = \"t\"").is_ok());
    assert!(
        parse("[tenant_map]\nacme = \"other\"")
            .unwrap_err()
            .contains("not in tenants")
    );
    assert!(
        parse("tenant_claim = \"a..b\"")
            .unwrap_err()
            .contains("invalid claim path")
    );
    assert!(
        parse("[delegation]\nactor_agent_claim = \"client_id\"")
            .unwrap_err()
            .contains("needs agent_claim")
    );
    assert!(parse("[delegation]\nactor_claim = \"\"").is_err());
    assert!(
        toml::from_str::<contextosd::oidc::OidcConfig>(
            "issuer = \"http://kc.example/realms/acme\"\naudience = \"a\"\ntenants = [\"t\"]"
        )
        .unwrap()
        .check(false)
        .unwrap_err()
        .contains("https"),
        "discovery needs an https issuer outside development"
    );
}

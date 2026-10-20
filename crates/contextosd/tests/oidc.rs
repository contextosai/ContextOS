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
    let base = serve(router(state, Duration::from_secs(5))).await;
    let http = reqwest::Client::new();
    for _ in 0..100 {
        if http.get(format!("{base}/readyz")).send().await.unwrap().status() == 200 {
            return base;
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

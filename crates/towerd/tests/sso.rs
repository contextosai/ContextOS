//! Single sign-on against a local identity provider: ID tokens map to roles through
//! groups, anything else is refused, API keys still work, and Tower exchanges a PKCE
//! code only for a token it accepts itself.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Form, State};
use axum::routing::{get, post};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use contextos_audit::AuditSigner;
use contextos_store::{MemoryLog, MemoryStore};
use contextosd::auth::hash_api_key;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Value, json};
use towerd::{Config, Tower, api};

const VERIFIER: &str = "verifier-0123456789-0123456789-0123456789-abc";

struct Idp {
    base: String,
    pkcs8: Vec<u8>,
    /// What the token endpoint puts in the next ID token.
    next: Mutex<Value>,
    /// The last form the token endpoint received.
    seen: Mutex<Value>,
}

impl Idp {
    fn sign(&self, kid: &str, claims: &Value) -> String {
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(kid.into());
        jsonwebtoken::encode(&header, claims, &EncodingKey::from_ed_der(&self.pkcs8)).unwrap()
    }

    fn claims(&self, groups: &[&str]) -> Value {
        json!({"iss": self.base, "aud": "tower-ui", "sub": "u-1", "email": "risk.lead@example.com",
            "groups": groups, "iat": now(), "exp": now() + 300})
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

async fn serve(app: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

async fn token(
    State(idp): State<Arc<Idp>>,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> axum::Json<Value> {
    *idp.seen.lock().unwrap() = json!(form);
    if form.get("code").map(String::as_str) == Some("huge-code") {
        return axum::Json(json!({"id_token": "x".repeat(2 * 1024 * 1024)}));
    }
    if form.get("code").map(String::as_str) != Some("good-code")
        || form.get("code_verifier").map(String::as_str) != Some(VERIFIER)
    {
        return axum::Json(json!({"error": "invalid_grant"}));
    }
    let claims = idp.next.lock().unwrap().clone();
    axum::Json(json!({"id_token": idp.sign("k1", &claims), "token_type": "Bearer"}))
}

async fn idp() -> Arc<Idp> {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let public = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .unwrap()
        .public_key()
        .as_ref()
        .to_vec();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let idp = Arc::new(Idp {
        base: base.clone(),
        pkcs8: pkcs8.as_ref().to_vec(),
        next: Mutex::new(Value::Null),
        seen: Mutex::new(Value::Null),
    });
    let metadata = json!({"issuer": base, "jwks_uri": format!("{base}/jwks"),
        "authorization_endpoint": format!("{base}/authorize"), "token_endpoint": format!("{base}/token")});
    let jwks = json!({"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "k1", "alg": "EdDSA", "use": "sig",
        "x": URL_SAFE_NO_PAD.encode(&public)}]});
    let app = axum::Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(move || async move { axum::Json(metadata) }),
        )
        .route("/jwks", get(move || async move { axum::Json(jwks) }))
        .route("/token", post(token))
        .with_state(idp.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    idp
}

async fn tower(idp: &Idp) -> String {
    let config = Config::parse(&format!(
        r#"
        [server]
        listen = "127.0.0.1:0"
        development = true
        [journal]
        signing_seed_env = "UNUSED"
        key_id = "tower-journal"
        [[api_keys]]
        key_sha256 = "{viewer}"
        principal_id = "ciso"
        roles = ["viewer"]
        [sso]
        issuer = "{issuer}"
        client_id = "tower-ui"
        redirect_uri = "http://127.0.0.1:5173/tower/"
        algorithms = ["EdDSA"]
        [[sso.groups]]
        group = "grc-risk"
        roles = ["risk"]
        teams = ["grc"]
        [[sso.groups]]
        group = "everyone"
        roles = ["viewer"]
        "#,
        viewer = hash_api_key("viewer-key"),
        issuer = idp.base,
    ))
    .unwrap();
    let tower = Arc::new(
        Tower::assemble(
            config,
            vec![],
            Arc::new(MemoryStore::new()),
            MemoryLog::new(),
            AuditSigner::from_seed("tower-journal", [4; 32]),
            None,
        )
        .unwrap(),
    );
    tower.spawn_sso();
    let base = serve(api::router(tower)).await;
    // The metadata and keys load in the background.
    for _ in 0..100 {
        let (_, settings) = get_json(&base, "/api/sso", None).await;
        if settings["authorization_endpoint"].is_string() {
            return base;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the identity provider's metadata never loaded");
}

async fn get_json(base: &str, path: &str, bearer: Option<&str>) -> (u16, Value) {
    let mut request = reqwest::Client::new().get(format!("{base}{path}"));
    if let Some(token) = bearer {
        request = request.bearer_auth(token);
    }
    let response = request.send().await.unwrap();
    (response.status().as_u16(), response.json().await.unwrap_or(Value::Null))
}

async fn exchange(base: &str, body: &Value) -> (u16, Value) {
    let response = reqwest::Client::new()
        .post(format!("{base}/api/sso/token"))
        .json(body)
        .send()
        .await
        .unwrap();
    (response.status().as_u16(), response.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn id_tokens_sign_people_in_with_the_roles_their_groups_grant() {
    let idp = idp().await;
    let base = tower(&idp).await;

    let (status, settings) = get_json(&base, "/api/sso", None).await;
    assert_eq!(status, 200);
    assert_eq!(settings["client_id"], "tower-ui");
    assert_eq!(settings["redirect_uri"], "http://127.0.0.1:5173/tower/");
    assert_eq!(settings["authorization_endpoint"], format!("{}/authorize", idp.base));
    assert!(settings.get("token_endpoint").is_none(), "{settings}");

    let token = idp.sign("k1", &idp.claims(&["grc-risk", "everyone", "unmapped"]));
    let (status, me) = get_json(&base, "/api/me", Some(&token)).await;
    assert_eq!(status, 200, "{me}");
    assert_eq!(me["principal_id"], "risk.lead@example.com");
    assert_eq!(me["roles"], json!(["risk", "viewer"]));
    assert_eq!(me["teams"], json!(["grc"]));

    // Refused: no mapped group, another audience, expired, an unknown key.
    let mut refused = vec![idp.sign("k1", &idp.claims(&["unmapped"]))];
    let mut other = idp.claims(&["grc-risk"]);
    other["aud"] = json!("another-app");
    refused.push(idp.sign("k1", &other));
    let mut expired = idp.claims(&["grc-risk"]);
    expired["exp"] = json!(now() - 3600);
    refused.push(idp.sign("k1", &expired));
    refused.push(idp.sign("k9", &idp.claims(&["grc-risk"])));
    for token in &refused {
        assert_eq!(get_json(&base, "/api/me", Some(token)).await.0, 401);
    }

    // API keys still sign in.
    let (status, me) = get_json(&base, "/api/me", Some("viewer-key")).await;
    assert_eq!((status, me["principal_id"].as_str()), (200, Some("ciso")));
}

#[tokio::test]
async fn tower_exchanges_a_code_only_for_a_token_it_accepts() {
    let idp = idp().await;
    let base = tower(&idp).await;
    let nonce = "nonce-0123456789abcdef";
    let mut claims = idp.claims(&["grc-risk"]);
    claims["nonce"] = json!(nonce);
    *idp.next.lock().unwrap() = claims.clone();

    let (status, done) = exchange(
        &base,
        &json!({"code": "good-code", "code_verifier": VERIFIER, "nonce": nonce}),
    )
    .await;
    assert_eq!(status, 200, "{done}");
    assert_eq!(done["roles"], json!(["risk"]));
    let seen = idp.seen.lock().unwrap().clone();
    assert_eq!(seen["redirect_uri"], "http://127.0.0.1:5173/tower/");
    assert_eq!(seen["client_id"], "tower-ui");
    assert!(seen.get("client_secret").is_none(), "a public client sends no secret");
    let (status, me) = get_json(&base, "/api/me", done["id_token"].as_str()).await;
    assert_eq!(
        (status, me["principal_id"].as_str()),
        (200, Some("risk.lead@example.com"))
    );

    // A token minted for another sign-in (another nonce) is not handed back.
    let (status, _) = exchange(
        &base,
        &json!({"code": "good-code", "code_verifier": VERIFIER, "nonce": "nonce-of-someone-else"}),
    )
    .await;
    assert_eq!(status, 403);
    // The identity provider refuses the code.
    let (status, _) = exchange(
        &base,
        &json!({"code": "stolen-code", "code_verifier": VERIFIER, "nonce": nonce}),
    )
    .await;
    assert_eq!(status, 401);
    // A token response larger than any identity provider sends is not read.
    let (status, _) = exchange(
        &base,
        &json!({"code": "huge-code", "code_verifier": VERIFIER, "nonce": nonce}),
    )
    .await;
    assert_eq!(status, 401);
    // A verifier that is not RFC 7636's shape is refused before anything is sent.
    let (status, _) = exchange(
        &base,
        &json!({"code": "good-code", "code_verifier": "short", "nonce": nonce}),
    )
    .await;
    assert_eq!(status, 422);
}

#[test]
fn sso_configuration_is_checked() {
    let parse = |extra: &str| {
        Config::parse(&format!(
            r#"
            [server]
            listen = "127.0.0.1:0"
            [journal]
            signing_seed_env = "UNUSED"
            key_id = "tower-journal"
            [sso]
            issuer = "https://login.example.com"
            client_id = "tower-ui"
            redirect_uri = "https://tower.example.com/tower/"
            {extra}
            "#
        ))
    };
    assert!(parse("[[sso.groups]]\ngroup = \"g\"\nroles = [\"viewer\"]").is_ok());
    assert!(parse("").is_err(), "no group mapping");
    assert!(parse("[[sso.groups]]\ngroup = \"g\"\nroles = [\"superuser\"]").is_err());
    assert!(
        parse("algorithms = [\"HS256\"]\n[[sso.groups]]\ngroup = \"g\"\nroles = [\"viewer\"]").is_err(),
        "a shared-secret algorithm"
    );
}

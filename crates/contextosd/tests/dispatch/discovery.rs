//! MCP hosts discover where to get a token from the server's protected resource
//! metadata (RFC 9728), named in every refusal's `WWW-Authenticate`.

use serde_json::{Value, json};

use crate::harness::*;

fn challenge(response: &reqwest::Response) -> String {
    response.headers()["www-authenticate"].to_str().unwrap().to_owned()
}

#[tokio::test]
async fn refusals_name_the_metadata_that_says_where_to_get_a_token() {
    let w = world_with(&ALL_CONTROLS, 1, |c| {
        c.server.public_url = Some("https://contextos.example".into());
    })
    .await;
    let http = reqwest::Client::new();
    let mcp = format!("{}/v1/runs/run_1/mcp", w.base);
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});

    let anonymous = http.post(&mcp).json(&body).send().await.unwrap();
    assert_eq!(anonymous.status(), 401);
    assert_eq!(
        challenge(&anonymous),
        "Bearer resource_metadata=\"https://contextos.example/.well-known/oauth-protected-resource/v1/runs/run_1/mcp\""
    );
    let no_scope = http.post(&mcp).bearer_auth("ops-key").json(&body).send().await.unwrap();
    assert_eq!(no_scope.status(), 403);
    assert!(
        challenge(&no_scope).starts_with("Bearer error=\"insufficient_scope\", scope=\"dispatch\", resource_metadata="),
        "{}",
        challenge(&no_scope)
    );
    let api = http.get(format!("{}/v1/runs/run_1", w.base)).send().await.unwrap();
    assert_eq!(
        challenge(&api),
        "Bearer resource_metadata=\"https://contextos.example/.well-known/oauth-protected-resource\""
    );

    let metadata: Value = http
        .get(format!(
            "{}/.well-known/oauth-protected-resource/v1/runs/run_1/mcp",
            w.base
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(metadata["resource"], "https://contextos.example/v1/runs/run_1/mcp");
    assert_eq!(metadata["scopes_supported"], json!(["dispatch"]));
    assert_eq!(metadata["bearer_methods_supported"], json!(["header"]));
    assert!(metadata["authorization_servers"].is_array());
    let api: Value = http
        .get(format!("{}/.well-known/oauth-protected-resource", w.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(api["resource"], "https://contextos.example");
    assert!(api["scopes_supported"].as_array().unwrap().contains(&json!("admit")));
}

#[tokio::test]
async fn without_a_public_url_nothing_is_published_and_challenges_stay_plain() {
    let w = world(&ALL_CONTROLS).await;
    let http = reqwest::Client::new();
    let metadata = http
        .get(format!("{}/.well-known/oauth-protected-resource", w.base))
        .send()
        .await
        .unwrap();
    assert_eq!(metadata.status(), 404);
    let anonymous = http.get(format!("{}/v1/runs/run_1", w.base)).send().await.unwrap();
    assert_eq!(challenge(&anonymous), "Bearer");
}

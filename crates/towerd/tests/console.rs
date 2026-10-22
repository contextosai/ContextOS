//! The Tower UI build served by towerd (`[tower] dir`): a strict content policy, client
//! routes, no path outside the build.

use std::path::PathBuf;
use std::sync::Arc;

use towerd::console::{Console, routes};

async fn serve(dir: Option<&PathBuf>) -> String {
    let app: axum::Router = match dir {
        Some(d) => routes(Arc::new(Console::load(d).unwrap())),
        None => axum::Router::new(),
    };
    let app = app.layer(tower_http::set_header::SetResponseHeaderLayer::overriding(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

/// A console build with an entry page, one script and one icon.
fn build(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("tower-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("assets")).unwrap();
    std::fs::write(dir.join("index.html"), "<!doctype html><title>Tower</title>").unwrap();
    std::fs::write(dir.join("assets/app.js"), "export {};").unwrap();
    std::fs::write(dir.join("favicon.svg"), "<svg/>").unwrap();
    dir
}

#[tokio::test]
async fn serves_the_build_with_a_strict_policy_and_client_routes() {
    let dir = build("serve");
    let base = serve(Some(&dir)).await;
    let http = client();

    let redirect = http.get(format!("{base}/tower")).send().await.unwrap();
    assert_eq!(redirect.status(), 308);
    assert_eq!(redirect.headers()["location"], "/tower/");

    let page = http.get(format!("{base}/tower/")).send().await.unwrap();
    assert_eq!(page.status(), 200);
    assert_eq!(page.headers()["content-type"], "text/html; charset=utf-8");
    let csp = page.headers()["content-security-policy"].to_str().unwrap().to_owned();
    for directive in [
        "default-src 'none'",
        "script-src 'self'",
        "connect-src 'self'",
        "frame-ancestors 'none'",
    ] {
        assert!(csp.contains(directive), "{csp}");
    }
    assert!(!csp.contains("unsafe-inline") && !csp.contains("unsafe-eval"));
    assert_eq!(page.headers()["x-frame-options"], "DENY");
    assert_eq!(page.headers()["referrer-policy"], "no-referrer");
    assert_eq!(page.headers()["x-content-type-options"], "nosniff");

    let script = http.get(format!("{base}/tower/assets/app.js")).send().await.unwrap();
    assert_eq!(script.headers()["content-type"], "text/javascript; charset=utf-8");
    assert_eq!(script.text().await.unwrap(), "export {};");

    // A client-side route gets the application page; a missing file does not.
    let route = http.get(format!("{base}/tower/runs/run_1")).send().await.unwrap();
    assert_eq!(route.status(), 200);
    assert!(route.text().await.unwrap().contains("<title>Tower</title>"));
    for missing in [
        "/tower/assets/missing.js",
        "/tower/%2e%2e/Cargo.toml",
        "/tower/..%2fCargo.toml",
    ] {
        assert_eq!(
            http.get(format!("{base}{missing}")).send().await.unwrap().status(),
            404,
            "{missing}"
        );
    }
}

#[tokio::test]
async fn the_console_is_off_unless_configured() {
    let base = serve(None).await;
    assert_eq!(
        client().get(format!("{base}/tower/")).send().await.unwrap().status(),
        404
    );
}

#[test]
fn a_build_must_have_an_entry_page_and_known_file_types() {
    let dir = build("check");
    let console = Console::load(&dir).unwrap();
    let mut paths: Vec<&str> = console.paths().collect();
    paths.sort_unstable();
    assert_eq!(paths, ["assets/app.js", "favicon.svg", "index.html"]);

    std::fs::write(dir.join("notes.exe"), "").unwrap();
    assert!(Console::load(&dir).unwrap_err().contains("unknown type"));
    std::fs::remove_file(dir.join("notes.exe")).unwrap();
    std::fs::remove_file(dir.join("index.html")).unwrap();
    assert!(Console::load(&dir).unwrap_err().contains("no index.html"));
}

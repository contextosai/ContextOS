//! The Tower UI, served by towerd at `/tower/`.
//!
//! The UI is a React application built in `tower/` (`npm run build`), and
//! `[tower] dir` points at its build output. The files are read into memory once at
//! startup, so requests never touch the filesystem and no request path can name a file
//! outside the build.
//!
//! The UI holds no data and grants nothing: every view is a call to towerd's API
//! under the signed-in person's own credentials and roles. Tokens live in the tab's
//! session storage only.
//!
//! Pages carry a restrictive Content-Security-Policy: scripts, styles and connections
//! from this origin only, no inline script, no framing.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use axum::Router;
use axum::extract::{self, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
                   connect-src 'self'; font-src 'self'; manifest-src 'self'; base-uri 'none'; \
                   form-action 'none'; frame-ancestors 'none'";

/// A console build larger than this is refused at startup.
const MAX_BYTES: u64 = 32 * 1024 * 1024;
const MAX_FILES: usize = 512;

/// The console's built files, by path relative to the build directory.
#[derive(Debug)]
pub struct Console {
    files: HashMap<String, (&'static str, Vec<u8>)>,
}

fn content_type(path: &str) -> Option<&'static str> {
    Some(match path.rsplit_once('.')?.1 {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "json" | "map" => "application/json",
        "txt" => "text/plain; charset=utf-8",
        "webmanifest" => "application/manifest+json",
        _ => return None,
    })
}

impl Console {
    /// Reads a console build. Fails without `index.html`, past the size limits, or on
    /// a file type it would not know how to serve.
    pub fn load(dir: &Path) -> Result<Self, String> {
        let mut files = HashMap::new();
        let mut total = 0;
        let mut pending = vec![dir.to_path_buf()];
        while let Some(current) = pending.pop() {
            let entries = std::fs::read_dir(&current).map_err(|e| format!("[tower] dir {}: {e}", current.display()))?;
            for entry in entries {
                let entry = entry.map_err(|e| format!("[tower] dir: {e}"))?;
                let path = entry.path();
                let kind = entry.file_type().map_err(|e| format!("[tower] dir: {e}"))?;
                if kind.is_dir() {
                    pending.push(path);
                    continue;
                }
                if !kind.is_file() {
                    return Err(format!("[tower] dir holds a non-regular file: {}", path.display()));
                }
                let relative = path
                    .strip_prefix(dir)
                    .ok()
                    .and_then(Path::to_str)
                    .map(|p| p.replace('\\', "/"))
                    .ok_or_else(|| format!("[tower] dir holds an unusable path: {}", path.display()))?;
                let kind = content_type(&relative)
                    .ok_or_else(|| format!("[tower] dir holds a file of unknown type: {relative}"))?;
                let body = std::fs::read(&path).map_err(|e| format!("[tower] {relative}: {e}"))?;
                total += body.len() as u64;
                if total > MAX_BYTES || files.len() >= MAX_FILES {
                    return Err("[tower] dir is too large for a console build".into());
                }
                files.insert(relative, (kind, body));
            }
        }
        if !files.contains_key("index.html") {
            return Err(format!(
                "[tower] dir {} has no index.html (run `npm run build` in tower/)",
                dir.display()
            ));
        }
        Ok(Self { files })
    }

    /// The console's paths, for tests.
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.files.keys().map(String::as_str)
    }

    /// A built file; any other path without an extension is a client-side route and
    /// gets the application page.
    fn serve(&self, path: &str) -> Response {
        let found = self.files.get(path).or_else(|| {
            let last = path.rsplit('/').next().unwrap_or_default();
            (!last.contains('.')).then(|| self.files.get("index.html")).flatten()
        });
        let Some((kind, body)) = found else {
            return StatusCode::NOT_FOUND.into_response();
        };
        let mut response = body.clone().into_response();
        let headers = response.headers_mut();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(kind));
        headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
        headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
        headers.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
        headers.insert("cross-origin-opener-policy", HeaderValue::from_static("same-origin"));
        headers.insert("cross-origin-resource-policy", HeaderValue::from_static("same-origin"));
        headers.insert(
            "permissions-policy",
            HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=(), usb=()"),
        );
        response
    }
}

/// The UI's routes, merged into the API router when `[tower] dir` is set.
pub fn routes<S>(console: Arc<Console>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/tower", get(|| async { Redirect::permanent("/tower/") }))
        .route(
            "/tower/",
            get(|State(console): State<Arc<Console>>| async move { console.serve("index.html") }),
        )
        .route(
            "/tower/{*path}",
            get(
                |State(console): State<Arc<Console>>, extract::Path(path): extract::Path<String>| async move {
                    console.serve(&path)
                },
            ),
        )
        .with_state(console)
}

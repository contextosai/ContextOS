//! `contextosd --mcp-stdio <url>`: connects an MCP host that only launches local
//! (stdio) servers to a run's MCP endpoint.
//!
//! The host starts this process as its server. Each newline-delimited JSON-RPC message
//! on stdin is POSTed to `<url>` (`…/v1/runs/{run_id}/mcp`) with
//! `Authorization: Bearer $CONTEXTOS_TOKEN` and, when set,
//! `ContextOS-Executor-Generation: $CONTEXTOS_EXECUTOR_GENERATION`. Each response is
//! written to stdout as one line. Requests run concurrently, so a slow governed call
//! does not hold up `tools/list`. The bridge decides nothing: the server governs every
//! call. Diagnostics go to stderr, since stdout belongs to the protocol.

use std::sync::Arc;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

/// The longest line accepted from the host or the server.
const MAX_MESSAGE: usize = 16 * 1024 * 1024;

struct Bridge {
    client: reqwest::Client,
    url: String,
    token: Option<String>,
    generation: Option<String>,
    /// The version `initialize` negotiated, sent on every later request.
    version: Mutex<Option<String>>,
}

fn error_line(id: &Value, code: i64, message: &str) -> String {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}).to_string()
}

/// The JSON-RPC messages in a response body: a JSON body, or the `data` of each SSE
/// `message` event.
fn messages(content_type: &str, body: &str) -> Vec<String> {
    if !content_type.starts_with("text/event-stream") {
        return vec![body.trim().to_owned()]
            .into_iter()
            .filter(|b| !b.is_empty())
            .collect();
    }
    body.split("\n\n")
        .filter_map(|event| {
            let mut kind = "message";
            let mut data = Vec::new();
            for line in event.lines() {
                if let Some(v) = line.strip_prefix("event:") {
                    kind = v.trim();
                } else if let Some(v) = line.strip_prefix("data:") {
                    data.push(v.strip_prefix(' ').unwrap_or(v));
                }
            }
            (kind == "message" && !data.is_empty()).then(|| data.join("\n"))
        })
        .collect()
}

impl Bridge {
    /// Sends one message and returns the lines to write back (none for notifications).
    async fn forward(&self, line: &str) -> Vec<String> {
        let parsed: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => return vec![error_line(&Value::Null, -32700, "invalid JSON")],
        };
        let id = parsed.get("id").cloned();
        let mut request = self
            .client
            .post(&self.url)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(line.to_owned());
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        if let Some(generation) = &self.generation {
            request = request.header(crate::app::EXECUTOR_GENERATION_HEADER, generation);
        }
        if let Some(version) = self.version.lock().await.clone() {
            request = request.header(crate::mcp_transport::VERSION_HEADER, version);
        }
        let fail = |message: String| {
            id.as_ref()
                .map(|id| error_line(id, -32603, &message))
                .into_iter()
                .collect()
        };
        let response = match request.send().await {
            Ok(r) => r,
            Err(e) => return fail(format!("ContextOS is unreachable: {e}")),
        };
        let status = response.status();
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let body = match response.text().await {
            Ok(b) if b.len() <= MAX_MESSAGE => b,
            Ok(_) => return fail("the response is too large".into()),
            Err(e) => return fail(format!("reading the response failed: {e}")),
        };
        let lines = messages(&content_type, &body);
        let replies: Vec<String> = lines
            .into_iter()
            .filter(|m| serde_json::from_str::<Value>(m).is_ok_and(|v| v.get("jsonrpc").is_some()))
            .collect();
        if !status.is_success() && replies.is_empty() {
            let detail = serde_json::from_str::<Value>(&body)
                .ok()
                .and_then(|v| v["error"]["message"].as_str().map(str::to_owned))
                .unwrap_or_default();
            return fail(format!("ContextOS answered HTTP {}: {detail}", status.as_u16()));
        }
        if parsed["method"] == "initialize" {
            let negotiated = replies.iter().find_map(|m| {
                let v: Value = serde_json::from_str(m).ok()?;
                v["result"]["protocolVersion"].as_str().map(str::to_owned)
            });
            *self.version.lock().await = negotiated;
        }
        replies
    }
}

/// Runs the bridge until stdin closes.
pub async fn run(url: &str) -> Result<(), String> {
    let parsed = url::Url::parse(url).map_err(|_| format!("{url:?} is not an absolute URL"))?;
    if !matches!(parsed.scheme(), "http" | "https") || !parsed.path().ends_with("/mcp") {
        return Err("the URL must be a run's MCP endpoint, https://…/v1/runs/{run_id}/mcp".into());
    }
    let bridge = Arc::new(Bridge {
        client: reqwest::Client::builder()
            .user_agent(concat!("contextosd-mcp-stdio/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| e.to_string())?,
        url: url.to_owned(),
        token: std::env::var("CONTEXTOS_TOKEN").ok().filter(|t| !t.is_empty()),
        generation: std::env::var("CONTEXTOS_EXECUTOR_GENERATION")
            .ok()
            .filter(|g| !g.is_empty()),
        version: Mutex::new(None),
    });
    if bridge.token.is_none() {
        eprintln!("contextosd --mcp-stdio: CONTEXTOS_TOKEN is not set; requests are sent without a token");
    }
    let stdout = Arc::new(Mutex::new(tokio::io::stdout()));
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut tasks = tokio::task::JoinSet::new();
    while let Some(line) = lines.next_line().await.map_err(|e| e.to_string())? {
        if line.trim().is_empty() {
            continue;
        }
        if line.len() > MAX_MESSAGE {
            let mut out = stdout.lock().await;
            let reply = error_line(&Value::Null, -32600, "the message is too large");
            out.write_all(format!("{reply}\n").as_bytes())
                .await
                .map_err(|e| e.to_string())?;
            out.flush().await.map_err(|e| e.to_string())?;
            continue;
        }
        let bridge = bridge.clone();
        let stdout = stdout.clone();
        // `initialize` completes before anything after it is sent, so later requests
        // carry the negotiated version.
        let initializing = serde_json::from_str::<Value>(&line).is_ok_and(|v| v["method"] == "initialize");
        let task = async move {
            let replies = bridge.forward(&line).await;
            let mut out = stdout.lock().await;
            for reply in replies {
                if out.write_all(format!("{reply}\n").as_bytes()).await.is_err() {
                    return;
                }
            }
            let _ = out.flush().await;
        };
        if initializing {
            task.await;
        } else {
            tasks.spawn(task);
        }
        while tasks.try_join_next().is_some() {}
    }
    while tasks.join_next().await.is_some() {}
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn responses_are_json_or_sse_message_events() {
        assert_eq!(messages("application/json", " {\"a\":1}\n"), vec!["{\"a\":1}"]);
        assert_eq!(messages("application/json", ""), Vec::<String>::new());
        let sse = "event: message\ndata: {\"a\":1}\n\n: comment\n\nevent: ping\ndata: x\n\ndata: {\"b\":\ndata: 2}\n\n";
        assert_eq!(messages("text/event-stream", sse), vec!["{\"a\":1}", "{\"b\":\n2}"]);
    }
}

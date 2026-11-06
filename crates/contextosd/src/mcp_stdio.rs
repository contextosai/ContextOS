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
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
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
    serve(bridge, BufReader::new(tokio::io::stdin()), stdout).await
}

/// One line read from the host.
#[derive(Debug, PartialEq)]
enum Line {
    Message(String),
    /// Longer than [`MAX_MESSAGE`]; the rest of it was read and dropped unbuffered.
    TooLong,
}

/// Reads the next newline-delimited line, holding at most `max` bytes of it.
async fn read_line<R: AsyncBufRead + Unpin>(reader: &mut R, max: usize) -> std::io::Result<Option<Line>> {
    let mut line = Vec::new();
    let mut too_long = false;
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            // End of input: a last line without a newline still counts.
            return Ok((too_long || !line.is_empty()).then(|| finish(line, too_long)));
        }
        let (chunk, done) = match available.iter().position(|&b| b == b'\n') {
            Some(i) => (&available[..i], i + 1),
            None => (available, available.len()),
        };
        if !too_long && line.len() + chunk.len() > max {
            too_long = true;
            line = Vec::new();
        }
        if !too_long {
            line.extend_from_slice(chunk);
        }
        let ended = done > chunk.len();
        reader.consume(done);
        if ended {
            return Ok(Some(finish(line, too_long)));
        }
    }
}

fn finish(line: Vec<u8>, too_long: bool) -> Line {
    if too_long {
        return Line::TooLong;
    }
    let mut text = String::from_utf8_lossy(&line).into_owned();
    if text.ends_with('\r') {
        text.pop();
    }
    Line::Message(text)
}

/// Forwards each line of `input` and writes the replies to `output`, until `input` ends.
///
/// Ordering: `initialize` and every notification are forwarded before the next line is
/// read, so a notification reaches the server after everything the host wrote before
/// it was sent and before anything after it (`notifications/initialized` cannot trail
/// the first `tools/call`). Requests run concurrently, so a slow governed call does not
/// hold up `tools/list`; a `notifications/cancelled` may therefore reach the server
/// while the request it names is still in flight. The server takes no action on
/// notifications: a governed call runs to its recorded outcome either way.
async fn serve<R, W>(bridge: Arc<Bridge>, mut input: R, output: Arc<Mutex<W>>) -> Result<(), String>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let mut tasks = tokio::task::JoinSet::new();
    while let Some(line) = read_line(&mut input, MAX_MESSAGE).await.map_err(|e| e.to_string())? {
        let line = match line {
            Line::Message(line) if line.trim().is_empty() => continue,
            Line::Message(line) => line,
            Line::TooLong => {
                let reply = error_line(&Value::Null, -32600, "the message is too large");
                let mut out = output.lock().await;
                out.write_all(format!("{reply}\n").as_bytes())
                    .await
                    .map_err(|e| e.to_string())?;
                out.flush().await.map_err(|e| e.to_string())?;
                continue;
            }
        };
        let bridge = bridge.clone();
        let out = output.clone();
        // `initialize` completes before anything after it is sent, so later requests
        // carry the negotiated version; notifications keep their place in the stream.
        let in_order = serde_json::from_str::<Value>(&line)
            .is_ok_and(|v| v["method"] == "initialize" || (v.get("id").is_none() && v.get("method").is_some()));
        let task = async move {
            let replies = bridge.forward(&line).await;
            let mut out = out.lock().await;
            for reply in replies {
                if out.write_all(format!("{reply}\n").as_bytes()).await.is_err() {
                    return;
                }
            }
            let _ = out.flush().await;
        };
        if in_order {
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

    #[tokio::test]
    async fn lines_are_bounded_before_they_are_buffered() {
        // A small read buffer, so lines span many fills.
        let input = format!("short\r\n{}\nafter\nlast", "x".repeat(100));
        let mut reader = BufReader::with_capacity(4, input.as_bytes());
        let mut lines = Vec::new();
        while let Some(line) = read_line(&mut reader, 16).await.unwrap() {
            lines.push(line);
        }
        assert_eq!(
            lines,
            [
                Line::Message("short".into()),
                Line::TooLong,
                Line::Message("after".into()),
                Line::Message("last".into()),
            ]
        );
    }

    /// A run's MCP endpoint that records the order messages arrive in; `tools/call`
    /// answers slowly.
    async fn recording_server() -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
        use axum::routing::post;
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = seen.clone();
        let router = axum::Router::new().route(
            "/v1/runs/run_1/mcp",
            post(move |body: String| {
                let log = log.clone();
                async move {
                    let v: Value = serde_json::from_str(&body).unwrap();
                    log.lock().unwrap().push(v["method"].as_str().unwrap().to_owned());
                    if v["method"] == "tools/call" {
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    }
                    match v.get("id") {
                        None => axum::http::StatusCode::ACCEPTED.into_response(),
                        Some(id) => axum::Json(json!({"jsonrpc": "2.0", "id": id,
                            "result": {"protocolVersion": "2025-06-18"}}))
                        .into_response(),
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        (format!("http://{addr}/v1/runs/run_1/mcp"), seen)
    }

    use axum::response::IntoResponse;

    #[tokio::test]
    async fn notifications_keep_their_place_and_requests_do_not_wait() {
        let (url, seen) = recording_server().await;
        let bridge = Arc::new(Bridge {
            client: reqwest::Client::new(),
            url,
            token: None,
            generation: None,
            version: Mutex::new(None),
        });
        let mut input = String::new();
        for message in [
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {}}),
            json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}),
        ] {
            input.push_str(&message.to_string());
            input.push('\n');
        }
        input.push_str(&"y".repeat(MAX_MESSAGE + 1));
        input.push('\n');
        let output = Arc::new(Mutex::new(Vec::<u8>::new()));
        serve(bridge, BufReader::new(input.as_bytes()), output.clone())
            .await
            .unwrap();

        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen[..2], ["initialize", "notifications/initialized"]);
        assert_eq!(seen.len(), 4, "{seen:?}");
        let out = String::from_utf8(output.lock().await.clone()).unwrap();
        let replies: Vec<Value> = out.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        let ids: Vec<&Value> = replies.iter().map(|r| &r["id"]).collect();
        // tools/list was not held up by the slow tools/call; the oversized line was
        // refused without being forwarded.
        let list = ids.iter().position(|id| **id == json!(3)).unwrap();
        let call = ids.iter().position(|id| **id == json!(2)).unwrap();
        assert!(list < call, "{out}");
        assert!(replies.iter().any(|r| r["error"]["code"] == -32600), "{out}");
    }
}

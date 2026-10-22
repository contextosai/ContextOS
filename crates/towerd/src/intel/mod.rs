//! Intelligence: Claude helping people govern, never governing.
//!
//! Every job here produces a *proposal or an explanation* for a person. Nothing a model
//! returns changes a record, a runtime or a policy: drafts pass deterministic checks
//! and a human decision through the normal role-checked API. The analyst's tools are
//! read-only and see only what the asking role may see; tool output is wrapped as data;
//! answers must cite agents, findings and runs by id, and Tower checks every citation
//! exists. Every model call is journalled (who, which job, model, digests, tokens).
//!
//! The Messages API is called over HTTP (Rust has no official SDK): `claude-opus-5-5`,
//! adaptive thinking (the model's default), explicit effort, server-side refusal
//! fallback (`fallbacks: "default"`), structured outputs for drafts, strict tools.

pub mod jobs;

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{Value, json};

use crate::config::IntelligenceConfig;

#[derive(Debug, thiserror::Error)]
pub enum IntelError {
    #[error("intelligence is not configured")]
    Off,
    #[error("the model service failed: {0}")]
    Http(String),
    #[error("the model service refused the request ({status}): {message}")]
    Api { status: u16, message: String },
    #[error("the model declined this request{}", .0.as_ref().map(|c| format!(" ({c})")).unwrap_or_default())]
    Refusal(Option<String>),
    #[error("the model's answer was cut off; ask a narrower question")]
    Truncated,
    #[error("the model's output was not usable: {0}")]
    Malformed(String),
}

/// A Messages API endpoint: real, or scripted for tests.
#[async_trait::async_trait]
pub trait Model: Send + Sync + std::fmt::Debug {
    fn name(&self) -> &str;
    async fn create(&self, request: Value) -> Result<Value, IntelError>;
}

#[derive(Debug)]
pub struct Anthropic {
    http: reqwest::Client,
    key: String,
    model: String,
    effort: String,
    url: String,
}

impl Anthropic {
    pub fn from_config(config: &IntelligenceConfig) -> Result<Self, String> {
        let key = std::env::var(&config.api_key_env).map_err(|_| format!("{} is not set", config.api_key_env))?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(600))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            http,
            key,
            model: config.model.clone(),
            effort: config.effort.clone(),
            url: format!("{}/v1/messages", config.base_url.trim_end_matches('/')),
        })
    }
}

#[async_trait::async_trait]
impl Model for Anthropic {
    fn name(&self) -> &str {
        &self.model
    }

    async fn create(&self, mut request: Value) -> Result<Value, IntelError> {
        request["model"] = json!(self.model);
        request["fallbacks"] = json!("default");
        let output = request["output_config"].as_object().cloned().unwrap_or_default();
        request["output_config"] = json!(output);
        request["output_config"]["effort"] = json!(self.effort);
        let response = self
            .http
            .post(&self.url)
            .header("x-api-key", &self.key)
            .header("anthropic-version", "2023-06-01")
            .header("anthropic-beta", "server-side-fallback-2026-07-01")
            .json(&request)
            .send()
            .await
            .map_err(|e| IntelError::Http(e.without_url().to_string()))?;
        let status = response.status();
        let body: Value = response.json().await.map_err(|e| IntelError::Http(e.to_string()))?;
        if !status.is_success() {
            return Err(IntelError::Api {
                status: status.as_u16(),
                message: body["error"]["message"].as_str().unwrap_or("unknown error").to_owned(),
            });
        }
        Ok(body)
    }
}

/// Replays canned responses, recording requests: for tests.
#[derive(Debug, Default)]
pub struct Scripted {
    responses: Mutex<VecDeque<Value>>,
    pub requests: Mutex<Vec<Value>>,
}

impl Scripted {
    pub fn new(responses: Vec<Value>) -> Self {
        Self {
            responses: Mutex::new(responses.into()),
            requests: Mutex::default(),
        }
    }

    /// A final text answer.
    pub fn text(text: &str) -> Value {
        json!({"stop_reason": "end_turn", "content": [{"type": "text", "text": text}], "usage": {"input_tokens": 10, "output_tokens": 10}})
    }

    /// A call of one tool.
    pub fn tool(name: &str, input: Value) -> Value {
        json!({"stop_reason": "tool_use", "content": [{"type": "tool_use", "id": format!("toolu_{name}"), "name": name, "input": input}],
            "usage": {"input_tokens": 10, "output_tokens": 10}})
    }
}

#[async_trait::async_trait]
impl Model for Scripted {
    fn name(&self) -> &'static str {
        "scripted"
    }

    async fn create(&self, request: Value) -> Result<Value, IntelError> {
        self.requests.lock().expect("lock").push(request);
        self.responses
            .lock()
            .expect("lock")
            .pop_front()
            .ok_or_else(|| IntelError::Malformed("script exhausted".into()))
    }
}

/// Checks a response's stop reason before its content is read.
pub fn checked(response: &Value) -> Result<(), IntelError> {
    match response["stop_reason"].as_str() {
        Some("refusal") => Err(IntelError::Refusal(
            response["stop_details"]["category"].as_str().map(str::to_owned),
        )),
        Some("max_tokens") => Err(IntelError::Truncated),
        _ => Ok(()),
    }
}

/// The concatenated text blocks of a response.
pub fn text(response: &Value) -> String {
    response["content"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|b| b["type"] == "text")
        .filter_map(|b| b["text"].as_str())
        .collect::<Vec<_>>()
        .join("")
}

/// Token usage of a response, summed into `total`.
pub fn add_usage(total: &mut Value, response: &Value) {
    for k in ["input_tokens", "output_tokens", "cache_read_input_tokens"] {
        let add = response["usage"][k].as_u64().unwrap_or(0);
        total[k] = json!(total[k].as_u64().unwrap_or(0) + add);
    }
}

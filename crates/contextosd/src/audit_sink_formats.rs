//! Wire formats for audit sinks: ContextOS's own batch, or the ingestion API of a SIEM.
//!
//! | `format` | Request | Credential header (`token_env`) |
//! |---|---|---|
//! | `contextos` (default) | `{sink, tenant_id, from_sequence, to_sequence, entries}` | none |
//! | `splunk_hec` | one HEC event per entry, concatenated: `{"time", "source": "contextos", "sourcetype": "contextos:audit", "event"}` | `Authorization: Splunk <token>` |
//! | `datadog` | a JSON array for the logs intake: `{"ddsource": "contextos", "service": "contextosd", "ddtags", "message", "contextos"}` | `DD-API-KEY: <token>` |
//! | `elastic_bulk` | NDJSON `create` actions with `_id` `<tenant>:<sequence>` | `Authorization: ApiKey <token>` |
//!
//! Every format carries the same entries, masked as the sink says, and every request is
//! still signed (`ContextOS-Signature`). Delivery is at least once: Elasticsearch drops a
//! redelivered entry by its `_id`; Splunk and Datadog receive it again, keyed by
//! `tenant_id` and `sequence` for deduplication in search.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SinkFormat {
    #[default]
    Contextos,
    SplunkHec,
    Datadog,
    ElasticBulk,
}

/// Seconds since the Unix epoch for an RFC 3339 time, for Splunk's `time`.
fn epoch_seconds(at: &str) -> Option<u64> {
    contextos_contract::validation::elapsed_millis("1970-01-01T00:00:00Z", at).map(|ms| ms / 1000)
}

impl SinkFormat {
    /// Whether the format needs a credential (`token_env`).
    #[must_use]
    pub fn needs_token(self) -> bool {
        self != Self::Contextos
    }

    /// The request body and its content type for one batch.
    #[must_use]
    pub fn encode(self, sink: &str, tenant: &str, from: u64, to: u64, entries: &[Value]) -> (&'static str, Vec<u8>) {
        match self {
            Self::Contextos => (
                "application/json",
                serde_json::to_vec(&json!({"sink": sink, "tenant_id": tenant, "from_sequence": from,
                    "to_sequence": to, "entries": entries}))
                .unwrap_or_default(),
            ),
            Self::SplunkHec => {
                let mut out = Vec::new();
                for e in entries {
                    let event = json!({"time": e["emitted_at"].as_str().and_then(epoch_seconds),
                        "source": "contextos", "sourcetype": "contextos:audit", "event": e});
                    out.extend(serde_json::to_vec(&event).unwrap_or_default());
                    out.push(b'\n');
                }
                ("application/json", out)
            }
            Self::Datadog => {
                let logs: Vec<Value> = entries
                    .iter()
                    .map(|e| {
                        let kind = e["kind"].as_str().unwrap_or("unknown");
                        json!({"ddsource": "contextos", "service": "contextosd",
                            "ddtags": format!("tenant:{tenant},kind:{kind},sink:{sink}"),
                            "message": format!("{kind} #{}", e["sequence"]), "contextos": e})
                    })
                    .collect();
                ("application/json", serde_json::to_vec(&logs).unwrap_or_default())
            }
            Self::ElasticBulk => {
                let mut out = Vec::new();
                for e in entries {
                    let action = json!({"create": {"_id": format!("{tenant}:{}", e["sequence"])}});
                    out.extend(serde_json::to_vec(&action).unwrap_or_default());
                    out.push(b'\n');
                    out.extend(serde_json::to_vec(e).unwrap_or_default());
                    out.push(b'\n');
                }
                ("application/x-ndjson", out)
            }
        }
    }

    /// The credential header, for formats that take one.
    #[must_use]
    pub fn auth_header(self, token: &str) -> Option<(&'static str, String)> {
        match self {
            Self::Contextos => None,
            Self::SplunkHec => Some(("authorization", format!("Splunk {token}"))),
            Self::Datadog => Some(("dd-api-key", token.to_owned())),
            Self::ElasticBulk => Some(("authorization", format!("ApiKey {token}"))),
        }
    }

    /// Whether the receiver accepted the whole batch. A bulk request answers 200 even
    /// when items failed, so its items are checked; an item that already exists (409,
    /// a redelivery) counts as accepted.
    #[must_use]
    pub fn accepted(self, status: u16, body: &[u8]) -> bool {
        if !(200..300).contains(&status) {
            return false;
        }
        match self {
            Self::ElasticBulk => {
                let Ok(reply) = serde_json::from_slice::<Value>(body) else {
                    return false;
                };
                reply["errors"] == false
                    || reply["items"].as_array().is_some_and(|items| {
                        items.iter().all(|i| {
                            let status = i["create"]["status"].as_u64().unwrap_or(0);
                            (200..300).contains(&status) || status == 409
                        })
                    })
            }
            _ => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries() -> Vec<Value> {
        vec![
            json!({"tenant_id": "acme", "sequence": 7, "kind": "run_admitted", "emitted_at": "2026-11-26T10:00:00Z",
                "payload": {"email": "masked:hmac-sha256:ab"}}),
            json!({"tenant_id": "acme", "sequence": 8, "kind": "revocation", "emitted_at": "2026-11-26T10:00:01Z", "payload": {}}),
        ]
    }

    #[test]
    fn splunk_gets_one_event_per_entry_with_its_time() {
        let (kind, body) = SinkFormat::SplunkHec.encode("siem", "acme", 7, 8, &entries());
        assert_eq!(kind, "application/json");
        let lines: Vec<Value> = body
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_slice(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["time"], 1_795_687_200);
        assert_eq!(
            lines[0]["event"]["payload"]["email"], "masked:hmac-sha256:ab",
            "masking is kept"
        );
        assert_eq!(
            SinkFormat::SplunkHec.auth_header("tok"),
            Some(("authorization", "Splunk tok".into()))
        );
    }

    #[test]
    fn datadog_gets_tagged_logs() {
        let (_, body) = SinkFormat::Datadog.encode("siem", "acme", 7, 8, &entries());
        let logs: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(logs[1]["ddtags"], "tenant:acme,kind:revocation,sink:siem");
        assert_eq!(logs[1]["contextos"]["sequence"], 8);
        assert_eq!(SinkFormat::Datadog.auth_header("k").unwrap().0, "dd-api-key");
    }

    #[test]
    fn elastic_creates_by_tenant_and_sequence_and_checks_items() {
        let (kind, body) = SinkFormat::ElasticBulk.encode("siem", "acme", 7, 8, &entries());
        assert_eq!(kind, "application/x-ndjson");
        let text = String::from_utf8(body).unwrap();
        assert!(text.starts_with("{\"create\":{\"_id\":\"acme:7\"}}\n"), "{text}");
        assert_eq!(text.lines().count(), 4);
        let ok = br#"{"errors": false, "items": []}"#;
        let redelivered = br#"{"errors": true, "items": [{"create": {"status": 201}}, {"create": {"status": 409}}]}"#;
        let failed = br#"{"errors": true, "items": [{"create": {"status": 201}}, {"create": {"status": 400}}]}"#;
        assert!(SinkFormat::ElasticBulk.accepted(200, ok));
        assert!(SinkFormat::ElasticBulk.accepted(200, redelivered));
        assert!(!SinkFormat::ElasticBulk.accepted(200, failed));
        assert!(!SinkFormat::ElasticBulk.accepted(200, b"not json"));
        assert!(!SinkFormat::Datadog.accepted(403, b""));
        assert!(SinkFormat::Datadog.accepted(202, b""));
    }
}

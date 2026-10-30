//! Upstream drift: a pinned capability names an upstream tool whose reviewed
//! definition can change without its name changing (an MCP server is upgraded or
//! compromised). A capability whose manifest pins `upstream_tool_digest` is checked
//! against the provider's current definition. While it differs, or the tool is gone,
//! the capability refuses calls with `upstream_tool_drifted` until the manifest is
//! reviewed and re-pinned. A changed description (`upstream_description_digest`) is
//! reported but not refused: agents see the manifest's reviewed description, never
//! the upstream one.
//!
//! An unreachable provider keeps the last verdict. Its calls fail on their own, and
//! refusing them for unavailability would hide which problem it is.

use std::collections::{BTreeMap, HashSet};

use contextos_contract::canonical::sha256_canonical;
use contextos_store::{AppendLog, DocumentStore};
use serde_json::{Value, json};

use crate::Gateway;

/// The digest pinned as `upstream_tool_digest`: what a call means (name, schemas,
/// annotations), canonicalized (RFC 8785).
#[must_use]
pub fn tool_digest(tool: &Value) -> Option<String> {
    sha256_canonical(&json!({
        "name": tool["name"],
        "inputSchema": tool["inputSchema"],
        "outputSchema": tool["outputSchema"],
        "annotations": tool["annotations"],
    }))
    .ok()
}

/// The digest pinned as `upstream_description_digest`.
#[must_use]
pub fn description_digest(tool: &Value) -> Option<String> {
    sha256_canonical(&tool["description"]).ok()
}

/// What one check found for one pinned capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamStatus {
    Matches,
    /// The schemas or annotations changed, or the tool is gone: calls are refused.
    Drifted,
    /// Only the description changed: reported, calls continue.
    DescriptionChanged,
    /// The provider could not be asked; the previous verdict stands.
    Unavailable,
}

impl UpstreamStatus {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Matches => "matches",
            Self::Drifted => "drifted",
            Self::DescriptionChanged => "description_changed",
            Self::Unavailable => "unavailable",
        }
    }
}

/// The capability ids currently refused for drift.
#[derive(Debug, Default)]
pub(crate) struct DriftState(std::sync::RwLock<HashSet<String>>);

impl DriftState {
    pub(crate) fn drifted(&self, capability_id: &str) -> bool {
        self.0.read().is_ok_and(|set| set.contains(capability_id))
    }

    fn set(&self, capability_id: &str, drifted: bool) {
        if let Ok(mut set) = self.0.write() {
            if drifted {
                set.insert(capability_id.to_owned());
            } else {
                set.remove(capability_id);
            }
        }
    }
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// Checks every capability that pins an upstream digest against its provider's
    /// current tool definitions, one listing per adapter, and updates which are
    /// refused. Returns each checked capability's status.
    pub async fn check_upstream_tools(&self) -> BTreeMap<String, UpstreamStatus> {
        let mut by_adapter: BTreeMap<&str, Vec<&crate::CapabilityManifest>> = BTreeMap::new();
        for manifest in self.manifests.values() {
            if manifest.upstream_tool_digest.is_some() || manifest.upstream_description_digest.is_some() {
                by_adapter.entry(&manifest.adapter_id).or_default().push(manifest);
            }
        }
        let mut statuses = BTreeMap::new();
        for (adapter_id, manifests) in by_adapter {
            let listed = match self.adapters.get(adapter_id) {
                Some(adapter) => adapter.upstream_tools().await,
                None => None,
            };
            let tools = match listed {
                Some(Ok(tools)) => tools,
                Some(Err(error)) => {
                    tracing::warn!(adapter = adapter_id, error = %error.message, "upstream tool check failed");
                    for manifest in manifests {
                        statuses.insert(manifest.capability_id.clone(), UpstreamStatus::Unavailable);
                    }
                    continue;
                }
                None => continue,
            };
            for manifest in manifests {
                let tool = tools.iter().find(|t| t["name"] == manifest.protocol_tool.as_str());
                let schema_drift = manifest
                    .upstream_tool_digest
                    .as_ref()
                    .is_some_and(|pinned| tool.and_then(tool_digest).as_ref() != Some(pinned));
                let description_drift = manifest
                    .upstream_description_digest
                    .as_ref()
                    .is_some_and(|pinned| tool.and_then(description_digest).as_ref() != Some(pinned));
                let status = if schema_drift || tool.is_none() {
                    UpstreamStatus::Drifted
                } else if description_drift {
                    UpstreamStatus::DescriptionChanged
                } else {
                    UpstreamStatus::Matches
                };
                let refused = status == UpstreamStatus::Drifted;
                if refused != self.drift.drifted(&manifest.capability_id) {
                    tracing::warn!(
                        capability = %manifest.capability_id,
                        status = status.as_str(),
                        "upstream tool definition {}",
                        if refused { "changed; refusing calls until re-pinned" } else { "matches its pin again" }
                    );
                }
                self.drift.set(&manifest.capability_id, refused);
                statuses.insert(manifest.capability_id.clone(), status);
            }
        }
        statuses
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tool_digest_covers_meaning_and_ignores_the_description() {
        let tool = json!({"name": "issue_refund", "description": "Refunds an order.",
            "inputSchema": {"type": "object"}, "annotations": {"destructiveHint": true}});
        let mut reworded = tool.clone();
        reworded["description"] = json!("Issues a refund.");
        assert_eq!(tool_digest(&tool), tool_digest(&reworded));
        assert_ne!(description_digest(&tool), description_digest(&reworded));
        let mut widened = tool.clone();
        widened["inputSchema"]["additionalProperties"] = json!(true);
        assert_ne!(tool_digest(&tool), tool_digest(&widened));
        let mut relabelled = tool.clone();
        relabelled["annotations"]["destructiveHint"] = json!(false);
        assert_ne!(tool_digest(&relabelled), tool_digest(&tool));
    }
}

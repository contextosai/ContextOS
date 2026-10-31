//! Periodic upstream drift checks and the `--pin-mcp-tools` report (see
//! [`contextos_gateway::upstream_drift`]).
//!
//! Every replica checks at startup and then every [`CHECK_INTERVAL`] (every
//! [`RETRY_INTERVAL`] while a pinned tool is still unverified), because each
//! keeps its own verdict and refuses drifted capabilities itself. The gauge
//! `contextos_upstream_tool{capability,status}` is 1 for each checked capability's
//! current status. Capabilities are pinned at startup, so the label is bounded.

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

use contextos_gateway::Gateway;
use contextos_gateway::upstream_drift::{UpstreamStatus, description_digest, tool_digest};
use contextos_store::{AppendLog, DocumentStore};

use crate::metrics::Metrics;

pub const CHECK_INTERVAL: Duration = Duration::from_secs(300);
/// How soon to check again while a pinned tool is unverified (its calls are refused).
pub const RETRY_INTERVAL: Duration = Duration::from_secs(15);

/// The gauge exposition for one check.
#[must_use]
pub fn exposition(statuses: &std::collections::BTreeMap<String, UpstreamStatus>) -> String {
    let mut out = String::from(
        "# HELP contextos_upstream_tool Each pinned capability's upstream tool status (1 for the current one).\n\
         # TYPE contextos_upstream_tool gauge\n",
    );
    for (capability, status) in statuses {
        let _ = writeln!(
            out,
            "contextos_upstream_tool{{capability=\"{capability}\",status=\"{}\"}} 1",
            status.as_str()
        );
    }
    out
}

/// Checks now and every [`CHECK_INTERVAL`] on this replica.
pub async fn run<S, L>(gateway: Arc<Gateway<S, L>>, metrics: Arc<Metrics>)
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    loop {
        let statuses = gateway.check_upstream_tools().await;
        if !statuses.is_empty() {
            metrics.set_upstream(Some(exposition(&statuses)));
        }
        let wait = if gateway.upstream_unverified() {
            RETRY_INTERVAL
        } else {
            CHECK_INTERVAL
        };
        tokio::time::sleep(wait).await;
    }
}

/// One line per capability on an MCP adapter: the digests to pin for its upstream
/// tool as it is now, for review in version control.
pub async fn pin_report(config: &crate::Config) -> Result<Vec<String>, String> {
    let setup = crate::runtime::dispatch_setup_from_config(config)?.ok_or("no dispatch gateway is configured")?;
    let mut lines = Vec::new();
    for (adapter_id, adapter) in &setup.adapters {
        let manifests: Vec<_> = setup.manifests.iter().filter(|m| &m.adapter_id == adapter_id).collect();
        if manifests.is_empty() {
            continue;
        }
        let Some(listed) = adapter.upstream_tools().await else {
            continue;
        };
        let tools = listed.map_err(|e| format!("{adapter_id}: {}", e.message))?;
        for manifest in manifests {
            match tools.iter().find(|t| t["name"] == manifest.protocol_tool.as_str()) {
                Some(tool) => lines.push(format!(
                    "{}: \"upstream_tool_digest\": \"{}\", \"upstream_description_digest\": \"{}\"",
                    manifest.capability_id,
                    tool_digest(tool).unwrap_or_default(),
                    description_digest(tool).unwrap_or_default()
                )),
                None => lines.push(format!(
                    "{}: upstream tool {} not listed by {adapter_id}",
                    manifest.capability_id, manifest.protocol_tool
                )),
            }
        }
    }
    Ok(lines)
}

/// `--check-config` notes for effectful MCP capabilities without a pin.
#[must_use]
pub fn unpinned(config: &crate::Config, setup: &crate::runtime::DispatchSetup) -> Vec<String> {
    setup
        .manifests
        .iter()
        .filter(|m| m.action_risk.effect != contextos_contract::types::ActionEffect::None)
        .filter(|m| m.upstream_tool_digest.is_none())
        .filter(|m| {
            config
                .adapters
                .iter()
                .any(|a| a.id == m.adapter_id && a.kind == crate::config::AdapterKind::Mcp)
        })
        .map(|m| {
            format!(
                "{} is effectful on an MCP adapter and pins no upstream_tool_digest: upstream changes are not detected",
                m.capability_id
            )
        })
        .collect()
}

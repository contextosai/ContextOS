//! Quarantine for drifted upstream tools: once a pinned tool's definition is seen to
//! differ from its review, the capability stays refused (`upstream_tool_quarantined`)
//! until a person acts, even if the provider changes it back.
//!
//! Without quarantine a provider that alternates between the reviewed definition and
//! another one could be served the moment a check sees the reviewed one again, and
//! calls between checks would reach whichever was live. The quarantine is kept in the
//! store, so it holds on every replica and across restarts, and is keyed to the pin it
//! was raised under. It ends in one of two ways:
//!
//! - **Re-pin.** A reviewed manifest with a new `upstream_tool_digest` is loaded. The
//!   quarantine no longer applies to the new pin and is dropped at the next check.
//! - **Release.** An operator (`control`) releases it with a reason, after confirming
//!   the change was benign. The release is refused while the tool still differs from
//!   its pin, and is audited as `upstream_quarantine_released`.
//!
//! `[guards] quarantine_drifted_tools = false` restores the earlier behaviour, where
//! a drifted tool is served again as soon as it matches its pin.

use std::collections::BTreeMap;

use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore};
use serde_json::{Value, json};

use crate::upstream_drift::{UpstreamStatus, tool_digest};
use crate::{Gateway, GatewayError};

/// Quarantines are deployment-wide: capabilities are, too.
const SCOPE: &str = "*";

fn key() -> DocKey {
    DocKey::new(SCOPE, DocKind::ToolQuarantine, "quarantine")
}

#[derive(Debug, thiserror::Error)]
pub enum QuarantineError {
    #[error("no such quarantined capability")]
    NotQuarantined,
    #[error("the upstream tool still differs from its pin")]
    StillDrifted,
    #[error("a reason of 1 to 1024 bytes is required")]
    Invalid,
    #[error(transparent)]
    Gateway(#[from] GatewayError),
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// Keeps drifted tools refused until re-pinned or released (the default).
    pub fn set_quarantine_drifted_tools(&mut self, on: bool) {
        self.quarantine_drifted = on;
    }

    async fn quarantine_doc(&self) -> Result<(Option<u64>, BTreeMap<String, Value>), GatewayError> {
        let current = self.store.get(&key()).await?;
        let tools = current
            .as_ref()
            .and_then(|d| serde_json::from_value(d.body["tools"].clone()).ok())
            .unwrap_or_default();
        Ok((current.map(|d| d.revision), tools))
    }

    /// The quarantines that apply to the pins loaded now.
    fn current(&self, tools: BTreeMap<String, Value>) -> BTreeMap<String, Value> {
        tools
            .into_iter()
            .filter(|(capability, q)| {
                self.manifests
                    .get(capability)
                    .and_then(|m| m.upstream_tool_digest.as_deref())
                    .is_some_and(|pin| q["pinned"] == pin)
            })
            .collect()
    }

    /// After a check: quarantines each drifted capability, drops quarantines for pins no
    /// longer loaded, and refreshes which capabilities this replica refuses.
    pub(crate) async fn sync_quarantine(
        &self,
        statuses: &mut BTreeMap<String, UpstreamStatus>,
        observed: &BTreeMap<String, Option<String>>,
    ) -> Result<(), GatewayError> {
        if !self.quarantine_drifted {
            return Ok(());
        }
        let mut synced = false;
        for _ in 0..8 {
            let (revision, stored) = self.quarantine_doc().await?;
            let mut tools = self.current(stored.clone());
            let now = self.now();
            for (capability, status) in statuses.iter() {
                let pin = self
                    .manifests
                    .get(capability)
                    .and_then(|m| m.upstream_tool_digest.clone());
                if *status == UpstreamStatus::Drifted
                    && let Some(pin) = pin
                    && !tools.contains_key(capability)
                {
                    tracing::warn!(capability = %capability, "upstream tool quarantined until re-pinned or released");
                    tools.insert(
                        capability.clone(),
                        json!({"pinned": pin, "observed": observed.get(capability).cloned().flatten(), "since": now}),
                    );
                }
            }
            if tools == stored {
                self.drift.set_quarantined(tools.keys().cloned().collect());
                synced = true;
                break;
            }
            let body = json!({"tools": tools});
            let written = match revision {
                None => self.store.create(&key(), &body).await.map(|_| ()),
                Some(r) => self.store.compare_and_swap(&key(), r, &body).await.map(|_| ()),
            };
            match written {
                Ok(()) => {
                    self.drift.set_quarantined(tools.keys().cloned().collect());
                    synced = true;
                    break;
                }
                Err(e) if e.is_conflict() => {}
                Err(e) => return Err(e.into()),
            }
        }
        if !synced {
            // Other replicas kept winning the write. Refuse what the store holds now and
            // what this check found drifted; the next check writes it.
            tracing::warn!("quarantine not written after repeated conflicts; refusing locally until the next check");
            let (_, stored) = self.quarantine_doc().await?;
            let mut refused: std::collections::HashSet<String> = self.current(stored).into_keys().collect();
            refused.extend(
                statuses
                    .iter()
                    .filter(|(_, s)| **s == UpstreamStatus::Drifted)
                    .map(|(c, _)| c.clone()),
            );
            refused.extend(self.drift.quarantined_set());
            self.drift.set_quarantined(refused);
        }
        for (capability, status) in statuses.iter_mut() {
            if self.drift.quarantined(capability) && *status != UpstreamStatus::Drifted {
                *status = UpstreamStatus::Quarantined;
            }
        }
        Ok(())
    }

    /// The quarantines in force: capability, the pin, what was observed, since when.
    pub async fn quarantined_tools(&self) -> Result<Vec<Value>, GatewayError> {
        let (_, stored) = self.quarantine_doc().await?;
        Ok(self
            .current(stored)
            .into_iter()
            .map(|(capability, mut q)| {
                q["capability_id"] = json!(capability);
                q
            })
            .collect())
    }

    /// Releases one quarantine after checking the tool matches its pin again.
    pub async fn release_quarantine(
        &self,
        tenant: &str,
        capability_id: &str,
        reason: &str,
        operator: &str,
    ) -> Result<Value, QuarantineError> {
        if reason.trim().is_empty() || reason.len() > 1024 {
            return Err(QuarantineError::Invalid);
        }
        let (_, stored) = self.quarantine_doc().await?;
        let Some(held) = self.current(stored).remove(capability_id) else {
            return Err(QuarantineError::NotQuarantined);
        };
        let statuses = self.check_upstream_tools().await;
        if !matches!(
            statuses.get(capability_id),
            Some(UpstreamStatus::Quarantined | UpstreamStatus::Matches | UpstreamStatus::DescriptionChanged)
        ) {
            return Err(QuarantineError::StillDrifted);
        }
        let record = json!({"capability_id": capability_id, "pinned": held["pinned"], "observed": held["observed"],
            "since": held["since"], "reason": reason, "operator": operator});
        // Audited before it takes effect.
        self.audit
            .append(tenant, "upstream_quarantine_released", record.clone(), &self.now())
            .await
            .map_err(GatewayError::from)?;
        for _ in 0..8 {
            let (revision, mut tools) = self.quarantine_doc().await?;
            if tools.remove(capability_id).is_none() {
                break;
            }
            let Some(revision) = revision else { break };
            match self
                .store
                .compare_and_swap(&key(), revision, &json!({"tools": tools}))
                .await
            {
                Ok(_) => {
                    let current = self.current(tools);
                    self.drift.set_quarantined(current.keys().cloned().collect());
                    return Ok(record);
                }
                Err(e) if e.is_conflict() => {}
                Err(e) => return Err(GatewayError::from(e).into()),
            }
        }
        Ok(record)
    }
}

/// What a check observed for a pinned tool: its digest, or `None` when it is gone.
#[must_use]
pub fn observed(tool: Option<&Value>) -> Option<String> {
    tool.and_then(tool_digest)
}

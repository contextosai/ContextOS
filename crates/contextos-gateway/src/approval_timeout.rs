//! Approval timeouts: an approval request nobody decides is handed to a human, or
//! refused, instead of leaving its run waiting without anyone knowing.
//!
//! With `[guards.approval_timeout]`, each approval request the gateway makes for a
//! covered capability is watched. The governance sweep (on the leader) finds requests
//! with no redemption `timeout_seconds` after the gateway asked, audits
//! `approval_timed_out` with how long it waited, and then:
//!
//! - `on_timeout = "escalate"` (the default) opens an escalation for the run, so the
//!   request shows in the escalation inbox; a decision that arrives later still counts.
//! - `on_timeout = "deny"` also refuses any later decision on that request
//!   (`approval_timed_out`): the run must start a new operation if it still needs the
//!   effect.
//!
//! Time is the gateway's own, from when it first asked (see [`crate::approval_events`]).
//! At most [`MAX_TRACKED`] requests per tenant are watched; past that new requests are
//! logged and not timed out until older ones leave.

use contextos_contract::validation::elapsed_millis;
use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::admission::RunAdmission;
use crate::approval_events::requested_key;
use crate::{Gateway, GatewayError};

pub const MIN_TIMEOUT_SECONDS: u64 = 60;
pub const MAX_TIMEOUT_SECONDS: u64 = 7 * 86_400;
/// Requests watched per tenant at most.
pub const MAX_TRACKED: usize = 10_000;
/// Compare-and-swap attempts on the watch list before giving up for this call.
const ATTEMPTS: usize = 8;

/// What a timed-out request becomes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OnTimeout {
    /// Open an escalation; a later decision still counts.
    #[default]
    Escalate,
    /// Refuse any later decision on the request.
    Deny,
}

/// `[guards.approval_timeout]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TimeoutPolicy {
    /// Seconds after the gateway asked for an approval with no redemption, 60 to
    /// 604800 (seven days).
    pub timeout_seconds: u64,
    #[serde(default)]
    pub on_timeout: OnTimeout,
    /// Applies to approvals of these capabilities; every approval when empty.
    #[serde(default)]
    pub capabilities: Vec<String>,
}

impl TimeoutPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if !(MIN_TIMEOUT_SECONDS..=MAX_TIMEOUT_SECONDS).contains(&self.timeout_seconds) {
            return Err(format!(
                "approval_timeout timeout_seconds must be {MIN_TIMEOUT_SECONDS}..={MAX_TIMEOUT_SECONDS}"
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn applies(&self, capability_id: &str) -> bool {
        self.capabilities.is_empty() || self.capabilities.iter().any(|c| c == capability_id)
    }
}

fn watch_key(tenant_id: &str) -> DocKey {
    DocKey::new(tenant_id, DocKind::ApprovalTimeouts, "open")
}

fn watched(body: Option<&Value>) -> Vec<String> {
    body.and_then(|b| b["ids"].as_array())
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect()
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// Times out approval requests nobody decides (see [`crate::approval_timeout`]).
    pub fn set_approval_timeout(&mut self, policy: Option<TimeoutPolicy>) {
        self.approval_timeout = policy;
    }

    /// Changes the watch list with `edit` (which returns `false` to leave it as is).
    async fn edit_watch(&self, tenant_id: &str, edit: impl Fn(&mut Vec<String>) -> bool) -> Result<(), GatewayError> {
        let key = watch_key(tenant_id);
        for _ in 0..ATTEMPTS {
            let current = self.store.get(&key).await?;
            let mut ids = watched(current.as_ref().map(|c| &c.body));
            if !edit(&mut ids) {
                return Ok(());
            }
            let body = json!({"ids": ids});
            let written = match &current {
                None => self.store.create(&key, &body).await.map(|_| ()),
                Some(c) => self.store.compare_and_swap(&key, c.revision, &body).await.map(|_| ()),
            };
            match written {
                Ok(()) => return Ok(()),
                Err(e) if e.is_conflict() => {}
                Err(e) => return Err(e.into()),
            }
        }
        tracing::warn!(
            tenant_id,
            "approval timeout watch list is contended; will retry next time"
        );
        Ok(())
    }

    /// Watches an approval request just recorded, if a timeout covers its capability.
    pub(crate) async fn track_approval(
        &self,
        tenant_id: &str,
        request_id: &str,
        capability_id: &str,
    ) -> Result<(), GatewayError> {
        if !self.approval_timeout.as_ref().is_some_and(|p| p.applies(capability_id)) {
            return Ok(());
        }
        self.edit_watch(tenant_id, |ids| {
            if ids.iter().any(|id| id == request_id) {
                return false;
            }
            if ids.len() >= MAX_TRACKED {
                tracing::warn!(request_id, "approval timeout watch list is full; request not timed out");
                return false;
            }
            ids.push(request_id.to_owned());
            true
        })
        .await
    }

    /// Whether a decision on the request in `material` comes too late: the request timed
    /// out and the timeout denies late decisions.
    pub(crate) async fn approval_too_late(
        &self,
        admission: &RunAdmission,
        material: Option<&Value>,
    ) -> Result<bool, GatewayError> {
        let request_id = material.map_or("", |m| m["request"]["approval_request_id"].as_str().unwrap_or(""));
        self.request_timed_out(admission, request_id).await
    }

    /// Whether request `request_id` timed out and the timeout denies late decisions.
    pub(crate) async fn request_timed_out(
        &self,
        admission: &RunAdmission,
        request_id: &str,
    ) -> Result<bool, GatewayError> {
        if request_id.is_empty()
            || self
                .approval_timeout
                .as_ref()
                .is_none_or(|p| p.on_timeout != OnTimeout::Deny)
        {
            return Ok(false);
        }
        let recorded = self.store.get(&requested_key(&admission.tenant_id, request_id)).await?;
        Ok(recorded.is_some_and(|r| r.body["timed_out_at"].is_string()))
    }

    /// Times out watched requests of `tenant` with no redemption past the timeout,
    /// examining at most `limit`, oldest first. Returns how many timed out.
    pub async fn expire_approvals(&self, tenant: &str, limit: usize) -> Result<usize, GatewayError> {
        let Some(policy) = self.approval_timeout.clone() else {
            return Ok(0);
        };
        let ids = watched(self.store.get(&watch_key(tenant)).await?.as_ref().map(|c| &c.body));
        let now = self.now();
        let mut done = Vec::new();
        let mut timed_out = 0;
        for id in ids.iter().take(limit) {
            match self.examine_request(tenant, id, &policy, &now).await? {
                Examined::Waiting => {}
                Examined::Settled => done.push(id.clone()),
                Examined::TimedOut => {
                    timed_out += 1;
                    done.push(id.clone());
                }
            }
        }
        if !done.is_empty() {
            self.edit_watch(tenant, |ids| {
                ids.retain(|id| !done.contains(id));
                true
            })
            .await?;
        }
        Ok(timed_out)
    }

    async fn examine_request(
        &self,
        tenant: &str,
        id: &str,
        policy: &TimeoutPolicy,
        now: &str,
    ) -> Result<Examined, GatewayError> {
        let key = requested_key(tenant, id);
        let Some(requested) = self.store.get(&key).await? else {
            return Ok(Examined::Settled);
        };
        if requested.body["timed_out_at"].is_string() {
            return Ok(Examined::Settled);
        }
        let redemption = self
            .store
            .get(&DocKey::new(tenant, DocKind::ApprovalRedemption, id))
            .await?;
        if redemption.is_some_and(|r| r.body["operation_id"].is_string()) {
            return Ok(Examined::Settled);
        }
        let waited = requested.body["requested_at"]
            .as_str()
            .and_then(|at| elapsed_millis(at, now))
            .map_or(0, |ms| ms / 1000);
        if waited < policy.timeout_seconds {
            return Ok(Examined::Waiting);
        }
        let body = &requested.body;
        let on_timeout = serde_json::to_value(policy.on_timeout).unwrap_or(Value::Null);
        let facts = json!({"run_id": body["run_id"], "operation_id": body["operation_id"],
            "capability_id": body["capability_id"], "approval_request_id": id,
            "waited_seconds": waited, "on_timeout": on_timeout});
        // Audited before it is marked: a crash in between audits it again, never not at all.
        self.audit.append(tenant, "approval_timed_out", facts, now).await?;
        let mut marked = body.clone();
        marked["timed_out_at"] = json!(now);
        match self.store.compare_and_swap(&key, requested.revision, &marked).await {
            Ok(_) => {}
            Err(e) if e.is_conflict() => return Ok(Examined::Waiting),
            Err(e) => return Err(e.into()),
        }
        if policy.on_timeout == OnTimeout::Escalate {
            let run_id = body["run_id"].as_str().unwrap_or_default();
            let admission = self
                .store
                .get(&DocKey::new(tenant, DocKind::RunAdmission, run_id))
                .await?
                .and_then(|r| serde_json::from_value::<RunAdmission>(r.body).ok());
            if let Some(admission) = admission {
                let facts = json!({"operation_id": body["operation_id"], "capability_id": body["capability_id"],
                    "approval_request_id": id, "reason_codes": ["approval_timed_out"]});
                self.open_escalation_for(&admission, &format!("approval_timeout:{id}"), facts)
                    .await?;
            }
        }
        Ok(Examined::TimedOut)
    }
}

enum Examined {
    Waiting,
    Settled,
    TimedOut,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_timeout_is_bounded_and_scoped() {
        let mut policy = TimeoutPolicy {
            timeout_seconds: 900,
            on_timeout: OnTimeout::default(),
            capabilities: vec![],
        };
        assert!(policy.validate().is_ok());
        assert!(policy.applies("any.capability"));
        policy.capabilities = vec!["pay.refund".into()];
        assert!(policy.applies("pay.refund") && !policy.applies("crm.note"));
        policy.timeout_seconds = 30;
        assert!(policy.validate().is_err());
        policy.timeout_seconds = MAX_TIMEOUT_SECONDS + 1;
        assert!(policy.validate().is_err());
        assert_eq!(OnTimeout::default(), OnTimeout::Escalate);
    }
}

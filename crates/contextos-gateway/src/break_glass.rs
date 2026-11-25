//! Break-glass: a person with the `break_glass` scope lifts some runtime guards for
//! named capabilities for a short time, with a justification, during an incident.
//!
//! What it may lift is narrow on purpose: **change windows** (a freeze blocking an
//! urgent fix) and **open circuit breakers** (a rate stop during a recovery), each only
//! if `[guards.break_glass] lifts` allows it. It never lifts a revocation (a kill switch
//! or a breaker that revoked needs a restore), an approval, a budget, a shared ceiling,
//! a risk tier, an information-flow rule or tenant isolation; those decide every call
//! as before. A grant lasts at most `max_ttl_seconds` (one hour unless set lower), and
//! names its capabilities (no wildcard).
//!
//! Opening and closing are audited (`break_glass_opened`, `break_glass_closed`), and
//! every call a grant lets through is audited as `break_glass_used` with the guard it
//! lifted, so the post-incident review sees each one. Tower reports every grant until a
//! risk reviewer records its review.

use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{Gateway, GatewayError};

/// Grants kept per tenant (open, closed and expired) at most; the oldest closed or
/// expired ones are dropped first.
pub const MAX_GRANTS: usize = 256;
/// Capabilities one grant may name.
pub const MAX_CAPABILITIES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Lift {
    ChangeWindows,
    CircuitBreakers,
}

impl Lift {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Lift::ChangeWindows => "change_windows",
            Lift::CircuitBreakers => "circuit_breakers",
        }
    }
}

fn max_ttl() -> u64 {
    3600
}
fn all_lifts() -> Vec<Lift> {
    vec![Lift::ChangeWindows, Lift::CircuitBreakers]
}

/// `[guards.break_glass]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BreakGlassPolicy {
    /// The longest a grant may last, 60 to 3600 seconds.
    #[serde(default = "max_ttl")]
    pub max_ttl_seconds: u64,
    /// What a grant may lift.
    #[serde(default = "all_lifts")]
    pub lifts: Vec<Lift>,
}

impl BreakGlassPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if !(60..=3600).contains(&self.max_ttl_seconds) {
            return Err("[guards.break_glass] max_ttl_seconds is 60 to 3600".into());
        }
        if self.lifts.is_empty() {
            return Err("[guards.break_glass] lifts names at least one guard".into());
        }
        Ok(())
    }
}

/// A grant to open.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRequest {
    pub capabilities: Vec<String>,
    pub lifts: Vec<Lift>,
    pub justification: String,
    pub ttl_seconds: u64,
    /// The incident this serves, for the review.
    #[serde(default)]
    pub incident_ref: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum BreakGlassError {
    #[error("break-glass is not configured")]
    Off,
    #[error("{0}")]
    Invalid(String),
    #[error("not found")]
    NotFound,
    #[error("{0}")]
    Conflict(String),
    #[error(transparent)]
    Gateway(#[from] GatewayError),
}

fn key(tenant_id: &str) -> DocKey {
    DocKey::new(tenant_id, DocKind::BreakGlass, "break_glass")
}

fn open_at(grant: &Value, now: &str) -> bool {
    grant["closed_at"].is_null() && grant["expires_at"].as_str().is_some_and(|e| e > now)
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// Allows break-glass grants under `policy` (see [`crate::break_glass`]).
    pub fn set_break_glass(&mut self, policy: Option<BreakGlassPolicy>) {
        self.break_glass = policy;
    }

    /// The tenant's grants, newest first.
    pub async fn break_glass_grants(&self, tenant_id: &str) -> Result<Vec<Value>, GatewayError> {
        let mut grants = self
            .store
            .get(&key(tenant_id))
            .await?
            .and_then(|d| d.body["grants"].as_array().cloned())
            .unwrap_or_default();
        grants.reverse();
        Ok(grants)
    }

    /// Opens a grant (audited `break_glass_opened` before it takes effect).
    pub async fn open_break_glass(
        &self,
        tenant_id: &str,
        request: &GrantRequest,
        by: &str,
    ) -> Result<Value, BreakGlassError> {
        let policy = self.break_glass.as_ref().ok_or(BreakGlassError::Off)?;
        if request.justification.trim().len() < 20 || request.justification.len() > 2048 {
            return Err(BreakGlassError::Invalid(
                "a justification of 20 to 2048 characters is required".into(),
            ));
        }
        if request.capabilities.is_empty()
            || request.capabilities.len() > MAX_CAPABILITIES
            || request
                .capabilities
                .iter()
                .any(|c| c.is_empty() || c.contains('*') || c.len() > 256)
        {
            return Err(BreakGlassError::Invalid(format!(
                "name 1 to {MAX_CAPABILITIES} capabilities by id (no wildcards)"
            )));
        }
        if request.lifts.is_empty() || request.lifts.iter().any(|l| !policy.lifts.contains(l)) {
            return Err(BreakGlassError::Invalid(format!(
                "lifts must be among {:?}",
                policy.lifts.iter().map(|l| l.as_str()).collect::<Vec<_>>()
            )));
        }
        if request.ttl_seconds == 0 || request.ttl_seconds > policy.max_ttl_seconds {
            return Err(BreakGlassError::Invalid(format!(
                "ttl_seconds is 1 to {}",
                policy.max_ttl_seconds
            )));
        }
        let now = self.now();
        let expires_at = contextos_contract::validation::add_contract_seconds(&now, request.ttl_seconds)
            .ok_or_else(|| BreakGlassError::Invalid("ttl out of range".into()))?;
        let grant = json!({"grant_id": self.new_id("bg"), "capabilities": request.capabilities,
            "lifts": request.lifts, "justification": request.justification, "incident_ref": request.incident_ref,
            "opened_by": by, "opened_at": now, "expires_at": expires_at, "closed_at": null});
        self.audit
            .append(tenant_id, "break_glass_opened", grant.clone(), &now)
            .await
            .map_err(GatewayError::from)?;
        let doc = key(tenant_id);
        for _ in 0..32 {
            let current = self.store.get(&doc).await.map_err(GatewayError::from)?;
            let mut grants = current
                .as_ref()
                .and_then(|c| c.body["grants"].as_array().cloned())
                .unwrap_or_default();
            while grants.len() >= MAX_GRANTS {
                match grants.iter().position(|g| !open_at(g, &now)) {
                    Some(i) => {
                        grants.remove(i);
                    }
                    None => return Err(BreakGlassError::Conflict("too many open break-glass grants".into())),
                }
            }
            grants.push(grant.clone());
            let body = json!({"grants": grants});
            let written = match &current {
                None => self.store.create(&doc, &body).await.map(|_| ()),
                Some(c) => self.store.compare_and_swap(&doc, c.revision, &body).await.map(|_| ()),
            };
            match written {
                Ok(()) => return Ok(grant),
                Err(e) if e.is_conflict() => {}
                Err(e) => return Err(GatewayError::from(e).into()),
            }
        }
        Err(BreakGlassError::Conflict("too much contention".into()))
    }

    /// Closes a grant before it expires (audited `break_glass_closed`).
    pub async fn close_break_glass(&self, tenant_id: &str, grant_id: &str, by: &str) -> Result<Value, BreakGlassError> {
        let doc = key(tenant_id);
        let now = self.now();
        let mut audited = false;
        for _ in 0..32 {
            let current = self
                .store
                .get(&doc)
                .await
                .map_err(GatewayError::from)?
                .ok_or(BreakGlassError::NotFound)?;
            let mut grants = current.body["grants"].as_array().cloned().unwrap_or_default();
            let grant = grants
                .iter_mut()
                .find(|g| g["grant_id"] == grant_id)
                .ok_or(BreakGlassError::NotFound)?;
            if !open_at(grant, &now) {
                return Err(BreakGlassError::Conflict(
                    "the grant is already closed or expired".into(),
                ));
            }
            if !audited {
                self.audit
                    .append(
                        tenant_id,
                        "break_glass_closed",
                        json!({"grant_id": grant_id, "closed_by": by}),
                        &now,
                    )
                    .await
                    .map_err(GatewayError::from)?;
                audited = true;
            }
            grant["closed_at"] = json!(now);
            grant["closed_by"] = json!(by);
            let closed = grant.clone();
            match self
                .store
                .compare_and_swap(&doc, current.revision, &json!({"grants": grants}))
                .await
            {
                Ok(_) => return Ok(closed),
                Err(e) if e.is_conflict() => {}
                Err(e) => return Err(GatewayError::from(e).into()),
            }
        }
        Err(BreakGlassError::Conflict("too much contention".into()))
    }

    /// The open grant that lifts `lift` for `capability` at `now`, if any.
    pub(crate) async fn break_glass_for(
        &self,
        tenant_id: &str,
        capability: &str,
        lift: Lift,
        now: &str,
    ) -> Result<Option<String>, GatewayError> {
        let Some(policy) = &self.break_glass else {
            return Ok(None);
        };
        if !policy.lifts.contains(&lift) {
            return Ok(None);
        }
        let grants = self.break_glass_grants(tenant_id).await?;
        Ok(grants
            .iter()
            .find(|g| {
                open_at(g, now)
                    && g["capabilities"]
                        .as_array()
                        .is_some_and(|c| c.iter().any(|x| x == capability))
                    && g["lifts"]
                        .as_array()
                        .is_some_and(|l| l.iter().any(|x| x == lift.as_str()))
            })
            .and_then(|g| g["grant_id"].as_str().map(str::to_owned)))
    }
}

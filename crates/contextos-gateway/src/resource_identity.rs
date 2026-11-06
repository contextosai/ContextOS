//! Canonical resource identity for shared guarantees.
//!
//! A guarantee's ledger is keyed by the resource identifier the call's arguments name.
//! With `exact` matching, `ord_881` and `ORD-881` are two ledgers, each with its own
//! limit. A guarantee may name how identifiers are made canonical first:
//!
//! - `exact` (the default): the identifier as extracted.
//! - `ascii_casefold`: ASCII letters lowercased, for systems whose identifiers ignore
//!   case.
//! - `provider`: the deployment's resource identity service maps the identifier to its
//!   canonical id at reservation time and names the evidence for that mapping. An
//!   unavailable service or a malformed answer withholds the call
//!   (`shared_guarantee_identity_unavailable`): nothing reserves on a guessed ledger.
//!
//! The canonicalizer is part of the pinned definition (left out when `exact`, so
//! existing definitions keep their digest), so replicas cannot disagree about it.

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use contextos_store::{AppendLog, DocumentStore};

use crate::shared_guarantees::{SharedGuarantee, identifier};
use crate::{Gateway, PortError, RunAdmission};

const MAX_EVIDENCE_REF: usize = 512;

/// How a guarantee makes a resource identifier canonical before keying its ledger.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResourceCanonicalizer {
    #[default]
    Exact,
    AsciiCasefold,
    Provider,
}

impl ResourceCanonicalizer {
    #[must_use]
    pub fn is_exact(&self) -> bool {
        *self == Self::Exact
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::AsciiCasefold => "ascii_casefold",
            Self::Provider => "provider",
        }
    }
}

/// The deployment's resource identity service.
#[async_trait]
pub trait ResourceIdentityProvider: Send + Sync {
    /// Answers `{"canonical_id", "evidence_ref"}` for an identifier a call named.
    async fn canonical(&self, admission: &RunAdmission, guarantee_id: &str, resource: &str)
    -> Result<Value, PortError>;
}

/// A resource identifier made canonical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Canonical {
    pub id: String,
    /// The provider's evidence for the mapping (`provider` only).
    pub evidence_ref: Option<String>,
}

impl Canonical {
    /// What the reservation's audit entry records about the mapping: nothing for
    /// `exact`, so existing entries are unchanged.
    pub fn audit(&self, rule: &SharedGuarantee, extracted_digest: &str) -> Option<Value> {
        (!rule.resource_canonicalizer.is_exact()).then(|| {
            json!({"canonicalizer": rule.resource_canonicalizer.as_str(), "extracted_digest": extracted_digest,
                "evidence_ref": self.evidence_ref})
        })
    }
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// The resource identity service guarantees with `resource_canonicalizer =
    /// "provider"` consult. Set it before [`Gateway::set_shared_guarantees`].
    pub fn set_resource_identity(&mut self, provider: Arc<dyn ResourceIdentityProvider>) {
        self.resource_identity = Some(provider);
    }

    pub(crate) fn has_resource_identity(&self) -> bool {
        self.resource_identity.is_some()
    }

    /// `Err` is the refusal reason for the call.
    pub(crate) async fn canonical_resource(
        &self,
        admission: &RunAdmission,
        rule: &SharedGuarantee,
        resource: &str,
    ) -> Result<Canonical, &'static str> {
        match rule.resource_canonicalizer {
            ResourceCanonicalizer::Exact => Ok(Canonical {
                id: resource.to_owned(),
                evidence_ref: None,
            }),
            ResourceCanonicalizer::AsciiCasefold => Ok(Canonical {
                id: resource.to_ascii_lowercase(),
                evidence_ref: None,
            }),
            ResourceCanonicalizer::Provider => {
                const UNAVAILABLE: &str = "shared_guarantee_identity_unavailable";
                let provider = self.resource_identity.as_ref().ok_or(UNAVAILABLE)?;
                let answer = provider
                    .canonical(admission, &rule.id, resource)
                    .await
                    .map_err(|_| UNAVAILABLE)?;
                let id = answer["canonical_id"]
                    .as_str()
                    .filter(|s| identifier(s))
                    .ok_or(UNAVAILABLE)?;
                let evidence_ref = answer["evidence_ref"]
                    .as_str()
                    .filter(|s| !s.is_empty() && s.len() <= MAX_EVIDENCE_REF)
                    .ok_or(UNAVAILABLE)?;
                Ok(Canonical {
                    id: id.to_owned(),
                    evidence_ref: Some(evidence_ref.to_owned()),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_is_left_out_of_the_definition_so_existing_digests_hold() {
        let rule = |canonicalizer| SharedGuarantee {
            id: "refunds".into(),
            capability_ids: vec!["adp.refund".into()],
            resource_pointer: "/order_id".into(),
            amount_pointer: "/amount".into(),
            limit: 100,
            unit: "minor".into(),
            resource_canonicalizer: canonicalizer,
            owner_route: None,
            owner_after_seconds: None,
        };
        let exact = serde_json::to_value(rule(ResourceCanonicalizer::Exact)).unwrap();
        assert!(exact.get("resource_canonicalizer").is_none());
        let folded = serde_json::to_value(rule(ResourceCanonicalizer::AsciiCasefold)).unwrap();
        assert_eq!(folded["resource_canonicalizer"], "ascii_casefold");
        let parsed: SharedGuarantee = serde_json::from_value(exact).unwrap();
        assert!(parsed.resource_canonicalizer.is_exact());
    }
}

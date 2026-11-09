//! One-way import of exposure created outside the runtime.
//!
//! Spending that happened before a resource was onboarded, or later through another
//! system (a refund issued from the legacy back office), reaches the ledger as an
//! imported row. It only adds committed exposure. Nothing here ever replenishes a
//! resource from an outside reading: raising capacity stays a definition change. An
//! import may take a resource past its limit; the resource then refuses every new
//! reservation and reports `over_limit`.
//!
//! Each row is audited (`shared_guarantee_imported`) before the ledger changes, so no
//! imported exposure is ever unaudited. A row retried after a crash between the two may
//! be audited twice; the ledger counts it once (idempotent per `import_id`).

use contextos_contract::validation::is_contract_timestamp;
use contextos_kernel::shared_exposure::{
    ExposureBinding, ExposureImport, MAX_EXACT_EXPOSURE, empty_exposure, exposure_summary, import_exposure,
};
use contextos_store::{AppendLog, Commit, DocKey, DocKind, DocumentStore, transact};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::shared_guarantees::{exposure_key, hash, identifier, pin};
use crate::{Gateway, GatewayError, ResourceCanonicalizer};

const MAX_TEXT: usize = 512;

/// One imported row: exposure `amount` on the canonical `resource`, as of `as_of`,
/// taken from `source` and backed by `evidence_ref`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportRow {
    pub import_id: String,
    pub resource: String,
    pub amount: u64,
    pub source: String,
    pub as_of: String,
    pub evidence_ref: String,
}

impl ImportRow {
    fn valid(&self) -> bool {
        let text = |s: &str| !s.is_empty() && s.len() <= MAX_TEXT && !s.chars().any(char::is_control);
        identifier(&self.import_id)
            && identifier(&self.resource)
            && self.amount > 0
            && self.amount <= MAX_EXACT_EXPOSURE
            && text(&self.source)
            && text(&self.evidence_ref)
            && is_contract_timestamp(&self.as_of)
    }
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// Imports one row into guarantee `guarantee_id`'s ledger for its resource. `Ok(Err)`
    /// is the row's refusal reason; `Ok(Ok)` is `{import_id, status, resource_digest,
    /// over_limit}` with `status` `imported` or `duplicate`.
    pub async fn import_shared_exposure(
        &self,
        tenant: &str,
        guarantee_id: &str,
        row: &ImportRow,
        imported_by: &str,
    ) -> Result<Result<Value, &'static str>, GatewayError> {
        let Some(rule) = self.shared_guarantees().iter().find(|r| r.id == guarantee_id) else {
            return Ok(Err("shared_guarantee_not_found"));
        };
        if !row.valid() {
            return Ok(Err("shared_guarantee_import_invalid"));
        }
        // Rows name the canonical resource; case folding is applied as reservations
        // apply it. A provider's canonical ids must already be what the row names.
        let resource = match rule.resource_canonicalizer {
            ResourceCanonicalizer::AsciiCasefold => row.resource.to_ascii_lowercase(),
            ResourceCanonicalizer::Exact | ResourceCanonicalizer::Provider => row.resource.clone(),
        };
        let definition = rule.definition();
        let definition_key = DocKey::new(tenant, DocKind::GuaranteeDefinition, &rule.id);
        if !pin(self.store.as_ref(), &definition_key, &definition).await? {
            return Ok(Err("shared_guarantee_definition_mismatch"));
        }
        let binding = ExposureBinding {
            guarantee_id: rule.id.clone(),
            definition_digest: hash(&definition)?,
            // A windowed guarantee's import counts in the window its reading is as of.
            resource_digest: hash(&crate::guarantee_sources::digest_input(
                &resource,
                crate::guarantee_sources::window_start(rule, &row.as_of),
            ))?,
            limit: rule.limit,
            unit: rule.unit.clone(),
        };
        let key = exposure_key(tenant, &rule.id, &binding.resource_digest)?;
        match self.store.create(&key, &empty_exposure(&binding)).await {
            Ok(_) => {}
            Err(e) if e.is_conflict() => {}
            Err(e) => return Err(e.into()),
        }
        let import = ExposureImport {
            import_id: row.import_id.clone(),
            amount: row.amount,
            row_digest: hash(&json!(row))?,
        };
        let current = self.store.get(&key).await?.map(|d| d.body).unwrap_or_default();
        let trial = import_exposure(&current, &binding, &import);
        if !trial.is_accepted() {
            return Ok(Err(refusal(trial.reason_codes.as_deref())));
        }
        if trial.state == current {
            return Ok(Ok(result(row, &binding, "duplicate", &current)));
        }
        self.audit
            .append(
                tenant,
                "shared_guarantee_imported",
                json!({"guarantee_id": rule.id, "binding": binding, "import_id": row.import_id,
                    "amount": row.amount, "source": row.source, "as_of": row.as_of,
                    "evidence_ref": row.evidence_ref, "row_digest": import.row_digest, "imported_by": imported_by}),
                &self.now(),
            )
            .await?;
        let commit = transact(self.store.as_ref(), &key, |state| {
            import_exposure(state, &binding, &import)
        })
        .await?;
        if let Commit::Rejected { reason_codes } = commit {
            return Ok(Err(refusal(Some(&reason_codes))));
        }
        let state = self.store.get(&key).await?.map(|d| d.body).unwrap_or_default();
        Ok(Ok(result(row, &binding, "imported", &state)))
    }
}

fn refusal(reasons: Option<&[String]>) -> &'static str {
    match reasons.and_then(<[String]>::first).map(String::as_str) {
        Some("shared_guarantee_import_mismatch") => "shared_guarantee_import_mismatch",
        Some("shared_guarantee_import_saturated") => "shared_guarantee_import_saturated",
        Some("shared_guarantee_import_invalid") => "shared_guarantee_import_invalid",
        Some("shared_guarantee_definition_mismatch") => "shared_guarantee_definition_mismatch",
        _ => "shared_guarantee_invalid",
    }
}

fn result(row: &ImportRow, binding: &ExposureBinding, status: &str, state: &Value) -> Value {
    json!({"import_id": row.import_id, "status": status, "resource_digest": binding.resource_digest,
        "over_limit": exposure_summary(state).is_some_and(|s| s["over_limit"] == true)})
}

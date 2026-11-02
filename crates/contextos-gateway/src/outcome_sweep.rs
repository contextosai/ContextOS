//! The governance sweep's pass over a tenant's open outcomes (see [`crate::outcomes`]).
//!
//! A pass reads at most `limit` entries of the tenant's open-outcome index, starting
//! after where the previous pass stopped (a cursor kept in the store, so a new leader
//! continues it) and wrapping around. So every open outcome is examined within
//! `ceil(open / limit)` passes, however many outcomes ahead of it are not yet due or
//! still wait for their effect: none can starve an overdue one. Each entry is brought
//! up to the operation ledger first, so an effect that was applied (or definitively
//! not) before a crash is found here too.

use contextos_contract::validation::compare_contract_times;
use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore};
use serde_json::{Value, json};

use crate::admission::RunAdmission;
use crate::outcomes::{ids, tenant_index};
use crate::{Gateway, GatewayError};

fn cursor_key(tenant: &str) -> DocKey {
    DocKey::new(tenant, DocKind::Outcome, "sweep_cursor")
}

/// The entries a pass reads: up to `limit`, starting after `after` (or at `offset`
/// when that entry has left the index), wrapping around once.
fn window(ids: &[String], after: Option<&str>, offset: usize, limit: usize) -> (Vec<String>, usize) {
    if ids.is_empty() || limit == 0 {
        return (Vec::new(), 0);
    }
    let start = after
        .and_then(|a| ids.iter().position(|id| id == a))
        .map_or(offset % ids.len(), |p| (p + 1) % ids.len());
    let count = limit.min(ids.len());
    let taken = (0..count).map(|i| ids[(start + i) % ids.len()].clone()).collect();
    (taken, (start + count) % ids.len())
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// Opens one escalation for each examined outcome past due, reading at most `limit`
    /// open outcomes from where the last pass stopped. Returns how many it opened.
    pub async fn escalate_missed_outcomes(&self, tenant: &str, limit: usize) -> Result<usize, GatewayError> {
        let index = ids(self.store.get(&tenant_index(tenant)).await?);
        let cursor = self.store.get(&cursor_key(tenant)).await?;
        let (after, offset) = cursor.as_ref().map_or((None, 0), |c| {
            (
                c.body["after"].as_str().map(str::to_owned),
                usize::try_from(c.body["offset"].as_u64().unwrap_or(0)).unwrap_or(0),
            )
        });
        let (batch, next_offset) = window(&index, after.as_deref(), offset, limit);
        let mut opened = 0;
        for id in &batch {
            opened += usize::from(self.examine_outcome(tenant, id).await?);
        }
        if let Some(last) = batch.last() {
            let next = json!({"after": last, "offset": next_offset});
            // Another sweeper moved it meanwhile: either cursor serves.
            let _ = match cursor {
                Some(c) => {
                    self.store
                        .compare_and_swap(&cursor_key(tenant), c.revision, &next)
                        .await
                }
                None => self.store.create(&cursor_key(tenant), &next).await,
            };
        }
        Ok(opened)
    }

    /// Examines one open outcome; whether it opened an escalation.
    async fn examine_outcome(&self, tenant: &str, id: &str) -> Result<bool, GatewayError> {
        let key = DocKey::new(tenant, DocKind::Outcome, id);
        let Some(doc) = self.store.get(&key).await? else {
            self.drop_from(tenant_index(tenant), id).await?;
            return Ok(false);
        };
        let run_id = doc.body["run_id"].as_str().unwrap_or_default().to_owned();
        let operation_id = doc.body["operation_id"].as_str().unwrap_or_default().to_owned();
        let admission = self
            .store
            .get(&DocKey::new(tenant, DocKind::RunAdmission, &run_id))
            .await?
            .and_then(|r| serde_json::from_value::<RunAdmission>(r.body).ok());
        let mut record = doc.body.clone();
        let mut revision = doc.revision;
        if record["state"] == "awaiting_effect" {
            let Some(admission) = &admission else {
                return Ok(false);
            };
            match self.sync_outcome(admission, &operation_id).await? {
                Some(synced) if synced["state"] == "pending" => {
                    let Some(current) = self.store.get(&key).await? else {
                        return Ok(false);
                    };
                    record = current.body;
                    revision = current.revision;
                }
                // Still waiting for its effect, or retired.
                _ => return Ok(false),
            }
        }
        if record["state"] != "pending" {
            self.drop_from(tenant_index(tenant), id).await?;
            return Ok(false);
        }
        let due = record["due_at"].as_str().unwrap_or_default();
        if compare_contract_times(&self.now(), due) == Some(std::cmp::Ordering::Less) {
            return Ok(false);
        }
        let Some(admission) = admission else {
            return Ok(false);
        };
        let facts = json!({"operation_id": operation_id, "capability_id": record["capability_id"],
            "action_digest": record["action_digest"], "witness": record["witness"],
            "postcondition": record["postcondition"], "due_at": due,
            "reason_codes": ["outcome_missed"]});
        let escalation_id = self
            .open_escalation_for(&admission, &format!("outcome:{operation_id}"), facts)
            .await?;
        let mut missed: Value = record.clone();
        missed["state"] = json!("missed");
        missed["escalation_id"] = json!(escalation_id);
        match self.store.compare_and_swap(&key, revision, &missed).await {
            Ok(_) => {
                self.drop_from(tenant_index(tenant), id).await?;
                Ok(true)
            }
            // Witnessed meanwhile: a later pass drops it.
            Err(e) if e.is_conflict() => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::window;

    #[test]
    fn passes_resume_after_the_last_entry_and_wrap_around() {
        let ids: Vec<String> = (0..5).map(|i| format!("o{i}")).collect();
        assert_eq!(window(&ids, None, 0, 2), (vec!["o0".into(), "o1".into()], 2));
        assert_eq!(window(&ids, Some("o1"), 2, 2), (vec!["o2".into(), "o3".into()], 4));
        assert_eq!(window(&ids, Some("o3"), 4, 2), (vec!["o4".into(), "o0".into()], 1));
        // The last entry read has left the index: resume at the stored offset.
        assert_eq!(window(&ids, Some("gone"), 3, 2), (vec!["o3".into(), "o4".into()], 0));
        assert_eq!(window(&ids, None, 0, 9).0.len(), 5, "never more than the index");
        assert_eq!(window(&[], None, 0, 2), (vec![], 0));
    }
}

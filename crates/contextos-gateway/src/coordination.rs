//! Advisory peer work, separate from effect authority and accepted child outputs.
//!
//! One bounded CAS document makes task dependencies and ownership atomic. RunState
//! eligibility reads are separate: requests already admitted may commit during a
//! concurrent lifecycle change. Expiring a work lease says nothing about effects.

use std::collections::{BTreeMap, HashSet};

use contextos_contract::canonical::{canonicalize, is_sha256_digest, sha256_canonical};
use contextos_contract::validation::{add_contract_seconds, compare_contract_times};
use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore, StoreError, Versioned};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{Gateway, GatewayError, Ownership, RunAdmission, is_erased};

pub const MAX_WORK_TASKS: usize = 256;
pub const MAX_WORK_BOARD_BYTES: usize = 1024 * 1024;
const CAS_ATTEMPTS: usize = 16;

/// Immutable, explicitly shared metadata. All admitted descendants can read it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkTaskInput {
    pub task_id: String,
    pub title: String,
    pub acceptance_criteria: String,
    #[serde(default)]
    pub dependencies: Vec<String>,
}

/// A worker-supplied reference, not independently verified or admitted evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkEvidence {
    pub artifact_type: String,
    pub artifact_id: String,
    pub sha256: String,
}

/// Conditional mutations. After a lost response, read the task before retrying:
/// the old expected revision conflicts if the mutation committed.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkCommand {
    Claim {
        expected_revision: u64,
        lease_seconds: u64,
    },
    Renew {
        expected_revision: u64,
        lease_epoch: u64,
        lease_seconds: u64,
    },
    Release {
        expected_revision: u64,
        lease_epoch: u64,
    },
    Complete {
        expected_revision: u64,
        lease_epoch: u64,
        evidence_refs: Vec<WorkEvidence>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum WorkError {
    #[error("{0}")]
    Refused(&'static str),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Audit(#[from] contextos_audit::AuditError),
}
impl WorkError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Refused(code) => code,
            Self::Store(_) | Self::Audit(_) => "work_unavailable",
        }
    }
}
fn refuse<T>(code: &'static str) -> Result<T, WorkError> {
    Err(WorkError::Refused(code))
}
fn identifier(s: &str) -> bool {
    (1..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
fn text(s: &str, max: usize) -> bool {
    !s.trim().is_empty() && s.len() <= max
}
fn before(a: &str, b: &str) -> bool {
    compare_contract_times(a, b) == Some(std::cmp::Ordering::Less)
}
fn key(tenant: &str, root: &str) -> DocKey {
    DocKey::new(tenant, DocKind::WorkBoard, root)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Claim {
    run_id: String,
    executor_generation: u64,
    lease_epoch: u64,
    expires_at: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Task {
    #[serde(flatten)]
    definition: WorkTaskInput,
    created_by_run_id: String,
    created_at: String,
    revision: u64,
    lease_epoch: u64,
    status: Status,
    claim: Option<Claim>,
    previous_claim: Option<Claim>,
    evidence_refs: Vec<WorkEvidence>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Pending,
    Claimed,
    Completed,
}
#[derive(Debug, Default, Serialize, Deserialize)]
struct Board {
    tasks: BTreeMap<String, Task>,
}
/// A verified team member: the worker's protected admission, its root and the current
/// time (shared with [`crate::findings`]).
pub(crate) struct Access {
    pub(crate) worker: RunAdmission,
    pub(crate) root_id: String,
    pub(crate) deadline: String,
    pub(crate) generation: u64,
    pub(crate) now: String,
}

impl Task {
    fn ready(&self, board: &Board) -> bool {
        self.definition
            .dependencies
            .iter()
            .all(|d| board.tasks.get(d).is_some_and(|t| t.status == Status::Completed))
    }
    fn available(&self, access: &Access) -> bool {
        self.status != Status::Completed
            && self.claim.as_ref().is_none_or(|c| {
                !before(&access.now, &c.expires_at)
                    || (c.run_id == access.worker.run_id && c.executor_generation < access.generation)
            })
    }
    fn view(&self, board: &Board, access: &Access) -> Value {
        let mut view = serde_json::to_value(self).expect("task fields are plain JSON");
        view["dependencies_ready"] = json!(self.ready(board));
        view["available"] = json!(self.ready(board) && self.available(access));
        view["lease_expired"] = json!(self.claim.as_ref().is_some_and(|c| !before(&access.now, &c.expires_at)));
        view
    }
}
fn decode(read: Option<&Versioned>) -> Result<Board, WorkError> {
    match read {
        Some(r) if is_erased(&r.body) => refuse("work_erased"),
        Some(r) => serde_json::from_value(r.body.clone()).map_err(|_| StoreError::Integrity.into()),
        None => Ok(Board::default()),
    }
}
fn single(task: &Task, board: &Board, access: &Access) -> Value {
    json!({"root_run_id":access.root_id,"task":task.view(board,access),
        "data_only":true,"evidence_verified":false})
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    // Reload protected admissions: caller-supplied lineage is never membership.
    pub(crate) async fn work_access(
        &self,
        admission: &RunAdmission,
        principal: &str,
        generation: u64,
    ) -> Result<Access, WorkError> {
        let worker = self
            .store
            .get(&DocKey::new(
                &admission.tenant_id,
                DocKind::RunAdmission,
                &admission.run_id,
            ))
            .await?
            .ok_or(WorkError::Refused("work_not_found"))?;
        let worker: RunAdmission = serde_json::from_value(worker.body).map_err(|_| StoreError::Integrity)?;
        if worker.tenant_id != admission.tenant_id || worker.run_id != admission.run_id {
            return Err(StoreError::Integrity.into());
        }
        if worker.admitted_by.is_empty() || worker.admitted_by != principal {
            return refuse("work_forbidden");
        }
        let root_id = worker
            .lineage
            .as_ref()
            .map_or(&worker.run_id, |l| &l.root_run_id)
            .clone();
        let root = self
            .store
            .get(&DocKey::new(&worker.tenant_id, DocKind::RunAdmission, &root_id))
            .await?
            .ok_or(WorkError::Refused("work_closed"))?;
        let root: RunAdmission = serde_json::from_value(root.body).map_err(|_| StoreError::Integrity)?;
        if root.tenant_id != worker.tenant_id || root.run_id != root_id || root.lineage.is_some() {
            return Err(StoreError::Integrity.into());
        }
        let now = self.now();
        if !before(&now, &worker.deadline) || !before(&now, &root.deadline) {
            return refuse("work_closed");
        }
        let state = self.store.get(&crate::ownership::run_state_key(&worker)).await?;
        match crate::ownership::ownership_in(state.as_ref().map(|s| &s.body), generation) {
            Ownership::Current(_) => {}
            Ownership::Refused("executor_stale") => return refuse("executor_stale"),
            Ownership::Refused(_) => return refuse("work_closed"),
        }
        if root_id != worker.run_id {
            let state = self.store.get(&crate::ownership::run_state_key(&root)).await?;
            if state.as_ref().is_none_or(|s| s.body["status"] != "running") {
                return refuse("work_closed");
            }
        }
        let deadline = if before(&worker.deadline, &root.deadline) {
            &worker.deadline
        } else {
            &root.deadline
        }
        .clone();
        Ok(Access {
            worker,
            root_id,
            deadline,
            generation,
            now,
        })
    }

    /// Publish an immutable task. Same creator/id/definition replays its current
    /// task; incompatible reuse conflicts. Metadata is shared with all descendants.
    pub async fn publish_work(
        &self,
        admission: &RunAdmission,
        principal: &str,
        generation: u64,
        input: WorkTaskInput,
    ) -> Result<Value, WorkError> {
        let deps: HashSet<_> = input.dependencies.iter().collect();
        if !identifier(&input.task_id)
            || !text(&input.title, 256)
            || !text(&input.acceptance_criteria, 4096)
            || input.dependencies.len() > 16
            || deps.len() != input.dependencies.len()
            || input.dependencies.iter().any(|d| !identifier(d) || d == &input.task_id)
        {
            return refuse("work_invalid");
        }
        let id = input.task_id.clone();
        self.mutate_work(admission, principal, generation, &id, "publish", |board, access| {
            if let Some(task) = board.tasks.get(&id) {
                if task.definition != input || task.created_by_run_id != access.worker.run_id {
                    return refuse("work_conflict");
                }
                return Ok((task.clone(), false));
            }
            if board.tasks.len() >= MAX_WORK_TASKS {
                return refuse("work_full");
            }
            if input.dependencies.iter().any(|d| !board.tasks.contains_key(d)) {
                return refuse("work_not_found");
            }
            let task = Task {
                definition: input.clone(),
                created_by_run_id: access.worker.run_id.clone(),
                created_at: access.now.clone(),
                revision: 1,
                lease_epoch: 0,
                status: Status::Pending,
                claim: None,
                previous_claim: None,
                evidence_refs: vec![],
            };
            board.tasks.insert(id.clone(), task.clone());
            Ok((task, true))
        })
        .await
    }

    /// Live view, ordered by task id. New ids before `after` appear on a fresh scan.
    /// Reads do not acknowledge or remove tasks. The maximum page is 100 tasks.
    pub async fn work_tasks(
        &self,
        admission: &RunAdmission,
        principal: &str,
        generation: u64,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Value, WorkError> {
        if !(1..=100).contains(&limit) || after.is_some_and(|s| !identifier(s)) {
            return refuse("work_invalid");
        }
        let access = self.work_access(admission, principal, generation).await?;
        let board = decode(
            self.store
                .get(&key(&admission.tenant_id, &access.root_id))
                .await?
                .as_ref(),
        )?;
        let mut page: Vec<_> = board
            .tasks
            .iter()
            .filter(|(id, _)| after.is_none_or(|a| id.as_str() > a))
            .take(limit + 1)
            .collect();
        let more = page.len() > limit;
        page.truncate(limit);
        let next = more.then(|| page.last().expect("nonempty page").0.clone());
        let tasks: Vec<_> = page.iter().map(|(_, t)| t.view(&board, &access)).collect();
        Ok(json!({"root_run_id":access.root_id,"tasks":tasks,"next_cursor":next,
            "data_only":true,"evidence_verified":false}))
    }

    /// Inspect ownership and conditional revision. Evidence remains worker-reported.
    pub async fn work_task(
        &self,
        admission: &RunAdmission,
        principal: &str,
        generation: u64,
        id: &str,
    ) -> Result<Value, WorkError> {
        if !identifier(id) {
            return refuse("work_invalid");
        }
        let access = self.work_access(admission, principal, generation).await?;
        let board = decode(
            self.store
                .get(&key(&admission.tenant_id, &access.root_id))
                .await?
                .as_ref(),
        )?;
        let task = board.tasks.get(id).ok_or(WorkError::Refused("work_not_found"))?;
        Ok(single(task, &board, &access))
    }

    /// Claim, renew, release or report completion. A claim grants no tool authority.
    /// Reclaiming work never proves previous external effects are safe to repeat.
    pub async fn update_work(
        &self,
        admission: &RunAdmission,
        principal: &str,
        generation: u64,
        id: &str,
        command: WorkCommand,
    ) -> Result<Value, WorkError> {
        if !identifier(id) {
            return refuse("work_invalid");
        }
        let action = match command {
            WorkCommand::Claim { .. } => "claim",
            WorkCommand::Renew { .. } => "renew",
            WorkCommand::Release { .. } => "release",
            WorkCommand::Complete { .. } => "complete",
        };
        self.mutate_work(admission, principal, generation, id, action, |board, access| {
            let ready = board
                .tasks
                .get(id)
                .ok_or(WorkError::Refused("work_not_found"))?
                .ready(board);
            let task = board.tasks.get_mut(id).expect("task exists");
            let (expected, epoch, seconds) = match &command {
                WorkCommand::Claim {
                    expected_revision,
                    lease_seconds,
                } => (*expected_revision, None, Some(*lease_seconds)),
                WorkCommand::Renew {
                    expected_revision,
                    lease_epoch,
                    lease_seconds,
                } => (*expected_revision, Some(*lease_epoch), Some(*lease_seconds)),
                WorkCommand::Release {
                    expected_revision,
                    lease_epoch,
                }
                | WorkCommand::Complete {
                    expected_revision,
                    lease_epoch,
                    ..
                } => (*expected_revision, Some(*lease_epoch), None),
            };
            if seconds.is_some_and(|s| !(1..=3600).contains(&s)) {
                return refuse("work_invalid");
            }
            if task.revision != expected {
                return refuse("work_conflict");
            }
            if task.status == Status::Completed {
                return refuse("work_completed");
            }
            if let Some(epoch) = epoch {
                let claim = task.claim.as_ref().ok_or(WorkError::Refused("work_lease_stale"))?;
                if claim.lease_epoch != epoch
                    || claim.run_id != access.worker.run_id
                    || claim.executor_generation != generation
                {
                    return refuse("work_lease_stale");
                }
                if !before(&access.now, &claim.expires_at) {
                    return refuse("work_lease_expired");
                }
            }
            match &command {
                WorkCommand::Claim { .. } => {
                    if !ready {
                        return refuse("work_not_ready");
                    }
                    if !task.available(access) {
                        return refuse("work_claimed");
                    }
                    task.lease_epoch = task.lease_epoch.checked_add(1).ok_or(WorkError::Refused("work_full"))?;
                    if task.claim.is_some() {
                        task.previous_claim = task.claim.take();
                    }
                    task.claim = Some(Claim {
                        run_id: access.worker.run_id.clone(),
                        executor_generation: generation,
                        lease_epoch: task.lease_epoch,
                        expires_at: lease_end(access, seconds.expect("claim seconds"))?,
                    });
                    task.status = Status::Claimed;
                }
                WorkCommand::Renew { .. } => {
                    task.claim.as_mut().expect("checked claim").expires_at =
                        lease_end(access, seconds.expect("renew seconds"))?;
                }
                WorkCommand::Release { .. } => {
                    task.previous_claim = task.claim.take();
                    task.status = Status::Pending;
                }
                WorkCommand::Complete { evidence_refs, .. } => {
                    if evidence_refs.is_empty()
                        || evidence_refs.len() > 16
                        || evidence_refs.iter().any(|e| {
                            !text(&e.artifact_type, 256) || !text(&e.artifact_id, 256) || !is_sha256_digest(&e.sha256)
                        })
                    {
                        return refuse("work_invalid");
                    }
                    task.evidence_refs.clone_from(evidence_refs);
                    task.status = Status::Completed;
                }
            }
            task.revision = task.revision.checked_add(1).ok_or(WorkError::Refused("work_full"))?;
            Ok((task.clone(), true))
        })
        .await
    }

    async fn mutate_work<F>(
        &self,
        admission: &RunAdmission,
        principal: &str,
        generation: u64,
        id: &str,
        action: &str,
        edit: F,
    ) -> Result<Value, WorkError>
    where
        F: Fn(&mut Board, &Access) -> Result<(Task, bool), WorkError>,
    {
        for attempt in 0..CAS_ATTEMPTS {
            if attempt > 0 {
                tokio::task::yield_now().await;
            }
            let access = self.work_access(admission, principal, generation).await?;
            let key = key(&admission.tenant_id, &access.root_id);
            let read = self.store.get(&key).await?;
            let mut board = decode(read.as_ref())?;
            let (task, changed) = edit(&mut board, &access)?;
            let response = single(&task, &board, &access);
            if !changed {
                return Ok(response);
            }
            let body = serde_json::to_value(&board).map_err(|_| StoreError::Integrity)?;
            if canonicalize(&body).map_or(true, |s| s.len() > MAX_WORK_BOARD_BYTES) {
                return refuse("work_full");
            }
            let digest = sha256_canonical(&body).map_err(StoreError::from)?;
            self.audit
                .append(
                    &admission.tenant_id,
                    "work_mutation_attempt",
                    json!({
                "root_run_id":access.root_id,"run_id":access.worker.run_id,"principal_id":principal,
                "executor_generation":generation,"task_id":id,"action":action,"task_revision":task.revision,
                "lease_epoch":task.lease_epoch,"base_store_revision":read.as_ref().map_or(0,|r|r.revision),
                "board_digest":digest}),
                    &access.now,
                )
                .await?;
            let written = match read {
                Some(r) => self.store.compare_and_swap(&key, r.revision, &body).await,
                None => self.store.create(&key, &body).await,
            };
            match written {
                Ok(_) => return Ok(response),
                Err(e) if e.is_conflict() => {}
                Err(e) => return Err(e.into()),
            }
        }
        refuse("work_busy")
    }

    /// Fence board creation/writes before erasing the root's retention index.
    pub(crate) async fn erase_work_board(
        &self,
        admission: &RunAdmission,
        operator: &str,
        reason: &str,
    ) -> Result<Option<Value>, GatewayError> {
        let key = key(&admission.tenant_id, &admission.run_id);
        self.erase_team_document(admission, key, "work_board", operator, reason)
            .await
    }

    /// Tombstones a root-owned team document, even an absent one, so a delayed write
    /// cannot re-create it after erasure.
    pub(crate) async fn erase_team_document(
        &self,
        admission: &RunAdmission,
        key: DocKey,
        document: &str,
        operator: &str,
        reason: &str,
    ) -> Result<Option<Value>, GatewayError> {
        if admission.lineage.is_some() {
            return Ok(None);
        }
        for _ in 0..CAS_ATTEMPTS {
            let read = self.store.get(&key).await?;
            if read.as_ref().is_some_and(|r| is_erased(&r.body)) {
                return Ok(None);
            }
            let digest = sha256_canonical(read.as_ref().map_or(&Value::Null, |r| &r.body)).map_err(StoreError::from)?;
            let now = self.now();
            let receipt = read
                .as_ref()
                .map(|_| json!({"document":document,"content_digest":digest}));
            let tombstone = json!({"content_digest":digest,"erased":true,"erased_at":now,"erased_by":operator});
            self.audit
                .append(
                    &admission.tenant_id,
                    &format!("{document}_erasure_attempt"),
                    json!({
                "root_run_id":admission.run_id,"principal_id":operator,"content_digest":digest,
                "reason_digest":sha256_canonical(&json!(reason)).map_err(StoreError::from)?}),
                    &now,
                )
                .await?;
            let written = match read {
                Some(r) => self.store.compare_and_swap(&key, r.revision, &tombstone).await,
                None => self.store.create(&key, &tombstone).await,
            };
            match written {
                Ok(_) => return Ok(receipt),
                Err(e) if e.is_conflict() => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err(StoreError::Backend(format!("{document} erasure contention")).into())
    }
}
fn lease_end(access: &Access, seconds: u64) -> Result<String, WorkError> {
    let end = add_contract_seconds(&access.now, seconds).ok_or(WorkError::Refused("work_closed"))?;
    Ok(if before(&end, &access.deadline) {
        end
    } else {
        access.deadline.clone()
    })
}

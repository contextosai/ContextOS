//! The loaded Context Packs, and adding pack versions while the server runs.
//!
//! Packs come from the files `packs` names and the JSON files under `pack_dirs`
//! (searched recursively; names starting with `.` are skipped, so a git checkout's
//! `.git` is ignored). A directory kept current by git, an image volume or a
//! configuration system is how a deployment publishes packs; the server re-reads its
//! sources every `pack_reload_secs` and on `POST /v1/packs/reload`.
//!
//! A reload only adds. A pack reference names one version forever, because runs,
//! decision records and replay cases cite it: a file whose reference is loaded with
//! other content is refused (publish a new version), and a file that disappears does
//! not unload its pack (retire a version with a `pack` revocation). A pack for a tenant
//! no startup pack names is refused too, since the per-tenant sweeps are fixed at
//! startup. Every added pack is recorded in its tenant's audit chain as `pack_loaded`.
//!
//! At startup any invalid source stops the server; on reload an invalid file is
//! refused alone and the rest still load.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock, Weak};
use std::time::Duration;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use contextos_gateway::Clock;
use contextos_store::{AppendLog, DocumentStore};
use serde::Serialize;
use serde_json::json;

use crate::app::{ApiResult, AppState, LoadedPack, authorize, load_pack};
use crate::config::Config;
use crate::runtime::SystemClock;

/// At most this many files are read per directory scan.
const MAX_FILES: usize = 4096;
/// Pack files larger than this are refused without being read.
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

type Packs = HashMap<String, Arc<LoadedPack>>;
/// A source file and what reading it gave.
type ReadPack = (PathBuf, Result<(String, LoadedPack), String>);

/// Where packs are read from.
#[derive(Debug, Clone, Default)]
pub struct PackSources {
    pub files: Vec<PathBuf>,
    pub dirs: Vec<PathBuf>,
}

impl PackSources {
    pub fn of(config: &Config) -> Self {
        Self {
            files: config.packs.clone(),
            dirs: config.pack_dirs.clone(),
        }
    }

    /// Every source file: the named files, then each directory's JSON files in order.
    fn paths(&self) -> Result<Vec<PathBuf>, String> {
        let mut paths = self.files.clone();
        for dir in &self.dirs {
            let mut found = Vec::new();
            walk(dir, &mut found)?;
            found.sort();
            paths.extend(found);
        }
        Ok(paths)
    }
}

fn walk(dir: &Path, found: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("{}: {e}", dir.display()))?;
        if entry.file_name().to_string_lossy().starts_with('.') {
            continue;
        }
        let path = entry.path();
        let kind = entry.file_type().map_err(|e| format!("{}: {e}", path.display()))?;
        if kind.is_dir() {
            walk(&path, found)?;
        } else if path.extension().is_some_and(|x| x == "json") {
            found.push(path);
        }
        if found.len() > MAX_FILES {
            return Err(format!("{}: more than {MAX_FILES} pack files", dir.display()));
        }
    }
    Ok(())
}

/// Reads and validates one pack file.
fn read_pack(path: &Path) -> Result<(String, LoadedPack), String> {
    let size = std::fs::metadata(path).map_err(|e| e.to_string())?.len();
    if size > MAX_FILE_BYTES {
        return Err(format!("larger than {MAX_FILE_BYTES} bytes"));
    }
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    load_pack(&text)
}

/// Reads every source for startup: any invalid file, or one reference with two
/// contents, is an error.
pub fn load_all(sources: &PackSources) -> Result<HashMap<String, LoadedPack>, String> {
    let mut packs: HashMap<String, LoadedPack> = HashMap::new();
    for path in sources.paths()? {
        let (pack_ref, pack) = read_pack(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        if let Some(loaded) = packs.get(&pack_ref)
            && loaded.sha256 != pack.sha256
        {
            return Err(format!(
                "{}: {pack_ref} is also loaded with other content",
                path.display()
            ));
        }
        packs.insert(pack_ref, pack);
    }
    Ok(packs)
}

#[derive(Debug, Clone, Serialize)]
pub struct AddedPack {
    pub pack_ref: String,
    pub tenant_id: String,
    pub sha256: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RefusedPack {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pack_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// `invalid`, `pack_ref_immutable` or `tenant_not_configured`.
    pub reason: &'static str,
    pub detail: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ReloadReport {
    pub added: Vec<AddedPack>,
    pub unchanged: usize,
    pub refused: Vec<RefusedPack>,
}

/// The loaded packs. Readers take a snapshot; a reload swaps in a larger map.
pub struct PackRegistry {
    packs: RwLock<Arc<Packs>>,
    tenants: BTreeSet<String>,
    sources: PackSources,
    /// One reload at a time.
    reloading: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for PackRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut refs: Vec<String> = self.snapshot().keys().cloned().collect();
        refs.sort_unstable();
        f.debug_struct("PackRegistry")
            .field("packs", &refs)
            .finish_non_exhaustive()
    }
}

impl PackRegistry {
    pub fn new(packs: HashMap<String, LoadedPack>, sources: PackSources) -> Self {
        let tenants = packs.values().map(|p| p.tenant_id.clone()).collect();
        let packs = packs.into_iter().map(|(r, p)| (r, Arc::new(p))).collect();
        Self {
            packs: RwLock::new(Arc::new(packs)),
            tenants,
            sources,
            reloading: tokio::sync::Mutex::new(()),
        }
    }

    pub fn snapshot(&self) -> Arc<Packs> {
        self.packs
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub fn get(&self, pack_ref: &str) -> Option<Arc<LoadedPack>> {
        self.snapshot().get(pack_ref).cloned()
    }

    /// Tenants with a pack at startup, the only ones a reload may add packs for.
    pub fn tenants(&self) -> &BTreeSet<String> {
        &self.tenants
    }

    /// Merges `read` (each source path and what reading it gave) into the loaded packs.
    fn merge(&self, read: Vec<ReadPack>) -> ReloadReport {
        let mut report = ReloadReport::default();
        let mut next: Packs = (*self.snapshot()).clone();
        for (path, result) in read {
            let path_text = path.display().to_string();
            let (pack_ref, pack) = match result {
                Ok(found) => found,
                Err(detail) => {
                    report.refused.push(RefusedPack {
                        path: path_text,
                        pack_ref: None,
                        tenant_id: None,
                        reason: "invalid",
                        detail,
                    });
                    continue;
                }
            };
            let refuse = |reason, detail: String| RefusedPack {
                path: path_text.clone(),
                pack_ref: Some(pack_ref.clone()),
                tenant_id: Some(pack.tenant_id.clone()),
                reason,
                detail,
            };
            match next.get(&pack_ref) {
                Some(loaded) if loaded.sha256 == pack.sha256 => report.unchanged += 1,
                Some(loaded) => report.refused.push(refuse(
                    "pack_ref_immutable",
                    format!(
                        "{pack_ref} is loaded as {}; publish changes as a new version",
                        loaded.sha256
                    ),
                )),
                None if !self.tenants.contains(&pack.tenant_id) => report.refused.push(refuse(
                    "tenant_not_configured",
                    format!("no startup pack is for tenant {}", pack.tenant_id),
                )),
                None => {
                    report.added.push(AddedPack {
                        pack_ref: pack_ref.clone(),
                        tenant_id: pack.tenant_id.clone(),
                        sha256: pack.sha256.clone(),
                        path: path_text.clone(),
                    });
                    next.insert(pack_ref, Arc::new(pack));
                }
            }
        }
        if !report.added.is_empty() {
            *self.packs.write().unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(next);
        }
        report
    }
}

/// Re-reads every source, adds new pack versions and records each in its tenant's
/// audit chain. A source directory that cannot be read refuses nothing and adds nothing.
pub async fn reload<S, L>(state: &AppState<S, L>) -> Result<ReloadReport, String>
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let registry = &state.packs;
    let _one = registry.reloading.lock().await;
    let sources = registry.sources.clone();
    let read = tokio::task::spawn_blocking(move || {
        sources.paths().map(|paths| {
            paths
                .into_iter()
                .map(|p| {
                    let r = read_pack(&p);
                    (p, r)
                })
                .collect::<Vec<_>>()
        })
    })
    .await
    .map_err(|e| e.to_string())??;
    let report = registry.merge(read);
    let now = state.gateway.as_ref().map_or_else(|| SystemClock.now(), |g| g.now());
    for added in &report.added {
        tracing::info!(pack_ref = %added.pack_ref, tenant = %added.tenant_id, "loaded context pack");
        let entry = json!({"pack_ref": added.pack_ref, "sha256": added.sha256, "source": added.path});
        if let Err(error) = state.audit.append(&added.tenant_id, "pack_loaded", entry, &now).await {
            tracing::warn!(%error, pack_ref = %added.pack_ref, "pack load not recorded");
        }
    }
    for refused in &report.refused {
        tracing::warn!(path = %refused.path, reason = refused.reason, detail = %refused.detail, "context pack refused");
    }
    Ok(report)
}

/// Reloads every `interval` until the server state is dropped.
pub async fn run<S, L>(state: Weak<AppState<S, L>>, interval: Duration)
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let mut tick = tokio::time::interval(interval);
    tick.tick().await;
    loop {
        tick.tick().await;
        let Some(state) = state.upgrade() else { return };
        if let Err(error) = reload(&state).await {
            tracing::warn!(%error, "context pack sources not read");
        }
    }
}

/// `POST /v1/packs/reload` (`control`): reload now. The answer lists what was added and
/// refused for the caller's tenant, and only counts what concerns other tenants or
/// files that are not packs.
pub async fn reload_handler<S, L>(State(state): State<Arc<AppState<S, L>>>, headers: HeaderMap) -> ApiResult
where
    S: DocumentStore + 'static,
    L: AppendLog + 'static,
{
    let caller = authorize(&state, &headers, Some("control"))?;
    let report = reload(&state).await.map_err(|error| {
        tracing::warn!(%error, "context pack sources not read");
        crate::app::ApiError::new(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "pack_sources_unavailable",
            "The Context Pack sources could not be read.",
        )
    })?;
    let ours = |tenant: Option<&String>| tenant.is_some_and(|t| *t == caller.tenant_id);
    let added: Vec<&AddedPack> = report.added.iter().filter(|a| ours(Some(&a.tenant_id))).collect();
    let refused: Vec<&RefusedPack> = report.refused.iter().filter(|r| ours(r.tenant_id.as_ref())).collect();
    Ok(axum::Json(json!({
        "added": added,
        "refused": refused,
        "unchanged": report.unchanged,
        "other": {"added": report.added.len() - added.len(), "refused": report.refused.len() - refused.len()},
    }))
    .into_response())
}

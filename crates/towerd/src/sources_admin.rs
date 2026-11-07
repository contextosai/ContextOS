//! Runtime sources managed from the console, and how every replica converges on them.
//!
//! The `sources` record collection holds two maps:
//!
//! - `console`: sources added from the console (`id` → definition, the tenant its read
//!   key resolved to when it was added, who added it and why). Keys are referenced by
//!   environment variable or secret-file path, never stored.
//! - `controls`: per source, console or `towerd.toml`, whether it is paused and two
//!   request counters, `retry` (verify the chain again from the last verified entry)
//!   and `reload` (read the keys again from their references).
//!
//! Each replica reconciles its [`crate::registry::Registry`] with the collection on a
//! timer and right after any change it makes, so all replicas agree. A counter is
//! acted on when it moves past the value this replica last applied; a replica seeing a
//! source for the first time takes the counters as already applied (its collector reads
//! the chain fresh anyway). A console source whose keys this replica cannot read is
//! listed as unavailable instead of failing startup.

use std::collections::BTreeMap;
use std::sync::Arc;

use contextos_store::{AppendLog, DocumentStore};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Tower;
use crate::config::SourceConfig;
use crate::records::RecordError;
use crate::registry::Origin;
use crate::source::Source;

/// The record collection.
pub const COLLECTION: &str = "sources";

/// A source added from the console, as stored.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsoleSource {
    pub config: SourceConfig,
    /// The tenant the read key resolved to when the source was added.
    pub tenant_id: String,
    pub added_by: String,
    pub added_at: String,
    pub reason: String,
}

/// Console controls over one source (either origin).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Control {
    #[serde(default)]
    pub paused: bool,
    #[serde(default)]
    pub retry: u64,
    #[serde(default)]
    pub reload: u64,
    /// The last change: who, when and why.
    #[serde(default)]
    pub by: Option<String>,
    #[serde(default)]
    pub at: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

/// The collection's two maps, read leniently: a malformed item is skipped (and
/// reported) rather than stopping every other source from converging.
#[derive(Debug, Default)]
pub struct Stored {
    pub console: BTreeMap<String, ConsoleSource>,
    pub controls: BTreeMap<String, Control>,
    pub malformed: Vec<String>,
}

impl Stored {
    pub fn parse(items: &Value) -> Self {
        let mut stored = Self::default();
        for (id, v) in items["console"].as_object().into_iter().flatten() {
            match serde_json::from_value::<ConsoleSource>(v.clone()) {
                Ok(s) if s.config.id == *id => {
                    stored.console.insert(id.clone(), s);
                }
                _ => stored.malformed.push(id.clone()),
            }
        }
        for (id, v) in items["controls"].as_object().into_iter().flatten() {
            match serde_json::from_value::<Control>(v.clone()) {
                Ok(c) => {
                    stored.controls.insert(id.clone(), c);
                }
                Err(_) => stored.malformed.push(id.clone()),
            }
        }
        stored
    }
}

/// A console source this replica holds but cannot run.
#[derive(Debug, Clone, Serialize)]
pub struct Unavailable {
    pub config: SourceConfig,
    pub error: String,
}

#[derive(Debug, Default)]
struct Inner {
    /// `(retry, reload)` counters this replica has acted on, per source.
    applied: BTreeMap<String, (u64, u64)>,
    unavailable: BTreeMap<String, Unavailable>,
    reconciled_at: Option<String>,
    last_error: Option<String>,
}

/// This replica's view of the console-managed sources.
#[derive(Debug, Default)]
pub struct State {
    /// One reconciliation at a time (timer and API).
    running: tokio::sync::Mutex<()>,
    inner: std::sync::RwLock<Inner>,
}

impl State {
    fn read(&self) -> std::sync::RwLockReadGuard<'_, Inner> {
        self.inner.read().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Inner> {
        self.inner.write().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn unavailable(&self) -> BTreeMap<String, Unavailable> {
        self.read().unavailable.clone()
    }

    /// When this replica last converged, and why it last could not.
    pub fn status(&self) -> (Option<String>, Option<String>) {
        let inner = self.read();
        (inner.reconciled_at.clone(), inner.last_error.clone())
    }
}

/// Converges this replica's registry with the stored console sources and controls,
/// and starts the collector of every source that is neither paused nor broken.
pub async fn reconcile<S: DocumentStore, L: AppendLog>(t: &Tower<S, L>) -> Result<(), RecordError> {
    let admin = &t.source_admin;
    let _one = admin.running.lock().await;
    let items = match t.records.load(COLLECTION).await {
        Ok(items) => items,
        Err(e) => {
            admin.write().last_error = Some(format!("load: {e}"));
            return Err(e);
        }
    };
    let stored = Stored::parse(&items);
    let every = std::time::Duration::from_millis(t.config.collector.poll_ms);
    let mut restart = Vec::new();
    let mut unavailable = BTreeMap::new();
    for (id, s) in &stored.console {
        if t.sources.origin(id) == Some(Origin::Config) {
            unavailable.insert(
                id.clone(),
                Unavailable {
                    config: s.config.clone(),
                    error: "towerd.toml defines a source with this id; the console definition is ignored".into(),
                },
            );
            continue;
        }
        let existing = t.sources.get(id);
        if existing.as_ref().is_some_and(|e| e.config == s.config) {
            continue;
        }
        match Source::new(s.config.clone()) {
            Ok(source) => {
                t.sources.upsert(Arc::new(source), Origin::Console);
                if existing.is_some() {
                    restart.push(id.clone());
                }
            }
            Err(e) => {
                if existing.is_some() {
                    t.sources.remove(id);
                }
                tracing::warn!(source = %id, error = %e, "console source unavailable on this replica");
                unavailable.insert(
                    id.clone(),
                    Unavailable {
                        config: s.config.clone(),
                        error: e.to_string(),
                    },
                );
            }
        }
    }
    for listed in t.sources.listed() {
        let id = listed.source.id();
        if listed.origin == Origin::Console && !stored.console.contains_key(id) {
            t.sources.remove(id);
            tracing::info!(source = %id, "console source removed");
        }
    }
    let mut applied = admin.read().applied.clone();
    applied.retain(|id, _| t.sources.get(id).is_some());
    for listed in t.sources.listed() {
        let id = listed.source.id().to_owned();
        let control = stored.controls.get(&id).cloned().unwrap_or_default();
        if listed.paused != control.paused {
            t.sources.set_paused(&id, control.paused);
        }
        let done = applied.entry(id.clone()).or_insert((control.retry, control.reload));
        if control.reload > done.1 {
            done.1 = control.reload;
            let error = listed.source.reload_keys().err().map(|e| format!("reload keys: {e}"));
            t.fleet.write().await.source(&id).last_error = error;
            restart.push(id.clone());
        }
        if control.retry > done.0 {
            done.0 = control.retry;
            let mut fleet = t.fleet.write().await;
            let state = fleet.source(&id);
            state.broken = None;
            state.last_error = None;
            drop(fleet);
            restart.push(id.clone());
        }
        if control.paused {
            continue;
        }
        let broken = t
            .fleet
            .read()
            .await
            .sources
            .get(&id)
            .is_some_and(|s| s.broken.is_some());
        if !broken {
            t.sources.start(&id, &t.fleet, every, restart.contains(&id));
        }
    }
    let mut inner = admin.write();
    inner.applied = applied;
    inner.unavailable = unavailable;
    inner.reconciled_at = Some(crate::collector::wall_clock());
    inner.last_error = (!stored.malformed.is_empty())
        .then(|| format!("malformed stored sources skipped: {}", stored.malformed.join(", ")));
    Ok(())
}

/// Converges once (falling back to the `towerd.toml` sources when the store cannot be
/// read), then keeps converging every `[collector] reconcile_ms`.
pub fn spawn<S: DocumentStore + 'static, L: AppendLog + 'static>(t: &Arc<Tower<S, L>>) {
    let tower = t.clone();
    let every = std::time::Duration::from_millis(t.config.collector.reconcile_ms.max(500));
    tokio::spawn(async move {
        if let Err(e) = reconcile(&tower).await {
            tracing::warn!(error = %e, "console sources not loaded yet; collecting the configured sources");
            tower.spawn_collectors();
        }
        let mut tick = tokio::time::interval(every);
        tick.tick().await;
        loop {
            tick.tick().await;
            if let Err(e) = reconcile(&tower).await {
                tracing::warn!(error = %e, "source reconciliation deferred");
            }
        }
    });
}

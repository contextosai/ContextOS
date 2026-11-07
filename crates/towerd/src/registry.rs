//! The runtime sources Tower reads, and the collector tailing each one.
//!
//! Sources come from `towerd.toml` (`origin: config`) or are managed from the console
//! (`origin: console`). Either may be paused, which stops its collector but keeps what
//! Tower has already verified from it. The registry is the only place collectors are
//! started and stopped, so a source never has two collectors folding the same chain.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde::Serialize;
use tokio::task::AbortHandle;

use crate::fleet::Fleet;
use crate::source::Source;

/// Where a source's definition lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// `[[sources]]` in `towerd.toml`: changed by editing the file and restarting.
    Config,
    /// Added from the console and kept in Tower's store.
    Console,
}

struct Entry {
    source: Arc<Source>,
    origin: Origin,
    paused: bool,
    collector: Option<AbortHandle>,
}

impl Drop for Entry {
    fn drop(&mut self) {
        if let Some(handle) = self.collector.take() {
            handle.abort();
        }
    }
}

/// A source as the console lists it.
#[derive(Debug, Clone)]
pub struct Listed {
    pub source: Arc<Source>,
    pub origin: Origin,
    pub paused: bool,
    pub collecting: bool,
}

#[derive(Default)]
pub struct Registry {
    entries: RwLock<BTreeMap<String, Entry>>,
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry").field("sources", &self.len()).finish()
    }
}

impl Registry {
    pub fn new(sources: impl IntoIterator<Item = (Arc<Source>, Origin)>) -> Self {
        let entries = sources
            .into_iter()
            .map(|(source, origin)| {
                (
                    source.id().to_owned(),
                    Entry {
                        source,
                        origin,
                        paused: false,
                        collector: None,
                    },
                )
            })
            .collect();
        Self {
            entries: RwLock::new(entries),
        }
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, BTreeMap<String, Entry>> {
        self.entries.read().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, BTreeMap<String, Entry>> {
        self.entries.write().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn len(&self) -> usize {
        self.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.read().is_empty()
    }

    /// Every source that is not paused, in id order.
    pub fn active(&self) -> Vec<Arc<Source>> {
        self.read()
            .values()
            .filter(|e| !e.paused)
            .map(|e| e.source.clone())
            .collect()
    }

    /// Every source, paused or not, in id order.
    pub fn listed(&self) -> Vec<Listed> {
        self.read()
            .values()
            .map(|e| Listed {
                source: e.source.clone(),
                origin: e.origin,
                paused: e.paused,
                collecting: e.collector.as_ref().is_some_and(|h| !h.is_finished()),
            })
            .collect()
    }

    /// A source by id, paused or not.
    pub fn get(&self, id: &str) -> Option<Arc<Source>> {
        self.read().get(id).map(|e| e.source.clone())
    }

    pub fn origin(&self, id: &str) -> Option<Origin> {
        self.read().get(id).map(|e| e.origin)
    }

    pub fn is_paused(&self, id: &str) -> Option<bool> {
        self.read().get(id).map(|e| e.paused)
    }

    /// Adds a source or replaces its definition (for example new credentials). A
    /// running collector is restarted only by [`Registry::start`].
    pub fn upsert(&self, source: Arc<Source>, origin: Origin) {
        let id = source.id().to_owned();
        let mut entries = self.write();
        match entries.get_mut(&id) {
            Some(e) => {
                e.source = source;
                e.origin = origin;
            }
            None => {
                entries.insert(
                    id,
                    Entry {
                        source,
                        origin,
                        paused: false,
                        collector: None,
                    },
                );
            }
        }
    }

    /// Removes a source and stops its collector. Returns whether it existed.
    pub fn remove(&self, id: &str) -> bool {
        self.write().remove(id).is_some()
    }

    /// Pauses or resumes a source; a paused source's collector is stopped.
    pub fn set_paused(&self, id: &str, paused: bool) -> bool {
        let mut entries = self.write();
        let Some(e) = entries.get_mut(id) else {
            return false;
        };
        e.paused = paused;
        if paused && let Some(handle) = e.collector.take() {
            handle.abort();
        }
        true
    }

    /// (Re)starts the collector of every source that is not paused and has none
    /// running. Must be called inside a Tokio runtime.
    pub fn start_all(&self, fleet: &Arc<tokio::sync::RwLock<Fleet>>, every: Duration) {
        let ids: Vec<String> = self.read().keys().cloned().collect();
        for id in ids {
            self.start(&id, fleet, every, false);
        }
    }

    /// Starts the collector of one source. With `restart`, a running collector is
    /// stopped first, so the source is read again from its verified anchor. A paused
    /// source is not started. Returns whether a collector is now running.
    pub fn start(&self, id: &str, fleet: &Arc<tokio::sync::RwLock<Fleet>>, every: Duration, restart: bool) -> bool {
        let mut entries = self.write();
        let Some(e) = entries.get_mut(id) else {
            return false;
        };
        if e.paused {
            return false;
        }
        let running = e.collector.as_ref().is_some_and(|h| !h.is_finished());
        if running && !restart {
            return true;
        }
        if let Some(handle) = e.collector.take() {
            handle.abort();
        }
        let task = tokio::spawn(crate::collector::run(e.source.clone(), fleet.clone(), every));
        e.collector = Some(task.abort_handle());
        true
    }
}

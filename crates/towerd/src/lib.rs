//! `towerd`: ContextOS Tower, the organisation's governance plane over ContextOS
//! runtimes. See docs/design/tower-governance-plane.md.

pub mod api;
pub mod authority;
pub mod collector;
pub mod config;
pub mod console;
pub mod fleet;
pub mod governance;
pub mod intel;
pub mod records;
pub mod source;

use std::sync::Arc;

use contextos_audit::{AuditSigner, AuditWriter};
use contextos_store::{AppendLog, DocumentStore};
use serde_json::{Value, json};
use tokio::sync::RwLock;

pub use config::Config;

/// The service: fleet model, sources, records, intelligence, callers.
pub struct Tower<S, L> {
    pub config: Config,
    pub fleet: Arc<RwLock<fleet::Fleet>>,
    pub sources: Vec<Arc<source::Source>>,
    pub records: records::Records<S, L>,
    pub model: Option<Arc<dyn intel::Model>>,
    pub callers: api::Callers,
    pub console: Option<Arc<console::Console>>,
    /// Tower's journal signing key, published for independent verification.
    pub journal_keys: Value,
}

impl<S, L> std::fmt::Debug for Tower<S, L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tower")
            .field("sources", &self.sources.len())
            .finish_non_exhaustive()
    }
}

/// Reads a 32-byte hex seed from the named environment variable.
pub fn signer_from_env(var: &str, key_id: &str) -> Result<AuditSigner, String> {
    let hex_seed = std::env::var(var).map_err(|_| format!("{var} is not set"))?;
    let bytes = hex::decode(hex_seed.trim()).map_err(|_| format!("{var} must be hex"))?;
    let seed: [u8; 32] = bytes.try_into().map_err(|_| format!("{var} must hold 32 bytes"))?;
    Ok(AuditSigner::from_seed(key_id, seed))
}

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Tower<S, L> {
    /// Assembles the service. Sources whose key is missing fail startup: a governance
    /// plane that silently skips a business unit would report a clean posture for it.
    pub fn build(
        config: Config,
        store: Arc<S>,
        log: L,
        signer: AuditSigner,
        model: Option<Arc<dyn intel::Model>>,
    ) -> Result<Self, String> {
        let sources = config
            .sources
            .iter()
            .map(|s| {
                source::Source::new(s.clone())
                    .map(Arc::new)
                    .map_err(|e| format!("source {}: {e}", s.id))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::assemble(config, sources, store, log, signer, model)
    }

    /// Assembles the service from sources already holding their keys.
    pub fn assemble(
        config: Config,
        sources: Vec<Arc<source::Source>>,
        store: Arc<S>,
        log: L,
        signer: AuditSigner,
        model: Option<Arc<dyn intel::Model>>,
    ) -> Result<Self, String> {
        let console = match &config.tower {
            Some(t) => Some(Arc::new(console::Console::load(&t.dir)?)),
            None => None,
        };
        let public = base64_key(&signer);
        let journal_keys = json!({"keys": [{"kid": signer.kid(), "alg": "ed25519", "public_key": public}]});
        let journal = Arc::new(AuditWriter::new(log, signer));
        let mut fleet = fleet::Fleet::new(config.collector.recent_runs, config.collector.hours);
        for s in &config.sources {
            fleet.source(&s.id);
        }
        Ok(Self {
            callers: api::Callers::new(&config.api_keys),
            fleet: Arc::new(RwLock::new(fleet)),
            sources,
            records: records::Records::new(store, journal),
            model,
            console,
            journal_keys,
            config,
        })
    }

    /// Starts one collector per source.
    pub fn spawn_collectors(&self) {
        let every = std::time::Duration::from_millis(self.config.collector.poll_ms);
        for source in &self.sources {
            tokio::spawn(collector::run(source.clone(), self.fleet.clone(), every));
        }
    }
}

fn base64_key(signer: &AuditSigner) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signer.verifying_key().as_bytes())
}

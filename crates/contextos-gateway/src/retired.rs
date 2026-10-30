//! Retired capability versions.
//!
//! An operation records the `capability_ref` it was claimed under, and a retry under
//! any other version is refused (`operation_binding_mismatch`): a new version may read
//! the same arguments differently. What is left is recovery. Reconciliation,
//! attestation and decision lineage read the operation's own version (its adapter,
//! protocol tool, completion contract and timeout), and once an upgrade replaces that
//! manifest they would refuse the operation (`capability_not_pinned`), leaving what it
//! holds held.
//!
//! A retired manifest is the previous version kept for exactly that. It is looked up
//! by `capability_ref` only, never by capability id, so nothing new is dispatched
//! through it.

use contextos_store::{AppendLog, DocumentStore};
use serde_json::Value;

use crate::manifest::{CapabilityManifest, ManifestError};
use crate::{Gateway, GatewayError};

impl<S: DocumentStore + 'static, L: AppendLog + 'static> Gateway<S, L> {
    /// Keeps a replaced capability version readable for the operations claimed under
    /// it. Its `capability_ref` must differ from every pinned and retired version.
    pub fn retire_capability(&mut self, manifest: CapabilityManifest) -> Result<(), GatewayError> {
        manifest.validate()?;
        if self.manifest_for_ref(&manifest.capability_ref).is_some() {
            return Err(ManifestError::DuplicateCapabilityRef(manifest.capability_id).into());
        }
        self.retired.push(manifest);
        Ok(())
    }

    /// The manifest an operation was claimed under: the pinned version, or a retired
    /// one.
    pub(crate) fn manifest_for_ref(&self, capability_ref: &Value) -> Option<&CapabilityManifest> {
        self.manifests
            .values()
            .chain(&self.retired)
            .find(|m| &m.capability_ref == capability_ref)
    }
}

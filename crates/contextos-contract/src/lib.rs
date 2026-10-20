//! ContextOS contract layer: published schema types, canonical encodings and shared
//! validation. Nothing in this crate authorizes an effect; schema validity and
//! digests only bind data so that the kernel can decide over it.

pub mod canonical;
pub mod errors;
pub mod execution;
pub mod ingress;
#[cfg(feature = "schema")]
pub mod schema;
pub mod shape;
pub mod types;
pub mod validation;

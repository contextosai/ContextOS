//! ContextOS contract layer: published schema types, canonical encodings and shared
//! validation. Nothing in this crate authorizes an effect; schema validity and
//! digests only bind data so that the kernel can decide over it.

pub mod canonical;
pub mod errors;
pub mod schema;
pub mod types;
pub mod validation;

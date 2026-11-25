//! Data categories and the boundaries they may not cross.
//!
//! Beside a run's classification level, the information-flow guard tracks which
//! categories of regulated data the run has read: personal data (`pii`), health data
//! (`phi`), payment card data (`pci`) and `secrets`. A capability's manifest declares
//! the categories its output may carry (`flow.output_categories`). Like the other
//! labels they only rise within a run, and they are metadata: the guard never reads
//! the data.
//!
//! A boundary says where data of some categories may go: the egress capabilities it
//! names, or capabilities whose manifest declares a destination vendor and region it
//! lists. An egress call in a run that has read one of a boundary's categories, through
//! a capability the boundary does not clear, gets the boundary's verdict (`deny` by
//! default, or `ask` for an approval of the exact call): `flow_category_boundary`.
//! A capability that declares no vendor or region is not cleared by a boundary that
//! restricts that dimension.

use serde::{Deserialize, Serialize};

use super::FlowVerdict;
use crate::manifest::CapabilityManifest;

/// At most this many boundaries.
pub const MAX_BOUNDARIES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DataCategory {
    Pii,
    Phi,
    Pci,
    Secrets,
}

const ALL: [DataCategory; 4] = [
    DataCategory::Pii,
    DataCategory::Phi,
    DataCategory::Pci,
    DataCategory::Secrets,
];

/// A set of categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Categories(u8);

impl Categories {
    #[must_use]
    pub fn of(list: &[DataCategory]) -> Self {
        Self(list.iter().fold(0, |bits, c| bits | (1 << *c as u8)))
    }

    /// Every category: what an unreadable label document counts as.
    #[must_use]
    pub fn all() -> Self {
        Self::of(&ALL)
    }

    #[must_use]
    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[must_use]
    pub fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    #[must_use]
    pub fn list(self) -> Vec<DataCategory> {
        ALL.into_iter().filter(|c| self.0 & (1 << *c as u8) != 0).collect()
    }

    /// The categories in a label document's `categories` (absent: none; not a list of
    /// known categories: every category, the worst case).
    #[must_use]
    pub fn parse(value: &serde_json::Value) -> Self {
        if value.is_null() {
            return Self::default();
        }
        serde_json::from_value::<Vec<DataCategory>>(value.clone()).map_or_else(|_| Self::all(), |l| Self::of(&l))
    }
}

fn deny() -> FlowVerdict {
    FlowVerdict::Deny
}

/// One `[[guards.information_flow.boundaries]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Boundary {
    /// The categories this boundary keeps in.
    pub categories: Vec<DataCategory>,
    /// Egress capabilities cleared for them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    /// Destination vendors cleared for them (a capability's `flow.egress_vendor`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vendors: Vec<String>,
    /// Destination regions cleared for them (a capability's `flow.egress_region`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub regions: Vec<String>,
    /// What a call through an uncleared capability gets: `deny` (default) or `ask`.
    #[serde(default = "deny")]
    pub verdict: FlowVerdict,
}

impl Boundary {
    pub fn validate(&self) -> Result<(), String> {
        if self.categories.is_empty() {
            return Err("an information-flow boundary names at least one category".into());
        }
        if self.verdict == FlowVerdict::Allow {
            return Err("an information-flow boundary's verdict is deny or ask".into());
        }
        if self.capabilities.len() + self.vendors.len() + self.regions.len() > 1024 {
            return Err("an information-flow boundary lists at most 1024 entries".into());
        }
        Ok(())
    }

    /// Whether `manifest` may carry this boundary's categories out: it is named, or its
    /// declared vendor and region are both cleared (a dimension the boundary does not
    /// restrict is cleared).
    #[must_use]
    pub fn clears(&self, manifest: &CapabilityManifest) -> bool {
        if self.capabilities.contains(&manifest.capability_id) {
            return true;
        }
        if self.vendors.is_empty() && self.regions.is_empty() {
            return false;
        }
        let flow = manifest.flow.clone().unwrap_or_default();
        let cleared = |allowed: &[String], declared: Option<&String>| {
            allowed.is_empty() || declared.is_some_and(|d| allowed.contains(d))
        };
        cleared(&self.vendors, flow.egress_vendor.as_ref()) && cleared(&self.regions, flow.egress_region.as_ref())
    }
}

/// Refuses an invalid set of boundaries.
pub fn validate(boundaries: &[Boundary]) -> Result<(), String> {
    if boundaries.len() > MAX_BOUNDARIES {
        return Err(format!("at most {MAX_BOUNDARIES} information-flow boundaries"));
    }
    boundaries.iter().try_for_each(Boundary::validate)
}

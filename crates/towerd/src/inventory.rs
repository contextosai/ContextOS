//! The inventory: every agent, capability (tool), adapter (MCP server or API), model
//! and owning team that the runtimes' verified audit chains show, or that an owner
//! declared, as one list.
//!
//! It is a view, not a registry. Nothing here is stored: each row is derived from the
//! fleet model (folded from verified audit entries) and the owners' declarations in
//! Tower's signed records, so it cannot disagree with the evidence. `ctx inventory`
//! derives the same rows offline from an audit export.
//!
//! A row is `declared` when something other than traffic accounts for it: an agent
//! with a declaration, a capability pinned in a pack the agent runs under (or surfaced
//! to its runs, which only pinned capabilities are), an adapter of a pinned capability, a model listed in the agent's declaration. A row seen in
//! traffic and not declared is a shadow row: the shadow-agent findings report them.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::Value;

use crate::governance::AgentView;

/// When an item was first and last seen in an agent's runs.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct Seen {
    pub first: String,
    pub last: String,
}

/// First and last sightings per `kind:id` (`capability:…`, `model:…`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SeenMap(BTreeMap<String, Seen>);

/// Distinct items tracked per agent; past it, sightings of new items are dropped (their
/// counts are still kept by the fleet model).
pub const MAX_SEEN: usize = 4_096;

impl SeenMap {
    /// Records a sighting at `at` (a contract timestamp; they order as strings).
    pub fn saw(&mut self, kind: &str, id: &str, at: &str) {
        let key = format!("{kind}:{id}");
        if let Some(seen) = self.0.get_mut(&key) {
            if at < seen.first.as_str() {
                at.clone_into(&mut seen.first);
            }
            if at > seen.last.as_str() {
                at.clone_into(&mut seen.last);
            }
        } else if self.0.len() < MAX_SEEN {
            self.0.insert(
                key,
                Seen {
                    first: at.to_owned(),
                    last: at.to_owned(),
                },
            );
        }
    }

    #[must_use]
    pub fn get(&self, kind: &str, id: &str) -> Option<&Seen> {
        self.0.get(&format!("{kind}:{id}"))
    }
}

pub const KINDS: [&str; 5] = ["agent", "capability", "adapter", "model", "owner"];

/// One inventory row.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Item {
    pub kind: &'static str,
    pub id: String,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    /// Environments of the sources it was seen on (`[[sources]] environment`).
    pub environments: BTreeSet<String>,
    pub sources: BTreeSet<String>,
    /// Agents: the declared tier. Others: the highest tier among the agents using it.
    pub risk_tier: Option<String>,
    /// Owning teams of the agents (for an owner row, the team itself).
    pub owner_teams: BTreeSet<String>,
    /// Agents that use it (for an agent row, the agents it delegates to).
    pub agents: BTreeSet<String>,
    pub declared: bool,
    /// Agents only: the declared lifecycle stage, or `undeclared`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<String>,
}

impl Item {
    fn new(kind: &'static str, id: &str) -> Self {
        Self {
            kind,
            id: id.to_owned(),
            first_seen: None,
            last_seen: None,
            environments: BTreeSet::new(),
            sources: BTreeSet::new(),
            risk_tier: None,
            owner_teams: BTreeSet::new(),
            agents: BTreeSet::new(),
            declared: false,
            lifecycle: None,
        }
    }

    fn seen(&mut self, first: &str, last: &str) {
        if first.is_empty() {
            return;
        }
        if self.first_seen.as_deref().is_none_or(|f| first < f) {
            self.first_seen = Some(first.to_owned());
        }
        if self.last_seen.as_deref().is_none_or(|l| last > l) {
            self.last_seen = Some(last.to_owned());
        }
    }

    fn tier(&mut self, tier: Option<&str>) {
        let rank = |t: Option<&str>| t.and_then(|t| crate::records::RISK_TIERS.iter().position(|r| *r == t));
        if rank(tier) > rank(self.risk_tier.as_deref()) {
            self.risk_tier = tier.map(str::to_owned);
        }
    }

    /// Records one agent using this item.
    fn used_by(&mut self, view: &AgentView, environments: &BTreeSet<String>, team: Option<&str>, tier: Option<&str>) {
        self.agents.insert(view.key.clone());
        self.sources.extend(view.activity.sources.iter().cloned());
        self.environments.extend(environments.iter().cloned());
        self.owner_teams.extend(team.map(str::to_owned));
        self.tier(tier);
    }
}

/// Whether `model` (`id@version`) matches a declared entry (`id` or `id@version`).
#[must_use]
pub fn model_declared(declared: &[String], model: &str) -> bool {
    let id = model.split_once('@').map_or(model, |(id, _)| id);
    declared.iter().any(|d| d == model || d == id)
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_owned)).collect())
        .unwrap_or_default()
}

/// The inventory rows of `views`, ordered by kind then id. `environments` maps a
/// source id to its declared environment.
#[must_use]
pub fn inventory(views: &[AgentView], environments: &BTreeMap<String, String>) -> Vec<Item> {
    let mut rows: BTreeMap<(usize, String), Item> = BTreeMap::new();
    let row = |kind: &'static str, id: &str| -> (usize, String) {
        let at = KINDS.iter().position(|k| *k == kind).unwrap_or(KINDS.len());
        (at, id.to_owned())
    };
    for view in views {
        let a = &view.activity;
        let d = view.declaration.as_ref();
        let team = d.and_then(|d| d["team"].as_str());
        let tier = d.and_then(|d| d["risk_tier"].as_str());
        let envs: BTreeSet<String> = a.sources.iter().filter_map(|s| environments.get(s).cloned()).collect();

        let k = row("agent", &view.key);
        let agent = rows.entry(k).or_insert_with(|| Item::new("agent", &view.key));
        agent.seen(&a.first_seen, &a.last_seen);
        agent.sources.extend(a.sources.iter().cloned());
        agent.environments.extend(envs.iter().cloned());
        agent.owner_teams.extend(team.map(str::to_owned));
        agent.agents.extend(a.delegates_to.iter().cloned());
        agent.tier(tier);
        agent.declared = d.is_some();
        agent.lifecycle = Some(
            d.and_then(|d| d["lifecycle"].as_str())
                .unwrap_or("undeclared")
                .to_owned(),
        );

        // Pinned: in a pack Tower knows the agent runs under, or surfaced to its runs at
        // admission (a runtime surfaces only pinned capabilities).
        let graph: BTreeMap<&str, (&str, bool)> = view
            .graph
            .iter()
            .map(|c| (c.id.as_str(), (c.adapter.as_str(), !c.packs.is_empty() || c.surfaced)))
            .collect();
        for (id, (adapter, pinned)) in &graph {
            let sighting = a.seen.get("capability", id);
            for (kind, key) in [("capability", *id), ("adapter", *adapter)] {
                let k = row(kind, key);
                let item = rows.entry(k).or_insert_with(|| Item::new(kind, key));
                item.used_by(view, &envs, team, tier);
                item.declared |= *pinned;
                if let Some(s) = sighting {
                    item.seen(&s.first, &s.last);
                }
            }
        }

        let declared_models = d.map(|d| strings(&d["models"])).unwrap_or_default();
        for id in &a.models {
            let k = row("model", id);
            let item = rows.entry(k).or_insert_with(|| Item::new("model", id));
            item.used_by(view, &envs, team, tier);
            item.declared |= model_declared(&declared_models, id);
            if let Some(s) = a.seen.get("model", id) {
                item.seen(&s.first, &s.last);
            }
        }

        if let Some(team) = team {
            let k = row("owner", team);
            let item = rows.entry(k).or_insert_with(|| Item::new("owner", team));
            item.used_by(view, &envs, Some(team), tier);
            item.seen(&a.first_seen, &a.last_seen);
            item.declared = true;
        }
    }
    rows.into_values().collect()
}

/// Rows as CSV (RFC 4180), sets joined with `;`.
#[must_use]
pub fn csv(items: &[Item]) -> String {
    fn cell(s: &str) -> String {
        // A leading formula character is neutralised for spreadsheet readers.
        let s = if s.starts_with(['=', '+', '-', '@']) {
            format!("'{s}")
        } else {
            s.to_owned()
        };
        if s.contains([',', '"', '\n', '\r']) {
            format!("\"{}\"", s.replace('"', "\"\""))
        } else {
            s
        }
    }
    let join = |set: &BTreeSet<String>| set.iter().cloned().collect::<Vec<_>>().join(";");
    let mut out = String::from(
        "kind,id,declared,lifecycle,risk_tier,owner_teams,environments,sources,agents,first_seen,last_seen\n",
    );
    for i in items {
        let cells = [
            i.kind.to_owned(),
            i.id.clone(),
            i.declared.to_string(),
            i.lifecycle.clone().unwrap_or_default(),
            i.risk_tier.clone().unwrap_or_default(),
            join(&i.owner_teams),
            join(&i.environments),
            join(&i.sources),
            join(&i.agents),
            i.first_seen.clone().unwrap_or_default(),
            i.last_seen.clone().unwrap_or_default(),
        ];
        out.push_str(&cells.iter().map(|c| cell(c)).collect::<Vec<_>>().join(","));
        out.push('\n');
    }
    out
}

#[cfg(test)]
#[path = "inventory_tests.rs"]
mod tests;

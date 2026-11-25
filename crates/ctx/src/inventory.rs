//! `ctx inventory`: the agents, capabilities, adapters, models and owning teams an
//! audit export shows, offline. The export is verified first, exactly as by
//! `ctx audit-verify`, and folded with Tower's fleet model, so the rows match Tower's
//! `GET /api/inventory` for the same entries.
//!
//! An export holds no packs, so offline a capability (and its adapter) is `declared`
//! only when the runtime surfaced it to a run at admission, which it does only for
//! pinned capabilities. Agents and models are declared by the declarations given with
//! `--declarations` (an object of agent key to declaration, as Tower stores them).

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde_json::{Value, json};
use towerd::fleet::Fleet;
use towerd::governance::views;
use towerd::inventory::{csv, inventory};

use crate::{Failure, audit_verify, read};

pub(crate) struct Options<'a> {
    pub entries: &'a PathBuf,
    pub keys: &'a PathBuf,
    pub continues: Option<&'a PathBuf>,
    pub source: &'a str,
    pub environment: Option<&'a str>,
    pub declarations: Option<&'a PathBuf>,
    pub csv: Option<&'a PathBuf>,
}

pub(crate) fn build(o: &Options<'_>) -> Result<Value, Failure> {
    let (report, chain) = audit_verify::verify(o.entries, o.keys, o.continues)?;
    if report["verified"] != true {
        // As `ctx audit-verify` reports it: nothing is derived from an unverified export.
        return Err(Failure::Rejected(report));
    }
    let declarations = match o.declarations {
        Some(path) => {
            let d = read(path)?;
            if !d.is_object() {
                return Err(Failure::Usage(format!(
                    "{}: declarations must be an object of agent key to declaration",
                    path.display()
                )));
            }
            d
        }
        None => json!({}),
    };
    let mut fleet = Fleet::new(1, 24);
    for entry in &chain {
        fleet.apply(o.source, entry);
    }
    let now = chain.last().map(|e| e.emitted_at.clone()).unwrap_or_default();
    let views = views(&fleet, &declarations, &json!({}), &now);
    let environments: BTreeMap<String, String> = o
        .environment
        .map(|e| (o.source.to_owned(), e.to_owned()))
        .into_iter()
        .collect();
    let items = inventory(&views, &environments);
    if let Some(path) = o.csv {
        std::fs::write(path, csv(&items)).map_err(|e| Failure::Usage(format!("{}: {e}", path.display())))?;
    }
    let shadow = items.iter().filter(|i| !i.declared && i.last_seen.is_some()).count();
    Ok(json!({
        "verified_to": chain.last().map(|e| e.sequence),
        "items": items,
        "shadow": shadow,
    }))
}

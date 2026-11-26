//! `ctx chargeback`: model spend from an audit export, grouped for whoever pays,
//! offline. The export is verified first, exactly as by `ctx audit-verify`, and folded
//! with Tower's fleet model, so the rows match Tower's `GET /api/spend` for the same
//! entries over the same hours. The window is the whole export.
//!
//! Teams, business units and owners come from `--declarations` (an object of agent key
//! to declaration, as Tower stores them); without it they are `(undeclared)`.

use std::path::PathBuf;

use serde_json::{Value, json};
use towerd::chargeback::{GROUPS, active, csv, rows, usage_json};
use towerd::fleet::{Fleet, hour_index};
use towerd::spend::Usage;

use crate::{Failure, audit_verify, read};

/// Hours of history kept while folding: longer than any export a person bills from.
const HOURS: usize = 24 * 400;

pub(crate) struct Options<'a> {
    pub entries: &'a PathBuf,
    pub keys: &'a PathBuf,
    pub continues: Option<&'a PathBuf>,
    pub declarations: Option<&'a PathBuf>,
    pub group: &'a str,
    pub csv: Option<&'a PathBuf>,
}

pub(crate) fn build(o: &Options<'_>) -> Result<Value, Failure> {
    if !GROUPS.contains(&o.group) {
        return Err(Failure::Usage(format!("--group is one of {}", GROUPS.join(", "))));
    }
    let (report, chain) = audit_verify::verify(o.entries, o.keys, o.continues)?;
    if report["verified"] != true {
        // Nothing is billed from an unverified export.
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
    let mut fleet = Fleet::new(towerd::fleet::OFFLINE_RUNS, HOURS);
    for entry in &chain {
        fleet.apply("export", entry);
    }
    let (Some(first), Some(last)) = (chain.first(), chain.last()) else {
        return Ok(json!({"verified_to": null, "group": o.group, "rows": [], "totals": usage_json(&Usage::default())}));
    };
    let (from, to) = (hour_index(&first.emitted_at), hour_index(&last.emitted_at) + 1);
    let rows = rows(&fleet, &declarations, from, to, o.group).map_err(Failure::Usage)?;
    if let Some(path) = o.csv {
        std::fs::write(path, csv(o.group, &rows)).map_err(|e| Failure::Usage(format!("{}: {e}", path.display())))?;
    }
    let mut totals = Usage::default();
    for (_, _, u) in active(&fleet, from, to) {
        totals.add(&u);
    }
    Ok(json!({
        "verified_to": last.sequence,
        "from": first.emitted_at,
        "to": last.emitted_at,
        "group": o.group,
        "totals": usage_json(&totals),
        "rows": rows,
    }))
}

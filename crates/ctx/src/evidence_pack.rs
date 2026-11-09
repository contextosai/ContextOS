//! `ctx evidence-pack`: a folder a reviewer can check on their own. It holds the audit
//! export exactly as served (re-verifiable with `ctx audit-verify`), the keys, a
//! machine-readable control map for the requested frameworks with the events that
//! evidence each control counted over the period, a coverage statement saying what the
//! evidence does and does not show, and a manifest of every file's digest.
//!
//! The pack is built only from a chain that verifies. It is deterministic: the same
//! export and options give the same files.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use contextos_audit::AuditEntry;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::Failure;

/// The frameworks a pack can map to.
pub(crate) const FRAMEWORKS: [&str; 4] = ["soc2", "iso42001", "eu-ai-act", "owasp-agentic"];
pub(crate) const PACK_VERSION: &str = "contextos.evidence_pack.v1";

/// The control map: per framework, controls with the audit event kinds that evidence them.
pub(crate) fn control_map() -> Value {
    serde_json::from_str(include_str!("evidence_controls.json")).unwrap_or(Value::Null)
}

pub(crate) struct Options<'a> {
    pub entries: &'a PathBuf,
    pub keys: &'a PathBuf,
    pub continues: Option<&'a PathBuf>,
    pub frameworks: &'a [String],
    pub config_report: Option<&'a PathBuf>,
    pub out: &'a PathBuf,
}

fn io(path: &Path, e: &std::io::Error) -> Failure {
    Failure::Usage(format!("{}: {e}", path.display()))
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// Each control with what the period's entries show for it.
fn controls(frameworks: &[String], counts: &BTreeMap<&str, u64>) -> Value {
    let map = control_map();
    let mut out = Vec::new();
    for id in frameworks {
        let framework = &map["frameworks"][id.as_str()];
        let controls: Vec<Value> = framework["controls"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|control| {
                let events: Vec<&str> = control["events"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .collect();
                let observed: BTreeMap<&str, u64> = events
                    .iter()
                    .map(|k| (*k, counts.get(k).copied().unwrap_or(0)))
                    .collect();
                let status = if events.is_empty() {
                    "outside_audit"
                } else if observed.values().any(|n| *n > 0) {
                    "evidenced"
                } else {
                    "no_events_in_period"
                };
                let mut c = control.clone();
                c["observed"] = json!(observed);
                c["status"] = json!(status);
                c
            })
            .collect();
        out.push(json!({"framework": id, "title": framework["title"], "controls": controls}));
    }
    json!({"pack_version": PACK_VERSION, "frameworks": out})
}

fn period(chain: &[AuditEntry]) -> Value {
    let (first, last) = (chain.first(), chain.last());
    json!({"tenant_id": first.map(|e| &e.tenant_id),
        "first_sequence": first.map(|e| e.sequence), "last_sequence": last.map(|e| e.sequence),
        "from": first.map(|e| &e.emitted_at), "to": last.map(|e| &e.emitted_at),
        "entries": chain.len(), "last_record_hash": last.map(|e| &e.record_hash)})
}

fn coverage(period: &Value, verification: &Value, controls: &Value, config_report: Option<&str>) -> String {
    let s = |v: &Value| v.as_str().map_or_else(|| v.to_string(), str::to_owned);
    let mut md = String::from("# Evidence pack\n\n");
    let _ = writeln!(
        md,
        "Tenant `{}`, audit entries {} to {} ({} entries), {} to {}. The chain verified \
         offline against the published keys{}; re-check it with\n`ctx audit-verify --entries entries.json --keys keys.json{}`.\n",
        s(&period["tenant_id"]),
        period["first_sequence"],
        period["last_sequence"],
        period["entries"],
        s(&period["from"]),
        s(&period["to"]),
        if verification["anchor_sequence"].is_null() {
            String::new()
        } else {
            format!(", continuing entry {} (anchor.json)", verification["anchor_sequence"])
        },
        if verification["anchor_sequence"].is_null() {
            ""
        } else {
            " --continues anchor.json"
        }
    );
    let masked = verification["payload_unverified_sequences"]
        .as_array()
        .map_or(0, Vec::len);
    if masked > 0 {
        let _ = writeln!(
            md,
            "{masked} entries were delivered with masked payloads: their linkage and signatures verify, their payloads are not shown.\n"
        );
    }
    md.push_str(
        "## What this evidence covers\n\n\
         - Every run admission, policy decision, approval, effect, refusal and operator change that went \
           through this tenant's ContextOS gateways in the period, signed in order.\n\
         - Counts per control below are of those entries; a count shows the control acted, not that it was \
           configured everywhere it should be.\n\n\
         ## What it does not cover\n\n\
         - Calls an agent made to a tool directly, with a credential that bypasses the gateway.\n\
         - Prompts, model outputs and tool content beyond what the entries record.\n\
         - Organizational controls: policies, training, risk and impact assessments, assigned oversight.\n",
    );
    let _ = match config_report {
        Some(name) => writeln!(
            md,
            "- Configuration is evidenced by `{name}`, as supplied with the pack, not by the chain."
        ),
        None => writeln!(
            md,
            "- Whether the configuration in force matched what was reviewed: attach `contextosd --check-config` output with `--config-report`."
        ),
    };

    for framework in controls["frameworks"].as_array().into_iter().flatten() {
        let _ = write!(
            md,
            "\n## {}\n\n| Control | Status | Events in the period |\n|---|---|---|\n",
            s(&framework["title"])
        );
        for c in framework["controls"].as_array().into_iter().flatten() {
            let observed: Vec<String> = c["observed"]
                .as_object()
                .into_iter()
                .flatten()
                .map(|(k, n)| format!("`{k}` {n}"))
                .collect();
            let detail = if observed.is_empty() {
                s(&c["note"])
            } else {
                observed.join(", ")
            };
            let _ = writeln!(
                md,
                "| {} {} | {} | {} |",
                s(&c["id"]),
                s(&c["title"]),
                s(&c["status"]).replace('_', " "),
                detail
            );
        }
    }
    md
}

/// Builds the pack in `options.out`, which must not exist or be empty.
pub(crate) fn build(options: &Options<'_>) -> Result<Value, Failure> {
    if let Some(unknown) = options.frameworks.iter().find(|f| !FRAMEWORKS.contains(&f.as_str())) {
        return Err(Failure::Usage(format!(
            "unknown framework {unknown}; one of {}",
            FRAMEWORKS.join(", ")
        )));
    }
    let out = options.out;
    if out.exists() && std::fs::read_dir(out).map_err(|e| io(out, &e))?.next().is_some() {
        return Err(Failure::Usage(format!("{}: not empty", out.display())));
    }
    let (verification, chain) = crate::audit_verify::verify(options.entries, options.keys, options.continues)?;
    let mut counts: BTreeMap<&str, u64> = BTreeMap::new();
    for entry in &chain {
        *counts.entry(entry.kind.as_str()).or_default() += 1;
    }
    let period = period(&chain);
    let controls = controls(options.frameworks, &counts);
    std::fs::create_dir_all(out).map_err(|e| io(out, &e))?;
    let mut files = BTreeMap::new();
    let mut put = |name: &str, bytes: Vec<u8>| -> Result<(), Failure> {
        let path = out.join(name);
        files.insert(name.to_owned(), sha256(&bytes));
        std::fs::write(&path, bytes).map_err(|e| io(&path, &e))
    };
    let copy = |from: &PathBuf| std::fs::read(from).map_err(|e| io(from, &e));
    // The export as served, so it re-verifies exactly (masked entries included).
    put("entries.json", copy(options.entries)?)?;
    put("keys.json", copy(options.keys)?)?;
    if let Some(anchor) = options.continues {
        put("anchor.json", copy(anchor)?)?;
    }
    // The report as supplied, keeping its kind (`--check-config` prints text).
    let report_name = options.config_report.map(|report| {
        let ext = report.extension().and_then(|e| e.to_str()).unwrap_or("txt");
        format!("config-report.{ext}")
    });
    if let (Some(report), Some(name)) = (options.config_report, &report_name) {
        put(name, copy(report)?)?;
    }
    let pretty = |v: &Value| serde_json::to_vec_pretty(v).unwrap_or_default();
    put("controls.json", pretty(&controls))?;
    let md = coverage(&period, &verification, &controls, report_name.as_deref());
    put("coverage.md", md.into_bytes())?;
    let mut tally: BTreeMap<String, u64> = BTreeMap::new();
    for c in controls["frameworks"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|f| f["controls"].as_array().into_iter().flatten())
    {
        *tally.entry(c["status"].as_str().unwrap_or("?").to_owned()).or_default() += 1;
    }
    let manifest = json!({"pack_version": PACK_VERSION, "frameworks": options.frameworks,
        "period": period, "verification": verification, "event_counts": counts,
        "controls": tally, "files": files});
    let path = out.join("manifest.json");
    std::fs::write(&path, pretty(&manifest)).map_err(|e| io(&path, &e))?;
    Ok(json!({"written": out.display().to_string(), "verified": true,
        "frameworks": options.frameworks, "period": manifest["period"], "controls": manifest["controls"]}))
}

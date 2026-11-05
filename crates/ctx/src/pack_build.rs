//! `ctx build`: assemble a Context Pack from a pack source, so packs can share rules.
//!
//! A pack source (`contextos.pack_source.v1`) names a `base` (a pack, or another pack
//! source), an optional JSON merge `patch` over it (RFC 7386; typically the new
//! `pack_meta.pack_version`), and `imports` of rule libraries
//! (`contextos.rule_library.v1`, a set of policy bundles kept once and reused by many
//! packs). An import may take a subset of a library's bundles, set their `priority`,
//! and scope them to one `intent`: every imported rule then applies to that intent
//! only. Scoping narrows and never redirects, so a rule that already names another
//! intent is refused.
//!
//! The result is an ordinary context-pack.v2 document: admission, the release gate and
//! pack tests see no difference, and a built pack is reviewed, tested and gated like
//! any other. Paths are relative to the file that names them. `--check` compares the
//! build with an existing file instead of writing it, so CI can refuse a committed pack
//! that no longer matches its sources.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use contextos_contract::canonical::{canonicalize, sha256_canonical};
use contextos_contract::schema::{SchemaDoc, SchemaTarget, validate};
use contextos_contract::types::ContextPack;
use contextos_kernel::ContextPackCompiler;
use contextos_kernel::pack_test::merge_patch;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{Failure, read};

pub const SOURCE_FORMAT: &str = "contextos.pack_source.v1";
pub const LIBRARY_FORMAT: &str = "contextos.rule_library.v1";
/// How deep a chain of pack sources may extend one another.
const MAX_DEPTH: usize = 8;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackSource {
    #[serde(rename = "pack_source")]
    format: String,
    base: PathBuf,
    #[serde(default)]
    patch: Value,
    #[serde(default)]
    imports: Vec<Import>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Import {
    library: PathBuf,
    /// Bundle ids to take; all when absent.
    #[serde(default)]
    bundles: Option<Vec<String>>,
    #[serde(default)]
    intent: Option<String>,
    #[serde(default)]
    priority: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleLibrary {
    #[serde(rename = "rule_library")]
    format: String,
    library_id: String,
    version: String,
    /// Free text for readers; not used by the build.
    #[serde(default, rename = "description")]
    _description: Option<String>,
    policy_bundles: Vec<Value>,
}

/// What a build read and where each bundle came from.
struct Build {
    inputs: Vec<Value>,
    origins: BTreeMap<String, String>,
}

fn usage(path: &Path, message: impl std::fmt::Display) -> Failure {
    Failure::Usage(format!("{}: {message}", path.display()))
}

fn relative(from: &Path, name: &Path) -> PathBuf {
    from.parent().unwrap_or_else(|| Path::new(".")).join(name)
}

fn record_input(build: &mut Build, path: &Path, role: &str, value: &Value) {
    build
        .inputs
        .push(json!({"path": path.display().to_string(), "role": role,
        "sha256": sha256_canonical(value).unwrap_or_default()}));
}

fn scope(bundle: &mut Value, intent: &str, path: &Path) -> Result<(), Failure> {
    let bundle_id = bundle["bundle_id"].as_str().unwrap_or_default().to_owned();
    let rules = bundle["policy_dsl"]["rules"]
        .as_array_mut()
        .ok_or_else(|| usage(path, format!("bundle {bundle_id} has no policy_dsl.rules")))?;
    for rule in rules {
        let named = rule["applies_to"]["intent"].as_str().unwrap_or_default();
        if !named.is_empty() && named != intent {
            return Err(usage(
                path,
                format!(
                    "rule {} in {bundle_id} applies to {named}; an import scoped to {intent} cannot redirect it",
                    rule["rule_id"].as_str().unwrap_or_default()
                ),
            ));
        }
        rule["applies_to"]["intent"] = json!(intent);
    }
    Ok(())
}

fn import(pack: &mut Value, from: &Path, spec: &Import, build: &mut Build) -> Result<(), Failure> {
    let path = relative(from, &spec.library);
    let value = read(&path)?;
    record_input(build, &path, "library", &value);
    let library: RuleLibrary = serde_json::from_value(value).map_err(|e| usage(&path, e))?;
    if library.format != LIBRARY_FORMAT {
        return Err(usage(&path, format!("rule_library must be {LIBRARY_FORMAT}")));
    }
    let id_of = |b: &Value| b["bundle_id"].as_str().unwrap_or_default().to_owned();
    if let Some(wanted) = &spec.bundles
        && let Some(missing) = wanted
            .iter()
            .find(|w| !library.policy_bundles.iter().any(|b| id_of(b) == **w))
    {
        return Err(usage(
            &path,
            format!("library {} has no bundle {missing}", library.library_id),
        ));
    }
    let bundles = pack["policy_layer"]["policy_bundles"]
        .as_array_mut()
        .ok_or_else(|| usage(from, "the base pack has no policy_layer.policy_bundles"))?;
    for mut bundle in library.policy_bundles {
        let bundle_id = id_of(&bundle);
        if spec.bundles.as_ref().is_some_and(|w| !w.contains(&bundle_id)) {
            continue;
        }
        if bundles.iter().any(|b| id_of(b) == bundle_id) {
            return Err(usage(
                &path,
                format!("bundle {bundle_id} is already in the pack; bundle ids must be unique"),
            ));
        }
        if let Some(intent) = &spec.intent {
            scope(&mut bundle, intent, &path)?;
        }
        if let Some(priority) = spec.priority {
            bundle["priority"] = json!(priority);
        }
        build
            .origins
            .insert(bundle_id, format!("{}@{}", library.library_id, library.version));
        bundles.push(bundle);
    }
    Ok(())
}

/// The pack a file describes: a pack as is, or a pack source assembled.
fn assemble(path: &Path, depth: usize, chain: &mut Vec<PathBuf>, build: &mut Build) -> Result<Value, Failure> {
    let value = read(&path.to_path_buf())?;
    if value.get("pack_source").is_none() {
        record_input(build, path, "pack", &value);
        return Ok(value);
    }
    record_input(build, path, "source", &value);
    let identity = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if chain.contains(&identity) {
        return Err(usage(path, "pack sources extend one another in a cycle"));
    }
    if depth >= MAX_DEPTH {
        return Err(usage(path, format!("more than {MAX_DEPTH} pack sources deep")));
    }
    let source: PackSource = serde_json::from_value(value).map_err(|e| usage(path, e))?;
    if source.format != SOURCE_FORMAT {
        return Err(usage(path, format!("pack_source must be {SOURCE_FORMAT}")));
    }
    chain.push(identity);
    let mut pack = assemble(&relative(path, &source.base), depth + 1, chain, build)?;
    chain.pop();
    if !source.patch.is_null() {
        merge_patch(&mut pack, &source.patch);
    }
    for spec in &source.imports {
        import(&mut pack, path, spec, build)?;
    }
    Ok(pack)
}

pub fn run(source: &Path, out: Option<&PathBuf>, check: Option<&PathBuf>) -> Result<Value, Failure> {
    let mut build = Build {
        inputs: Vec::new(),
        origins: BTreeMap::new(),
    };
    let pack = assemble(source, 0, &mut Vec::new(), &mut build)?;
    if let Err(e) = validate(&SchemaTarget::document(SchemaDoc::ContextPack), &pack) {
        return Err(Failure::Rejected(
            json!({"error": "the built pack does not conform to context-pack.v2", "violations": e.violations}),
        ));
    }
    let typed: ContextPack = serde_json::from_value(pack.clone())
        .map_err(|e| Failure::Rejected(json!({"error": format!("built pack: {e}")})))?;
    let pack_ref = typed.pack_meta.pack_ref();
    ContextPackCompiler::new(typed).map_err(|e| Failure::Rejected(json!({"error": e.to_string()})))?;
    let sha256 = sha256_canonical(&pack).map_err(|e| Failure::Usage(e.to_string()))?;
    let mut report = json!({"pack_ref": pack_ref, "sha256": sha256, "inputs": build.inputs,
        "imported_bundles": build.origins});
    if let Some(existing) = check {
        let current = read(existing)?;
        let same = canonicalize(&current).ok() == canonicalize(&pack).ok();
        report["check"] = json!({"path": existing.display().to_string(), "matches": same});
        return if same {
            Ok(report)
        } else {
            Err(Failure::Rejected(report))
        };
    }
    let text = serde_json::to_string_pretty(&pack).map_err(|e| Failure::Usage(e.to_string()))? + "\n";
    match out {
        Some(out) => {
            std::fs::write(out, text).map_err(|e| usage(out, e))?;
            report["out"] = json!(out.display().to_string());
            Ok(report)
        }
        None => Ok(pack),
    }
}

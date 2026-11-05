//! Pack tests: an author's expectations of what a Context Pack decides, checked
//! offline (runtime extension, `ctx test`).
//!
//! The release gate compares a candidate with the baseline and flags what changed; it
//! cannot say whether either pack is right. A test suite states it: for a base case
//! (request, run context, compile dependencies) and a JSON merge patch per test
//! (RFC 7386, so a test names only what differs from the base), the pack must reach
//! the expected verdict, apply the expected rules, surface or withhold capabilities
//! and set evidence gates as stated. Every observation is read exactly as admission
//! reads it (see [`crate::pack_observation`]).
//!
//! Expectations are partial: a test checks only the fields it names, and naming none
//! is refused, so a test cannot pass by checking nothing.

use std::collections::{BTreeMap, BTreeSet};

use contextos_contract::types::{ContextPack, InvokeRequest, RunContext};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::ContextPackCompiler;
use crate::pack_observation::{Observed, VERDICTS, observe};

/// The parts of a case a base or a patch may set.
const CASE_KEYS: [&str; 3] = ["request", "run_context", "deps"];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackTestSuite {
    pub suite: String,
    #[serde(default)]
    pub description: Option<String>,
    /// `{request, run_context, deps?}`: the case every test starts from.
    pub base: Value,
    pub tests: Vec<PackTest>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackTest {
    pub name: String,
    /// A JSON merge patch over the base, with keys among `request`, `run_context`,
    /// `deps`; `null` removes a field.
    #[serde(default)]
    pub with: Value,
    pub expect: Expectations,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expectations {
    /// `compiles` or `refused`. A refused case may expect nothing else.
    #[serde(default)]
    pub compile: Option<String>,
    /// The composed verdict: `deny`, `escalate`, `require_approval` or `allow`.
    #[serde(default)]
    pub verdict: Option<String>,
    /// Exactly the rule ids that apply.
    #[serde(default)]
    pub rules: Option<Vec<String>>,
    /// Exactly the obligations the composed verdict carries.
    #[serde(default)]
    pub obligations: Option<Vec<String>>,
    #[serde(default)]
    pub capabilities: Option<CapabilityExpectations>,
    /// Decision key to whether its gate allows commit; keys not named are unchecked.
    #[serde(default)]
    pub evidence_gates: Option<BTreeMap<String, bool>>,
}

/// Capabilities as `adapter_id.capability`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityExpectations {
    /// Each must be surfaced.
    #[serde(default)]
    pub include: Vec<String>,
    /// None may be surfaced.
    #[serde(default)]
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TestResult {
    pub name: String,
    /// `pass`, `fail` (an expectation was not met) or `error` (the case is invalid).
    pub status: String,
    pub failures: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SuiteReport {
    pub suite: String,
    /// `pass` when every test passed, else `fail`.
    pub verdict: String,
    pub passed: usize,
    pub failed: usize,
    pub tests: Vec<TestResult>,
}

/// RFC 7386 JSON merge patch.
pub fn merge_patch(target: &mut Value, patch: &Value) {
    let Value::Object(entries) = patch else {
        *target = patch.clone();
        return;
    };
    if !target.is_object() {
        *target = Value::Object(Map::new());
    }
    if let Value::Object(fields) = target {
        for (key, value) in entries {
            if value.is_null() {
                fields.remove(key);
            } else {
                merge_patch(fields.entry(key.clone()).or_insert(Value::Null), value);
            }
        }
    }
}

fn check_case_keys(value: &Value, what: &str) -> Result<(), String> {
    match value {
        Value::Null => Ok(()),
        Value::Object(fields) => match fields.keys().find(|k| !CASE_KEYS.contains(&k.as_str())) {
            Some(key) => Err(format!("{what} sets {key}; only request, run_context and deps")),
            None => Ok(()),
        },
        _ => Err(format!("{what} must be an object")),
    }
}

fn check_expectations(expect: &Expectations) -> Result<(), String> {
    let checks_observation = expect.verdict.is_some()
        || expect.rules.is_some()
        || expect.obligations.is_some()
        || expect.capabilities.is_some()
        || expect.evidence_gates.is_some();
    match expect.compile.as_deref() {
        None if !checks_observation => Err("expect names nothing to check".into()),
        Some("refused") if checks_observation => Err("a refused case can expect nothing else".into()),
        None | Some("compiles" | "refused") => Ok(()),
        Some(other) => Err(format!("expect.compile {other} is not compiles or refused")),
    }?;
    match expect.verdict.as_deref() {
        Some(verdict) if !VERDICTS.contains(&verdict) => Err(format!(
            "expect.verdict {verdict} is not one of {}",
            VERDICTS.join(", ")
        )),
        _ => Ok(()),
    }
}

fn set_difference(what: &str, expected: &[String], observed: &BTreeSet<String>, failures: &mut Vec<String>) {
    let expected: BTreeSet<&String> = expected.iter().collect();
    let observed: BTreeSet<&String> = observed.iter().collect();
    let missing: Vec<&&String> = expected.difference(&observed).collect();
    let extra: Vec<&&String> = observed.difference(&expected).collect();
    if !missing.is_empty() || !extra.is_empty() {
        failures.push(format!("{what}: expected {expected:?}, got {observed:?}"));
    }
}

fn compare(expect: &Expectations, observed: &Observed) -> Vec<String> {
    let mut failures = Vec::new();
    if let Some(verdict) = &expect.verdict
        && VERDICTS[observed.verdict] != verdict
    {
        failures.push(format!(
            "verdict: expected {verdict}, got {}",
            VERDICTS[observed.verdict]
        ));
    }
    if let Some(rules) = &expect.rules {
        set_difference("rules", rules, &observed.rules, &mut failures);
    }
    if let Some(obligations) = &expect.obligations {
        set_difference("obligations", obligations, &observed.obligations, &mut failures);
    }
    if let Some(capabilities) = &expect.capabilities {
        for id in capabilities
            .include
            .iter()
            .filter(|id| !observed.capabilities.contains(*id))
        {
            failures.push(format!("capability {id} is not surfaced"));
        }
        for id in capabilities
            .exclude
            .iter()
            .filter(|id| observed.capabilities.contains(*id))
        {
            failures.push(format!("capability {id} is surfaced"));
        }
    }
    for (key, allowed) in expect.evidence_gates.iter().flatten() {
        match observed.gates.get(key) {
            None => failures.push(format!("evidence gate {key} is absent")),
            Some(actual) if actual != allowed => {
                failures.push(format!(
                    "evidence gate {key}: expected commit_allowed {allowed}, got {actual}"
                ));
            }
            Some(_) => {}
        }
    }
    failures
}

fn run_one(compiler: &ContextPackCompiler, base: &Value, test: &PackTest) -> TestResult {
    let result = |status: &str, failures: Vec<String>| TestResult {
        name: test.name.clone(),
        status: status.into(),
        failures,
    };
    if let Err(e) = check_case_keys(&test.with, "with").and_then(|()| check_expectations(&test.expect)) {
        return result("error", vec![e]);
    }
    let mut case = base.clone();
    // An absent patch is no change (a top-level `null` patch would replace the case).
    if !test.with.is_null() {
        merge_patch(&mut case, &test.with);
    }
    let request = serde_json::from_value::<InvokeRequest>(case["request"].clone());
    let run_context = serde_json::from_value::<RunContext>(case["run_context"].clone());
    let (request, run_context) = match (request, run_context) {
        (Ok(request), Ok(run_context)) => (request, run_context),
        (Err(e), _) => return result("error", vec![format!("request is invalid: {e}")]),
        (_, Err(e)) => return result("error", vec![format!("run_context is invalid: {e}")]),
    };
    let failures = match (
        observe(compiler, &request, &run_context, &case["deps"]),
        test.expect.compile.as_deref(),
    ) {
        (Err(_), Some("refused")) => vec![],
        (Err(e), _) => vec![format!("compile: expected the case to compile, got {e}")],
        (Ok(_), Some("refused")) => vec!["compile: expected the case to be refused, it compiles".into()],
        (Ok(observed), _) => compare(&test.expect, &observed),
    };
    if failures.is_empty() {
        result("pass", failures)
    } else {
        result("fail", failures)
    }
}

/// Runs every test in `suite` against `pack`. Errors are for a suite that cannot run
/// at all; a test whose case or expectations are invalid is reported as `error`.
pub fn run_pack_tests(pack: &ContextPack, suite: &PackTestSuite) -> Result<SuiteReport, String> {
    if suite.tests.is_empty() {
        return Err(format!("suite {} has no tests", suite.suite));
    }
    let mut names = BTreeSet::new();
    if let Some(test) = suite.tests.iter().find(|t| !names.insert(t.name.as_str())) {
        return Err(format!(
            "test {} appears more than once in suite {}",
            test.name, suite.suite
        ));
    }
    check_case_keys(&suite.base, "base")?;
    let compiler = ContextPackCompiler::new(pack.clone()).map_err(|e| format!("pack: {e}"))?;
    let tests: Vec<TestResult> = suite
        .tests
        .iter()
        .map(|test| run_one(&compiler, &suite.base, test))
        .collect();
    let passed = tests.iter().filter(|t| t.status == "pass").count();
    let failed = tests.len() - passed;
    Ok(SuiteReport {
        suite: suite.suite.clone(),
        verdict: if failed == 0 { "pass" } else { "fail" }.into(),
        passed,
        failed,
        tests,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::merge_patch;

    #[test]
    fn merge_patch_follows_rfc_7386() {
        // RFC 7386 appendix A, a representative subset.
        let cases = [
            (json!({"a": "b"}), json!({"a": "c"}), json!({"a": "c"})),
            (json!({"a": "b"}), json!({"b": "c"}), json!({"a": "b", "b": "c"})),
            (json!({"a": "b"}), json!({"a": null}), json!({})),
            (json!({"a": ["b"]}), json!({"a": "c"}), json!({"a": "c"})),
            (
                json!({"a": {"b": "c"}}),
                json!({"a": {"b": "d", "c": null}}),
                json!({"a": {"b": "d"}}),
            ),
            (json!({"a": [{"b": "c"}]}), json!({"a": [1]}), json!({"a": [1]})),
            (json!(["a", "b"]), json!(["c", "d"]), json!(["c", "d"])),
            (json!({"e": null}), json!({"a": 1}), json!({"e": null, "a": 1})),
            (json!([1, 2]), json!({"a": "b", "c": null}), json!({"a": "b"})),
            (json!({}), json!({"a": {"bb": {"ccc": null}}}), json!({"a": {"bb": {}}})),
        ];
        for (mut target, patch, expected) in cases {
            merge_patch(&mut target, &patch);
            assert_eq!(target, expected, "patch {patch}");
        }
    }
}

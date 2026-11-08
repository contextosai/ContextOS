//! `[readiness]`: a consequential capability must have every mechanism it relies on,
//! or the profile names what is missing.

use std::collections::HashMap;
use std::path::PathBuf;

use contextos_gateway::manifest::CapabilityManifest;
use contextosd::config::Config;
use contextosd::workflow_readiness::{Area, evaluate, report};
use serde_json::{Value, json};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    std::fs::read_to_string(root().join(path)).unwrap()
}

fn manifest(name: &str, edit: impl FnOnce(&mut Value)) -> CapabilityManifest {
    let mut value: Value =
        serde_json::from_str(&read(&format!("examples/support-refund/capabilities/{name}.json"))).unwrap();
    edit(&mut value);
    serde_json::from_value(value).unwrap()
}

/// The refund with a completion contract, its provider reference and a witness.
fn ready_refund() -> CapabilityManifest {
    manifest("issue_refund", |m| {
        m["recovery"]["completion"] =
            json!({"state_pointer": "/status", "confirmed": ["succeeded"], "not_applied": ["failed"]});
        m["recovery"]["reference_pointer"] = json!("/refund_id");
        m["outcome"] = json!({"witness": "refund-ledger", "postcondition": "refund_posted", "within_seconds": 900, "binds": "effect"});
        m["intent"] = json!({"key_pointers": ["/order_id", "/amount_minor"]});
    })
}

fn bare_refund() -> CapabilityManifest {
    manifest("issue_refund", |_| {})
}

fn lookup() -> CapabilityManifest {
    manifest("lookup_order", |_| {})
}

/// Everything a refund workflow needs besides its manifest: strict evidence bound to
/// subjects, agent binding, a guarantee whose holds reach an owner.
const READY: &str = r#"
[[evidence_subjects]]
requirement = "identity_verified"
from = "/request/input/context/customer_id"
prefix = "customer:"

[[evidence_subjects]]
requirement = "order_lookup"
from = "/request/input/context/order_id"
prefix = "order:"

[[guarantees]]
id = "refund_ceiling"
capability_ids = ["adp_payments.issue_refund"]
resource_pointer = "/order_id"
amount_pointer = "/amount_minor"
limit = 500000
unit = "INR_minor"
owner_route = "refund_owners"

[[notifications]]
id = "refund_owners"
url = "http://127.0.0.1:9900/hook"
secret_env = "REFUND_OWNERS_SECRET"
"#;

const STRICT: &str = "evidence = \"strict\"\nagent_binding = \"required\"\n";

/// The quickstart configuration with `extra` appended and `guards` placed in `[guards]`.
fn config(guards: &str, extra: &str) -> Config {
    let text = read("examples/support-refund/contextosd.toml")
        .replace("sha256:REPLACED_BY_RUN_SH", &format!("sha256:{}", "ab".repeat(32)))
        .replace(
            "principal_id = \"svc_quickstart\"",
            "principal_id = \"svc_quickstart\"\nagent_ids = [\"agt_support\"]",
        );
    Config::parse(&format!("{text}\n[guards]\n{guards}\n{extra}")).unwrap()
}

fn packs() -> HashMap<String, contextosd::LoadedPack> {
    let (pack_ref, pack) = contextosd::load_pack(&read("examples/support-refund/pack.json")).unwrap();
    HashMap::from([(pack_ref, pack)])
}

const PROFILE: &str = "[readiness]\nglobal_evidence = [\"policy.eval\"]\n";

#[test]
fn absent_profile_checks_nothing() {
    assert!(evaluate(&config("", ""), &packs(), &[bare_refund()]).is_none());
}

#[test]
fn a_complete_refund_workflow_is_ready() {
    let config = config(STRICT, &format!("{READY}{PROFILE}"));
    let found = evaluate(&config, &packs(), &[ready_refund(), lookup()])
        .unwrap()
        .unwrap();
    assert_eq!(
        found.capabilities,
        ["adp_payments.issue_refund"],
        "the read-only lookup is not consequential"
    );
    assert!(found.gaps.is_empty(), "{:?}", found.gaps);
    let lines = report(&config, &packs(), &[ready_refund(), lookup()]).unwrap();
    assert_eq!(
        lines,
        ["workflow readiness (required): 1 capability(ies) ready: adp_payments.issue_refund"]
    );
}

#[test]
fn the_quickstart_refund_lacks_every_mechanism() {
    let config = config("", PROFILE);
    let found = evaluate(&config, &packs(), &[bare_refund(), lookup()])
        .unwrap()
        .unwrap();
    let areas: Vec<(&str, Area)> = found.gaps.iter().map(|g| (g.subject.as_str(), g.area)).collect();
    let refund = "adp_payments.issue_refund";
    for expected in [
        (refund, Area::Finality),
        (refund, Area::Witness),
        (refund, Area::Owner),
        (refund, Area::Intent),
        ("deployment", Area::Evidence),
        ("deployment", Area::Actor),
    ] {
        assert!(areas.contains(&expected), "{expected:?} missing from {areas:?}");
    }
    assert_eq!(
        areas
            .iter()
            .filter(|(s, a)| *s == refund && *a == Area::Finality)
            .count(),
        2,
        "completion and reference pointer are both missing"
    );
    assert!(
        found
            .gaps
            .iter()
            .any(|g| g.subject.ends_with("requirement identity_verified")),
        "{:?}",
        found.gaps
    );
    assert!(
        !found
            .gaps
            .iter()
            .any(|g| g.subject.ends_with("requirement policy.eval")),
        "a declared global requirement needs no binding"
    );
    assert!(!areas.contains(&(refund, Area::Resource)), "the refund names its order");
}

#[test]
fn required_refuses_with_every_gap_and_report_warns() {
    let required = config("", PROFILE);
    let error = report(&required, &packs(), &[bare_refund()]).unwrap_err();
    assert!(error.starts_with("workflow readiness (required): "), "{error}");
    assert!(
        error.contains("adp_payments.issue_refund [witness]: no outcome contract"),
        "{error}"
    );
    assert!(
        error.contains("deployment [actor]: agent_binding = \"observe\""),
        "{error}"
    );

    let reported = config("", &format!("{PROFILE}mode = \"report\"\n"));
    let lines = report(&reported, &packs(), &[bare_refund()]).unwrap();
    assert!(
        lines[0].starts_with("warning: workflow readiness (report): "),
        "{lines:?}"
    );
    assert!(
        lines.iter().skip(1).all(|l| l.starts_with("warning: readiness: ")),
        "{lines:?}"
    );
}

#[test]
fn a_guarantee_without_an_owner_is_a_gap() {
    let unowned = READY.replace("owner_route = \"refund_owners\"\n", "");
    let config = config(STRICT, &format!("{unowned}{PROFILE}"));
    let found = evaluate(&config, &packs(), &[ready_refund()]).unwrap().unwrap();
    assert_eq!(found.gaps.len(), 1, "{:?}", found.gaps);
    assert_eq!(found.gaps[0].area, Area::Owner);
    assert!(found.gaps[0].detail.contains("owner_route"), "{}", found.gaps[0]);
}

#[test]
fn a_capability_without_a_resource_is_a_gap() {
    let unanchored = manifest("issue_refund", |m| {
        m["recovery"]["completion"] = json!({"state_pointer": "/status", "confirmed": ["succeeded"]});
        m["recovery"]["reference_pointer"] = json!("/refund_id");
        m["outcome"] = json!({"witness": "refund-ledger", "postcondition": "refund_posted", "within_seconds": 900, "binds": "effect"});
        m["resource_pointers"] = json!([]);
        m["intent"] = json!({"key_pointers": ["/order_id", "/amount_minor"]});
    });
    let config = config(STRICT, &format!("{READY}{PROFILE}"));
    let found = evaluate(&config, &packs(), &[unanchored]).unwrap().unwrap();
    assert_eq!(found.gaps.iter().map(|g| g.area).collect::<Vec<_>>(), [Area::Resource]);
}

#[test]
fn named_capabilities_must_exist_and_be_consequential() {
    let unknown = config("", "[readiness]\ncapabilities = [\"adp_payments.void\"]\n");
    let error = evaluate(&unknown, &packs(), &[bare_refund()]).unwrap().unwrap_err();
    assert!(error.contains("not a configured capability"), "{error}");

    let read_only = config("", "[readiness]\ncapabilities = [\"adp_orders.lookup\"]\n");
    let error = evaluate(&read_only, &packs(), &[lookup()]).unwrap().unwrap_err();
    assert!(error.contains("changes no external state"), "{error}");
}

#[test]
fn a_global_requirement_cannot_also_be_bound() {
    let text = read("examples/support-refund/contextosd.toml")
        .replace("sha256:REPLACED_BY_RUN_SH", &format!("sha256:{}", "ab".repeat(32)));
    let error = Config::parse(&format!(
        "{text}\n{READY}[readiness]\nglobal_evidence = [\"identity_verified\"]\n"
    ))
    .unwrap_err()
    .to_string();
    assert!(error.contains("either about a subject or not"), "{error}");
}

#[test]
fn a_global_requirement_no_pack_asks_for_is_noted() {
    let config = config(
        STRICT,
        &format!("{READY}[readiness]\nmode = \"report\"\nglobal_evidence = [\"policy.eval\", \"kyc_program\"]\n"),
    );
    let lines = report(&config, &packs(), &[ready_refund()]).unwrap();
    assert!(
        lines.contains(&"warning: [readiness] global_evidence kyc_program is required by no loaded pack".to_owned()),
        "{lines:?}"
    );
}

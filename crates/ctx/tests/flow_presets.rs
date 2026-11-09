//! `ctx init-tool --preset` labels GitHub, database and CRM tools so that the "lethal
//! trifecta" (text outsiders wrote, private data, a way out) is gated: a run that read
//! private code cannot write it to a public issue or pull request.

use std::process::Command;

use contextos_gateway::CapabilityManifest;
use contextos_gateway::information_flow::{Classification, FlowPolicy, FlowVerdict, Integrity, RunLabels};
use serde_json::{Value, json};

fn ctx(args: &[&str]) -> (i32, Value) {
    let out = Command::new(env!("CARGO_BIN_EXE_ctx")).args(args).output().unwrap();
    (
        out.status.code().unwrap(),
        serde_json::from_slice(&out.stdout).unwrap_or(Value::Null),
    )
}

fn listed(names: &[&str]) -> String {
    let tools: Vec<Value> = names
        .iter()
        .map(|n| json!({"name": n, "inputSchema": {"type": "object"}}))
        .collect();
    let dir = std::env::temp_dir().join(format!("ctx-presets-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{}.json", names[0]));
    std::fs::write(&path, json!({"tools": tools}).to_string()).unwrap();
    path.display().to_string()
}

fn draft(preset: &str, tool: &str) -> Value {
    let (code, draft) = ctx(&[
        "init-tool",
        "--mcp",
        &listed(&[tool]),
        "--tool",
        tool,
        "--adapter",
        "adp_github",
        "--preset",
        preset,
    ]);
    assert_eq!(code, 0, "{draft}");
    draft
}

/// A reviewed manifest carrying the draft's flow labels.
fn reviewed(draft: &Value, effect: &str) -> CapabilityManifest {
    let read = effect == "none";
    let mut m = json!({
        "capability_id": draft["capability_id"], "capability_version": "1", "adapter_id": "adp_github",
        "protocol_tool": draft["protocol_tool"], "purpose_id": "dev.triage", "desired_effect": "done",
        "action_risk": {"effect": effect, "authority": "service",
            "reversibility": if read { "read_only" } else { "compensatable" },
            "interaction": "api", "data_scope": "CONFIDENTIAL"},
        "approval_mode": if read { "read_only" } else { "network" },
        "resource_pointers": [], "destination_pointers": [],
        "recovery": {"strategy": "no_retry", "max_attempts": 1, "retry_delays_seconds": []},
        "timeout_ms": 1000, "reservation": {"tokens": 0, "tool_calls": 1, "replans": 0, "cost_units": 0},
        "adapter_ref": {"artifact_type": "adapter", "artifact_id": "github", "version": "1",
            "sha256": "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
        "capability_ref": {"artifact_type": "capability", "artifact_id": "x", "version": "1",
            "sha256": "sha256:2222222222222222222222222222222222222222222222222222222222222222"},
    });
    m["flow"] = draft["flow"].clone();
    if draft["sends_data"] == true {
        m["sends_data"] = json!(true);
    }
    let manifest: CapabilityManifest = serde_json::from_value(m).unwrap();
    manifest.validate().unwrap();
    manifest
}

fn after(read: &[&CapabilityManifest]) -> RunLabels {
    read.iter().fold(
        RunLabels {
            integrity: Integrity::Trusted,
            classification: Classification::Public,
        },
        |labels, m| {
            let flow = m.flow.clone().unwrap_or_default();
            RunLabels {
                integrity: labels.integrity.max(flow.output_integrity),
                classification: labels.classification.max(flow.output_classification),
            }
        },
    )
}

#[test]
fn github_tools_are_labelled_by_what_they_read_and_where_they_write() {
    let issue = draft("github", "get_issue");
    assert_eq!(
        issue["flow"],
        json!({"output_integrity": "untrusted", "output_classification": "PUBLIC", "egress_ceiling": "INTERNAL"})
    );
    assert!(
        issue["description"]
            .as_str()
            .unwrap()
            .contains("preset github, rule discussion_read")
    );
    let file = draft("github", "get_file_contents");
    assert_eq!(file["flow"]["output_classification"], "CONFIDENTIAL");
    for write in ["create_pull_request", "add_issue_comment", "push_files"] {
        let w = draft("github", write);
        assert_eq!(w["flow"]["egress_ceiling"], "PUBLIC", "{write}");
        assert_eq!(w["sends_data"], true, "{write}");
    }
    // Reading comments is not writing them.
    assert!(draft("github", "get_pull_request_comments").get("sends_data").is_none());
    // Never trusted, and an unmatched tool is left for the reviewer.
    for tool in ["get_issue", "search_code", "list_commits"] {
        assert_eq!(draft("github", tool)["flow"]["output_integrity"], "untrusted", "{tool}");
    }
    let unknown = draft("github", "zzz_tool");
    assert!(unknown.get("flow").is_none());
    assert!(unknown["description"].as_str().unwrap().contains("no rule matched"));
    assert_eq!(
        ctx(&[
            "init-tool",
            "--mcp",
            &listed(&["x"]),
            "--tool",
            "x",
            "--adapter",
            "a",
            "--preset",
            "erp"
        ])
        .0,
        2
    );
}

#[test]
fn private_code_cannot_reach_a_public_pull_request() {
    let issue = reviewed(&draft("github", "get_issue"), "none");
    let file = reviewed(&draft("github", "get_file_contents"), "none");
    let comment = reviewed(&draft("github", "add_issue_comment"), "external_state");
    let pr = reviewed(&draft("github", "create_pull_request"), "external_state");
    let policy = FlowPolicy::default();

    // Read an issue, then comment: text an outsider wrote steers an effect, so ask.
    let triage = policy.check(after(&[&issue]), &comment);
    assert_eq!(triage.verdict, FlowVerdict::Ask, "{:?}", triage.reason_codes);
    assert!(!triage.reason_codes.contains(&"flow_classified_egress".to_owned()));

    // The injected-issue attack: read the issue, then private code, then open a PR.
    let leak = policy.check(after(&[&issue, &file]), &pr);
    assert_eq!(leak.verdict, FlowVerdict::Deny, "{:?}", leak.reason_codes);
    assert!(leak.reason_codes.contains(&"flow_classified_egress".to_owned()));
    assert!(leak.reason_codes.contains(&"flow_rule_of_two".to_owned()));
}

#[test]
fn database_and_crm_reads_are_confidential_and_sends_are_egress() {
    let rows = draft("database", "execute_query");
    assert_eq!(rows["flow"]["output_classification"], "CONFIDENTIAL");
    assert_eq!(draft("database", "export_table")["sends_data"], true);
    let contact = draft("crm", "get_contact");
    assert_eq!(contact["flow"]["output_classification"], "CONFIDENTIAL");
    let email = draft("crm", "send_email");
    assert_eq!(email["sends_data"], true);
    assert_eq!(email["flow"]["egress_ceiling"], "INTERNAL");
    // Personal data read in a run cannot be emailed out.
    let read = reviewed(&contact, "none");
    let send = reviewed(&email, "external_state");
    let out = FlowPolicy::default().check(after(&[&read]), &send);
    assert_eq!(out.verdict, FlowVerdict::Deny, "{:?}", out.reason_codes);
}

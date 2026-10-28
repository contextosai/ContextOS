//! Governance correctness that does not need a runtime: review expiry, pack identity
//! across sources, and the records' journal outbox.

use std::sync::Arc;

use contextos_audit::{AuditSigner, AuditWriter};
use contextos_store::{AppendLog, DocKey, DocKind, DocumentStore, MemoryLog, MemoryStore};
use serde_json::{Value, json};
use towerd::fleet::{AgentActivity, Counts, Fleet};
use towerd::governance;
use towerd::records::{NAMESPACE, RecordError, Records, array};

const NOW: &str = "2026-10-28T12:00:00.000000Z";

fn pack(effect: &str) -> Value {
    json!({"tooling_layer": {"adapter_registry": [{"adapter_id": "pay", "capabilities": ["refund"],
        "approval_mode": "destructive", "capability_risks": {"refund": {"effect": effect, "authority": "service",
        "reversibility": "irreversible", "interaction": "api", "data_scope": "INTERNAL"}}}]},
        "policy_layer": {"approval_gates": []}})
}

/// An agent that ran `p@1` in source `eu`.
fn fleet() -> Fleet {
    let mut fleet = Fleet::new(10, 48);
    let mut a = AgentActivity {
        key: "acme/bot".into(),
        agent_id: "bot".into(),
        runs: 3,
        first_seen: "2026-10-21T10:00:00Z".into(),
        last_seen: "2026-10-21T10:00:00Z".into(),
        ..AgentActivity::default()
    };
    a.packs.insert("p@1".into());
    a.source_packs.insert(("eu".into(), "p@1".into()));
    a.sources.insert("eu".into());
    a.capabilities.insert("pay.refund".into(), Counts::default());
    fleet.source("eu").packs = json!({"packs": [{"pack_ref": "p@1", "pack": pack("external_state")}]});
    fleet.agents.insert(a.key.clone(), a);
    fleet
}

/// The risk `pack("external_state")` declares for `pay.refund`.
static REFUND_RISK: std::sync::LazyLock<Value> = std::sync::LazyLock::new(|| {
    json!({"effect": "external_state", "authority": "service", "reversibility": "irreversible",
        "interaction": "api", "data_scope": "INTERNAL", "approval_mode": "destructive"})
});

/// An approval of `pay.refund` at `risk`, valid until `expires_at`.
fn review(expires_at: &str, risk: Value) -> Value {
    json!({"acme/bot": {"decision": "approved", "capabilities": ["pay.refund"],
        "capability_risks": {"pay.refund": risk},
        "reviewed_at": "2026-01-01T00:00:00.000000Z", "expires_at": expires_at}})
}

fn rules(fleet: &Fleet, reviews: &Value, now: &str) -> Vec<(String, String)> {
    let views = governance::views(fleet, &json!({}), reviews, now);
    governance::findings(fleet, &views, &json!([]), &json!([]), now)
        .into_iter()
        .map(|f| (f.rule, f.title))
        .collect()
}

#[test]
fn an_approval_stops_counting_when_it_expires() {
    let fleet = fleet();
    let reviews = review("2026-06-01T00:00:00.000000Z", REFUND_RISK.clone());

    let before = governance::views(&fleet, &json!({}), &reviews, "2026-05-01T00:00:00.000000Z");
    assert!(before[0].approved && !before[0].review_expired);
    assert!(
        !rules(&fleet, &reviews, "2026-05-01T00:00:00.000000Z")
            .iter()
            .any(|(r, _)| r == "unreviewed")
    );

    let after = governance::views(&fleet, &json!({}), &reviews, NOW);
    assert!(!after[0].approved && after[0].review_expired);
    assert_eq!(governance::facts(&after[0])["reviewed"], false);
    let found = rules(&fleet, &reviews, NOW);
    let (_, title) = found
        .iter()
        .find(|(r, _)| r == "unreviewed")
        .expect("an expired review is no review");
    assert!(title.contains("expired"), "{title}");

    // An approval without an expiry never counts.
    let undated = json!({"acme/bot": {"decision": "approved", "capabilities": ["pay.refund"]}});
    assert!(!governance::views(&fleet, &json!({}), &undated, NOW)[0].approved);
}

#[test]
fn a_pack_version_resolves_within_the_source_that_ran_it() {
    let mut fleet = fleet();
    // Another source publishes different content under the same id@version; it sorts
    // after `eu`, so a global index would have let it replace eu's pack.
    fleet.source("us").packs = json!({"packs": [{"pack_ref": "p@1", "pack": pack("none")}]});
    let views = governance::views(&fleet, &json!({}), &json!({}), NOW);
    assert_eq!(views[0].graph[0].effect, "external_state");

    let found = rules(&fleet, &json!({}), NOW);
    assert!(
        found
            .iter()
            .any(|(r, t)| r == "pack_version_conflict" && t.contains("eu, us")),
        "{found:?}"
    );

    // Identical content in both sources is not a conflict.
    fleet.source("us").packs = json!({"packs": [{"pack_ref": "p@1", "pack": pack("external_state")}]});
    assert!(
        !rules(&fleet, &json!({}), NOW)
            .iter()
            .any(|(r, _)| r == "pack_version_conflict")
    );
}

fn records() -> (Arc<MemoryStore>, Records<MemoryStore, MemoryLog>) {
    let store = Arc::new(MemoryStore::new());
    let journal = Arc::new(AuditWriter::new(MemoryLog::new(), AuditSigner::from_seed("j", [7; 32])));
    (store.clone(), Records::new(store, journal))
}

async fn journal(records: &Records<MemoryStore, MemoryLog>) -> Vec<Value> {
    let rows = records.journal().log().range(NAMESPACE, 1, 500).await.unwrap();
    rows.into_iter().map(|r| r.body).collect()
}

/// Activates draft `g1`, as Tower's guardrail activation does.
async fn activate(records: &Records<MemoryStore, MemoryLog>, by: &str) -> Result<(), RecordError> {
    records
        .change(
            "guardrails",
            "guardrail_activated",
            json!({"id": "g1", "by": by}),
            NOW,
            |items| {
                let g = array(items)
                    .iter_mut()
                    .find(|g| g["id"] == "g1")
                    .ok_or(RecordError::NotFound)?;
                if g["status"] != "draft" {
                    return Err(RecordError::Conflict("only a draft can be activated"));
                }
                g["status"] = json!("active");
                Ok(())
            },
        )
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_committed_changes_are_journaled() {
    // Two reviewers activate the same draft at once: one commits, the other is refused
    // on its compare-and-swap retry, and only the committed activation is signed.
    for _ in 0..50 {
        let (_, records) = records();
        let records = Arc::new(records);
        records
            .change("guardrails", "guardrail_drafted", json!({"id": "g1"}), NOW, |items| {
                array(items).push(json!({"id": "g1", "status": "draft"}));
                Ok(())
            })
            .await
            .unwrap();
        let (r1, r2) = (records.clone(), records.clone());
        let (a, b) = tokio::join!(
            tokio::spawn(async move { activate(&r1, "risk-a").await }),
            tokio::spawn(async move { activate(&r2, "risk-b").await })
        );
        let (a, b) = (a.unwrap(), b.unwrap());
        assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1, "{a:?} {b:?}");
        let kinds: Vec<Value> = journal(&records).await.iter().map(|e| e["kind"].clone()).collect();
        assert_eq!(kinds, [json!("guardrail_drafted"), json!("guardrail_activated")]);
        assert!(
            journal(&records)
                .await
                .iter()
                .all(|e| e["payload"]["change_id"].is_string())
        );
    }
}

#[tokio::test]
async fn a_change_committed_before_a_crash_is_journaled_once() {
    let (store, records) = records();
    // The state a crash leaves between the commit and the journal append.
    let key = DocKey::new(NAMESPACE, DocKind::Governance, "waivers");
    let pending = json!({"change_id": "c1", "kind": "waiver_requested", "payload": {"id": "w1", "change_id": "c1"},
        "at": NOW, "after": 0});
    store
        .create(
            &key,
            &json!({"items": [{"id": "w1", "status": "requested"}], "pending": [pending]}),
        )
        .await
        .unwrap();
    records.recover("waivers").await.unwrap();
    records.recover("waivers").await.unwrap();
    let entries = journal(&records).await;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["payload"]["change_id"], "c1");
    assert_eq!(store.get(&key).await.unwrap().unwrap().body["pending"], json!([]));

    // A crash after the append but before the pending mark was cleared: recovery finds
    // the entry in the journal and does not sign it again.
    let doc = store.get(&key).await.unwrap().unwrap();
    store
        .compare_and_swap(
            &key,
            doc.revision,
            &json!({"items": doc.body["items"], "pending": [pending]}),
        )
        .await
        .unwrap();
    records
        .change("waivers", "waiver_decided", json!({"id": "w1"}), NOW, |_| Ok(()))
        .await
        .unwrap();
    let kinds: Vec<Value> = journal(&records).await.iter().map(|e| e["kind"].clone()).collect();
    assert_eq!(kinds, [json!("waiver_requested"), json!("waiver_decided")]);
}

#[test]
fn a_risk_change_under_the_same_id_voids_the_approval() {
    let fleet = fleet();
    let valid = "2027-01-01T00:00:00.000000Z";
    let same = governance::views(&fleet, &json!({}), &review(valid, REFUND_RISK.clone()), NOW);
    assert!(same[0].approved && same[0].risk_changed.is_empty());

    // Every reviewed dimension counts, the approval mode included.
    for (field, reviewed) in [
        ("approval_mode", "network"),
        ("reversibility", "compensatable"),
        ("authority", "human_approved"),
    ] {
        let mut risk = REFUND_RISK.clone();
        risk[field] = json!(reviewed);
        let reviews = review(valid, risk);
        let view = &governance::views(&fleet, &json!({}), &reviews, NOW)[0];
        assert!(!view.approved, "{field}");
        assert_eq!(view.risk_changed, ["pay.refund"], "{field}");
        assert_eq!(governance::facts(view)["reviewed"], false);
        let found = governance::findings(&fleet, std::slice::from_ref(view), &json!([]), &json!([]), NOW);
        let drift = found.iter().find(|f| f.rule == "authority_drift").expect("drift");
        assert_eq!(drift.evidence["risk_changed"][0]["reviewed"][field], reviewed);
        assert!(!found.iter().any(|f| f.rule == "unreviewed"), "reported once, as drift");
    }

    // A review that recorded no risk cannot vouch for any.
    let legacy = json!({"acme/bot": {"decision": "approved", "capabilities": ["pay.refund"], "expires_at": valid}});
    let view = &governance::views(&fleet, &json!({}), &legacy, NOW)[0];
    assert!(!view.approved && view.risk_changed == ["pay.refund"]);
}

#[test]
fn packs_disagreeing_on_a_capabilitys_risk_yield_the_most_consequential() {
    let mut fleet = fleet();
    // A second pack the agent runs under pins pay.refund as read-only, and sorts first.
    let mut safe = pack("none");
    let risks = &mut safe["tooling_layer"]["adapter_registry"][0]["capability_risks"]["refund"];
    risks["reversibility"] = json!("read_only");
    risks["data_scope"] = json!("PUBLIC");
    risks["authority"] = json!("human_approved");
    safe["tooling_layer"]["adapter_registry"][0]["approval_mode"] = json!("read_only");
    fleet.source("eu").packs["packs"]
        .as_array_mut()
        .unwrap()
        .insert(0, json!({"pack_ref": "a@1", "pack": safe}));
    let agent = fleet.agents.get_mut("acme/bot").unwrap();
    agent.packs.insert("a@1".into());
    agent.source_packs.insert(("eu".into(), "a@1".into()));

    let views = governance::views(&fleet, &json!({}), &json!({}), NOW);
    let cap = &views[0].graph[0];
    assert!(cap.risk_conflict);
    assert_eq!(
        cap.risk(),
        *REFUND_RISK,
        "no dimension is lowered by the read-only declaration"
    );
    let found = rules(&fleet, &json!({}), NOW);
    assert!(found.iter().any(|(r, _)| r == "capability_risk_conflict"), "{found:?}");
}

#[test]
fn ids_created_in_the_same_millisecond_stay_distinct() {
    let ids: Vec<String> = (0..2000).map(|_| towerd::records::new_id()).collect();
    let distinct: std::collections::BTreeSet<&String> = ids.iter().collect();
    assert_eq!(distinct.len(), ids.len());
    assert!(ids.iter().all(|id| id.len() == 32));
    // The loop is fast enough that ids share a millisecond, where a 12-hex-character
    // prefix (the old id) would have collided.
    let prefixes: std::collections::BTreeSet<&str> = ids.iter().map(|id| &id[..12]).collect();
    assert!(prefixes.len() < ids.len(), "no two ids shared a millisecond");

    let mut items = json!([]);
    let record = json!({"id": ids[0]});
    towerd::records::push_new(&mut items, &record).unwrap();
    assert!(matches!(
        towerd::records::push_new(&mut items, &record),
        Err(RecordError::Conflict(_))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_later_change_waits_for_a_stalled_writers_entry() {
    let (store, records) = records();
    let records = Arc::new(records);
    records
        .change("waivers", "waiver_requested", json!({"id": "w1"}), NOW, |items| {
            array(items).push(json!({"id": "w1", "status": "requested"}));
            Ok(())
        })
        .await
        .unwrap();
    // A writer committed change 2 and stalled before journaling it, holding its lease.
    let key = DocKey::new(NAMESPACE, DocKind::Governance, "waivers");
    let doc = store.get(&key).await.unwrap().unwrap();
    let stalled = json!({"change_id": "stalled", "kind": "waiver_decided", "at": NOW, "after": 1,
        "payload": {"id": "w1", "change_id": "stalled", "collection": "waivers", "collection_seq": 2},
        "claimed_until": u64::MAX});
    store
        .compare_and_swap(
            &key,
            doc.revision,
            &json!({"items": doc.body["items"], "pending": [stalled], "seq": 2}),
        )
        .await
        .unwrap();

    let later = records.clone();
    let task = tokio::spawn(async move {
        later
            .change("waivers", "waiver_withdrawn", json!({"id": "w1"}), NOW, |_| Ok(()))
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert!(
        !task.is_finished(),
        "a later change must not commit ahead of a pending entry"
    );
    assert_eq!(journal(&records).await.len(), 1);

    // The stalled writer resumes: it journals its entry and clears the mark.
    records
        .journal()
        .append(NAMESPACE, "waiver_decided", stalled["payload"].clone(), NOW)
        .await
        .unwrap();
    let doc = store.get(&key).await.unwrap().unwrap();
    let mut body = doc.body.clone();
    body["pending"] = json!([]);
    store.compare_and_swap(&key, doc.revision, &body).await.unwrap();

    task.await.unwrap().unwrap();
    let entries = journal(&records).await;
    let order: Vec<(Value, Value)> = entries
        .iter()
        .map(|e| (e["kind"].clone(), e["payload"]["collection_seq"].clone()))
        .collect();
    assert_eq!(
        order,
        [
            (json!("waiver_requested"), json!(1)),
            (json!("waiver_decided"), json!(2)),
            (json!("waiver_withdrawn"), json!(3)),
        ]
    );
}

#[test]
fn merged_interaction_kinds_keep_every_kinds_controls() {
    let mut fleet = fleet();
    let variant = |interaction: &str| {
        let mut p = pack("external_state");
        p["tooling_layer"]["adapter_registry"][0]["capability_risks"]["refund"]["interaction"] = json!(interaction);
        p
    };
    fleet.source("eu").packs = json!({"packs": [
        {"pack_ref": "a@1", "pack": variant("browser")},
        {"pack_ref": "p@1", "pack": variant("computer")}]});
    let agent = fleet.agents.get_mut("acme/bot").unwrap();
    agent.source_packs.insert(("eu".into(), "a@1".into()));

    let views = governance::views(&fleet, &json!({}), &json!({}), NOW);
    let (cap, requirement) = (&views[0].graph[0], &views[0].requirement);
    assert_eq!(cap.interactions, ["browser".to_owned(), "computer".to_owned()].into());
    assert!(requirement.features.contains("external_network") && requirement.features.contains("arbitrary_code"));
    assert!(
        requirement.controls.contains("network.mediated") && requirement.controls.contains("isolation.required"),
        "{:?}",
        requirement.controls
    );
    let facts = governance::facts(&views[0]);
    assert_eq!(
        (
            facts["exposure"]["browser"].clone(),
            facts["exposure"]["computer"].clone()
        ),
        (json!(true), json!(true))
    );
    // Both kinds are part of the reviewed risk, so adding a variant is drift.
    assert_eq!(cap.risk()["interactions"], json!(["browser", "computer"]));
}

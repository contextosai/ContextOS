//! Circuit breakers stop an agent across runs once it makes too many effects or
//! collects too many refusals, and can trip the kill switch.

mod support;

use contextos_gateway::circuit_breakers::{BreakerCount, BreakerRule, BreakerScope, BreakerTrip};
use contextos_store::AppendLog;
use serde_json::{Value, json};
use support::*;

fn rule(count: BreakerCount, threshold: u64, trip: BreakerTrip) -> BreakerRule {
    BreakerRule {
        id: "support_agent".into(),
        scope: BreakerScope::Agent,
        count,
        capabilities: vec![],
        threshold,
        window_seconds: 60,
        trip,
    }
}

fn refund(id: &str, order: &str) -> Value {
    let mut c = call(id, Some(id));
    c["args"]["order_id"] = json!(order);
    c
}

async fn audited(h: &Harness, kind: &str) -> Vec<Value> {
    h.audit
        .log()
        .range(&h.admission.tenant_id, 1, 1000)
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.body["kind"] == kind)
        .map(|r| r.body["payload"].clone())
        .collect()
}

#[tokio::test]
async fn too_many_effects_open_the_breaker_and_it_trips_once() {
    let mut h = harness("allow", Behavior::Confirm).await;
    h.gateway
        .set_circuit_breakers(vec![rule(BreakerCount::Effects, 2, BreakerTrip::Refuse)]);
    for (id, order) in [("tc_1", "ord_1"), ("tc_2", "ord_2")] {
        let out = h.gateway.dispatch(&h.admission, &refund(id, order)).await.unwrap();
        assert_eq!(out.report.status, "completed", "{:?}", out.report);
    }
    for (id, order) in [("tc_3", "ord_3"), ("tc_4", "ord_4")] {
        let out = h.gateway.dispatch(&h.admission, &refund(id, order)).await.unwrap();
        assert_eq!(out.report.status, "blocked", "{:?}", out.report);
        assert_eq!(out.report.reason_codes, ["circuit_open"]);
    }
    let trips = audited(&h, "circuit_breaker_tripped").await;
    assert_eq!(trips.len(), 1, "one trip per window");
    assert_eq!(trips[0]["breaker_id"], "support_agent");
    assert_eq!(trips[0]["target"], "agt_support");
    assert_eq!(h.adapter.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_revoking_breaker_stops_the_agent_until_an_operator_restores_it() {
    let mut h = harness("allow", Behavior::Confirm).await;
    h.gateway
        .set_circuit_breakers(vec![rule(BreakerCount::Effects, 1, BreakerTrip::Revoke)]);
    let first = h
        .gateway
        .dispatch(&h.admission, &refund("tc_1", "ord_1"))
        .await
        .unwrap();
    assert_eq!(first.report.status, "completed", "{:?}", first.report);
    let tripped = h
        .gateway
        .dispatch(&h.admission, &refund("tc_2", "ord_2"))
        .await
        .unwrap();
    assert_eq!(tripped.report.reason_codes, ["circuit_open"]);
    let revoked = h.gateway.revocations(&h.admission.tenant_id).await.unwrap();
    assert_eq!(revoked["revoked"][0]["kind"], "agent");
    assert_eq!(revoked["revoked"][0]["target"], "agt_support");
    assert_eq!(revoked["revoked"][0]["by"], "circuit_breaker:support_agent");
    let next = h
        .gateway
        .dispatch(&h.admission, &refund("tc_3", "ord_3"))
        .await
        .unwrap();
    assert_eq!(next.report.reason_codes, ["revoked_agent"], "the kill switch holds it");
}

#[tokio::test]
async fn repeated_refusals_open_a_refusal_breaker_and_its_own_refusals_do_not_count() {
    let mut h = harness("deny", Behavior::Confirm).await;
    h.gateway
        .set_circuit_breakers(vec![rule(BreakerCount::Refusals, 2, BreakerTrip::Refuse)]);
    for (id, order) in [("tc_1", "ord_1"), ("tc_2", "ord_2")] {
        let out = h.gateway.dispatch(&h.admission, &refund(id, order)).await.unwrap();
        assert_eq!(out.report.status, "blocked");
        assert!(!out.report.reason_codes.contains(&"circuit_open".to_owned()));
    }
    for (id, order) in [("tc_3", "ord_3"), ("tc_4", "ord_4")] {
        let out = h.gateway.dispatch(&h.admission, &refund(id, order)).await.unwrap();
        assert_eq!(out.report.reason_codes, ["circuit_open"]);
    }
    let key = contextos_store::DocKey::new(
        &h.admission.tenant_id,
        contextos_store::DocKind::CircuitBreaker,
        "support_agent:agent:agt_support",
    );
    let state = contextos_store::DocumentStore::get(h.store.as_ref(), &key)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(state.body["current"], 2, "circuit_open refusals are not counted");
}

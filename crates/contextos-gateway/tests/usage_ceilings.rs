//! A usage ceiling keeps counting however many calls a window holds (T64).

mod support;

use contextos_gateway::UsageKind;
use contextos_gateway::usage_ceilings::UsageCeiling;
use serde_json::json;
use support::*;

#[tokio::test]
async fn a_window_holds_more_calls_than_a_ledger_keeps_receipts() {
    let mut h = harness_with_limits("allow", Behavior::Confirm, 8, 1_000_000.0).await;
    let ceiling: UsageCeiling = serde_json::from_value(json!({"id": "agent-tokens", "resource": "tokens",
        "per": "agent", "limit": 1_000_000, "window_seconds": 86_400}))
    .unwrap();
    h.gateway.set_usage_ceilings(vec![ceiling]);
    // More settled calls than the 1,024 receipts a shared ledger keeps live at once:
    // settled receipts are archived as later calls settle, never refused as saturated.
    for _ in 0..1_100 {
        let reservation = h
            .gateway
            .reserve_usage(&h.admission, UsageKind::ModelCall, 1, 0)
            .await
            .unwrap();
        h.gateway
            .settle_usage(&h.admission, &reservation, Some((1, 0)), "meter", Some("m"))
            .await
            .unwrap();
    }
    assert!(
        h.gateway
            .reserve_usage(&h.admission, UsageKind::ModelCall, 1, 0)
            .await
            .is_ok()
    );
}

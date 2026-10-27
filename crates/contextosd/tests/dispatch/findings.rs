//! Shared findings over HTTP: an observation bound to a real governed tool call,
//! falsification, and notices delivered on the next tool result.

use serde_json::{Value, json};

use crate::harness::*;

#[tokio::test]
async fn findings_are_bound_to_recorded_calls_and_notices_ride_on_tool_results() {
    let w = world(&ALL_CONTROLS).await;
    let http = executor_client(2);
    let root: Value = admit(&w, &run_body("find_root", 1200)).await.json().await.unwrap();
    let child = http
        .post(format!("{}/v1/runs", w.base))
        .bearer_auth("acme-key")
        .json(&child_of(&root, "find_root", "find_a", "ctxpack.support@5.2.0"))
        .send()
        .await
        .unwrap();
    assert_eq!(child.status(), 201, "{}", child.text().await.unwrap());
    let post = |run: &'static str, suffix: &'static str, body: Value| {
        let http = http.clone();
        let url = format!("{}/v1/runs/{run}/{suffix}", w.base);
        async move {
            let response = http.post(url).bearer_auth("acme-key").json(&body).send().await.unwrap();
            let status = response.status().as_u16();
            (status, response.json::<Value>().await.unwrap())
        }
    };

    // A worker posts an urgent hypothesis; the root's next tool result carries it.
    let (status, _) = post(
        "find_a",
        "findings",
        json!({"finding_id": "uncharged", "kind": "claim",
        "statement": "Order ord_881 was never charged, so no refund is due.", "urgent": true}),
    )
    .await;
    assert_eq!(status, 201);
    let out = dispatch(&w, "find_root", &tool_call("find_root", "tc_1", 120_000)).await;
    assert_eq!(out["result"]["status"], "completed", "{out}");
    let notices = &out["result"]["metadata"]["notices"];
    assert_eq!(notices["pending"], 1, "{out}");
    assert_eq!(notices["notices"][0]["finding_id"], "uncharged");
    assert_eq!(notices["data_only"], true);
    conforms("ToolCallOutcome", &out);

    // The root's observation rests on the call the gateway just recorded.
    let (status, observed) = post(
        "find_root",
        "findings",
        json!({"finding_id": "refunded", "kind": "observed",
        "statement": "The refund for ord_881 was issued, so the order was charged.",
        "basis": {"operation_id": "refund:find_root"}, "refutes": "uncharged"}),
    )
    .await;
    assert_eq!(status, 201, "{observed}");
    assert_eq!(
        observed["finding"]["basis"]["action_digest"],
        out["report"]["action_digest"]
    );
    let (status, refused) = post(
        "find_root",
        "findings/uncharged/invalidate",
        json!({"reason": "Disproved"}),
    )
    .await;
    assert_eq!(
        (status, refused["error"]["code"].clone()),
        (409, json!("refutation_required"))
    );
    let (status, falsified) = post(
        "find_root",
        "findings/uncharged/invalidate",
        json!({"reason": "The refund shows a charge.", "refuted_by": "refunded"}),
    )
    .await;
    assert_eq!(status, 200, "{falsified}");
    assert_eq!(falsified["finding"]["status"], "invalidated");

    // The worker learns its hypothesis was falsified, until it acknowledges.
    let read = || {
        let http = http.clone();
        let url = format!("{}/v1/runs/find_a/notices", w.base);
        async move {
            http.get(url)
                .bearer_auth("acme-key")
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()
        }
    };
    let pending = read().await;
    assert_eq!(pending["pending"], 1, "{pending}");
    assert_eq!(pending["notices"][0]["kind"], "finding_invalidated");
    assert_eq!(pending["notices"][0]["by_run_id"], "find_root");
    let seq = pending["notices"][0]["seq"].clone();
    let (status, acked) = post("find_a", "notices/ack", json!({"through": seq})).await;
    assert_eq!((status, acked["pending"].clone()), (200, json!(0)));
    assert_eq!(read().await["pending"], 0);
    let (status, _) = post("find_a", "notices/ack", json!({"through": 99})).await;
    assert_eq!(status, 422);
}

# contextosd metric reference

Generated from what `GET /metrics` exports by
`CONTEXTOS_BLESS=1 cargo test -p contextosd --test generated`; do not edit by hand.
Labels are bounded: capabilities, packs and guarantees are the ones configured at
startup, and statuses and reason codes are the runtime's own. Tenants are not a
label; per-tenant evidence is in the audit chain. The governance sweep's gauges
(`contextos_shared_holds`, `contextos_shared_hold_oldest_seconds`,
`contextos_shared_receipts_fill_ratio`, `contextos_shared_ledgers_unreadable`,
`contextos_escalations_open`, `contextos_approvals_timed_out_total` and
`contextos_governance_sweep_completed_timestamp_seconds`)
come only from the replica leading the sweep.

| Metric | Type | Labels | Description |
|---|---|---|---|
| `contextos_admissions_total` | counter | `pack` | Admitted runs by Context Pack release. |
| `contextos_agent_binding_mismatches_total` | counter | `mode` | Runs whose declared agent their credential does not name, by binding mode. |
| `contextos_approval_decision_seconds` | histogram | none | Seconds from the gateway's approval request to the fastest approving decision, for redeemed approvals. |
| `contextos_approvals_redeemed_total` | counter | `capability` | Approvals redeemed for an operation, by capability. |
| `contextos_approvals_requested_total` | counter | `capability` | Approvals the gateway asked for, by capability. |
| `contextos_approvals_timed_out_total` | counter | none | Approval requests timed out by this leader's sweeps. |
| `contextos_audit_sink_batches_total` | counter | `sink`, `outcome` | Audit sink batches by sink and outcome. |
| `contextos_decisions_total` | counter | `status` | Recorded decisions by status. |
| `contextos_dispatch_outcomes_total` | counter | `capability`, `status` | Governed tool dispatches by capability and status. |
| `contextos_dispatch_refusals_total` | counter | `reason` | Reason codes of dispatches that did not complete. |
| `contextos_escalations_open` | gauge | none | Policy escalations awaiting a human, across tenants. |
| `contextos_governance_sweep_completed_timestamp_seconds` | gauge | none | When the last full governance sweep completed. |
| `contextos_http_request_duration_ms` | histogram | `route` | Request latency in milliseconds. |
| `contextos_http_requests_total` | counter | `route`, `status` | HTTP requests by route and status. |
| `contextos_notifications_total` | counter | `webhook`, `outcome` | Escalation notification attempts by webhook and outcome. |
| `contextos_pack_intent_mismatches_total` | counter | `mode` | Runs whose intent their Context Pack's rules do not name, by mode. |
| `contextos_replicas` | gauge | none | Live replicas sharing tenant limits. |
| `contextos_shared_guarantee_over_limit_imports_total` | counter | `guarantee` | Imported rows that left a resource over its guarantee's limit, by guarantee. |
| `contextos_shared_hold_oldest_seconds` | gauge | `guarantee` | Age of the oldest held receipt's attempt (0 when none). |
| `contextos_shared_holds` | gauge | `guarantee`, `state` | Held shared-guarantee receipts by diagnosed state, at the last full sweep (leader only). |
| `contextos_shared_ledgers_unreadable` | gauge | none | Exposure ledgers the last sweep could not read. |
| `contextos_shared_receipts_fill_ratio` | gauge | `guarantee` | Live receipts of the fullest ledger over the receipt cap. |
| `contextos_task_authorization_amendments_total` | counter | `change` | Amended task authorizations by change. |
| `contextos_upstream_tool` | gauge | `capability`, `status` | Each pinned capability's upstream tool status (1 for the current one). |
| `contextos_user_binding_mismatches_total` | counter | `reason` | Runs whose declared user their credential does not act for, by reason. |

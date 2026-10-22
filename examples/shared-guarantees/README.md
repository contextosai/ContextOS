# Two agents, one business ceiling

Run from the repository root:

```sh
./examples/shared-guarantees/run.sh
```

Prerequisites: the pinned Rust toolchain and Python 3.9+. The script builds debug
binaries and uses synthetic loopback services, temporary development credentials
and an in-memory store. No model key, cloud account or payment account is needed.

Two separately admitted agents, support email and support chat, each request
INR 800 from the same order. A trusted guarantee caps all mediated refunds on that
order at INR 1,000. Exactly one provider invocation succeeds; the competitor is
withheld before dispatch.

A third agent requests INR 150 and receives a pending MCP task. Its reservation
remains held, leaving INR 50 available. A further INR 100 request is withheld.
Querying the provider confirms the pending effect; the final balance is INR 950
committed and INR 50 available.

The example exports the audit and runs the offline Rust verifier. Expected output
ends with `"verified": true`; hashes and identifiers vary. It asserts the observed
balances and actual synthetic provider call count, so a failed invariant exits
nonzero. Services and temporary runtime files are cleaned up.

The verification uses the development runtime's published key as the trust anchor.
Production verification requires independently trusted keys/anchors. The demonstration
covers mediated numeric ceilings; it does not verify the real refundable balance of
an order. [Configuration, recovery and limitations](../../docs/SHARED_GUARANTEES.md).

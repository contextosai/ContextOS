# Two agents, one business ceiling

Run from the repository root, or from an unpacked release archive:

```sh
./examples/shared-guarantees/run.sh
```

Prerequisites: Python 3.9+ and Bash. In a source checkout the script builds debug
binaries with the pinned Rust toolchain; a release archive uses its `bin/`. It first
runs `examples/doctor.sh`, which checks that this system can run the binaries and
names the alternative when it cannot. The demo uses synthetic loopback services,
temporary development credentials and an in-memory store. No model key, cloud
account or payment account is needed.

A trusted guarantee caps all mediated refunds on order `ord_881` at INR 1,000. After
each step the demo prints the guarantee's `limit / committed / held / available`:

1. Two separately admitted agents each request INR 800. Exactly one provider call
   happens; the competitor is withheld before dispatch (`shared_guarantee_exceeded`).
2. A third agent requests INR 100. The synthetic provider applies the refund but drops
   the connection, so the outcome is unknown. Its reservation stays held: releasing it
   could let a later refund exceed the ceiling, and retrying could refund twice.
3. A fourth agent's INR 50 refund is accepted as a pending provider task and is also
   held. A further INR 100 request is withheld with INR 50 available.
4. Querying the provider's task confirms the pending refund.
5. The lost response left no task to query. An operator checks the provider's ledger
   and records the refund as confirmed, citing the export's digest. The final balance
   is INR 950 committed, nothing held and INR 50 available.

The demo asserts each balance and the synthetic provider's call count, so a broken
invariant exits nonzero. It then exports the audit log and verifies it offline with
`ctx audit-verify`; output ends with `"verified": true`, and hashes and identifiers
vary. The receipt stays in `receipts/shared-guarantees/` (set `CONTEXTOS_RECEIPT_DIR`
to change it): `entries.json` and `keys.json` for the audit, `balances.json` for each
step's balance, and `provider-ledger.json`, the export the operator cited. The demo
prints the command to verify it again yourself. Services and other temporary files
are cleaned up.

The verification uses the development runtime's published key as the trust anchor.
Production verification requires independently trusted keys/anchors. The runtime
records the operator's cited artifact but does not fetch or validate it. The
demonstration covers mediated numeric ceilings; it does not verify the real
refundable balance of an order.
[Configuration, recovery and limitations](../../docs/SHARED_GUARANTEES.md).

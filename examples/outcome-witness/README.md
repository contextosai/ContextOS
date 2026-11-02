# Outcome witness

The payment API confirming a refund says it accepted the call. The refund is done when
the refund ledger says it posted, for that order and amount. The quickstart's refund
capability declares an outcome contract here, and the run cannot record its decision
or complete until the ledger, an evidence issuer independent of the payment provider,
attests it. Synthetic and local: no model key, cloud account or payment service.

From the repository or release archive root:

```sh
./examples/outcome-witness/run.sh
```

Expected output:

```text
[payments] refund 120000 for ord_881 (operation refund:ord_881)
Payment API confirmed refund rf_ord_881 of INR 1200 for ord_881.
Decision and completion refused: outcome_pending (the ledger has not reported).
Ledger reading of INR 900 refused: outcome_amount_mismatch.
Ledger reading of another INR 1200 refund refused: outcome_receipt_mismatch.
Ledger reading of refund rf_ord_881 accepted: refund_posted witnessed.
Decision cites the ledger's reading: outcome:sha256:…
Run completed.
Offline audit verification: {... "verified": true}
outcome witnessed
```

What it shows:

- The manifest's `outcome` names the witness (`[[evidence_issuers]]` issuer
  `https://refund-ledger.example.test`), the postcondition `refund_posted`, a
  15-minute deadline and `binds = "effect"`: the reading must name the refund the
  payment API reported (`recovery.reference_pointer = "/refund_id"`), so a reading of
  another refund of the same order and amount cannot close it, and one reading closes
  one refund.
- After the provider confirms the refund, `record_decision(…, "DECIDED")` and
  `complete()` are refused with `outcome_pending`.
- The ledger signs readings with `ctx attest` (the development signer; a real ledger
  signs with its own key) and relays them with a key holding only `outcome:report`.
  A reading for the wrong amount or another refund is refused; the right one closes
  the outcome.
- The decision's tool lineage cites the reading (`artifact_refs`), the evidence bundle
  lists the run's outcomes, and the audit chain records `outcome_pending` and
  `outcome_witnessed`.

See [docs/GUIDE.md](../../docs/GUIDE.md), "Outcome contracts".

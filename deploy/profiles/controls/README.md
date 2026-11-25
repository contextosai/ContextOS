# Control packs

Ready-made runtime controls, one file per control family. Each is a `contextosd.toml`
snippet: append the ones you need to your configuration, replace the example
capability ids, pointers and amounts with yours, and run `contextosd --check-config`.
Every pack starts the quickstart configuration (`examples/support-refund`) on its own,
and all of them together except where noted; CI checks this.

| Pack | Controls | Notes |
|---|---|---|
| [spend-and-rate.toml](spend-and-rate.toml) | A per-agent daily refund ceiling shared by every run, an effect-rate circuit breaker, tenant request and dispatch limits | One guarantee covers a capability; the file shows the per-order alternative |
| [data-egress.toml](data-egress.toml) | Information flow: classified egress and effects after untrusted input need an approval of the exact call | Use this **or** `pii-touch.toml` (both set `[guards.information_flow]`) |
| [pii-touch.toml](pii-touch.toml) | Personal data never leaves through a tool not cleared for it; run content deleted after 30 days | Rule and metadata based: label outputs and egress ceilings in manifests. No content inspection |
| [destructive-actions.toml](destructive-actions.toml) | Risk tiers: unclassified and high-tier capabilities need an approval of the exact action, prohibited ones are refused; a refusal storm revokes the agent | Classify every capability you add |
| [environment-separation.toml](environment-separation.toml) | Effects aimed at another environment than this gateway's are refused | Name how each capability's arguments say which environment |
| [change-freeze.toml](change-freeze.toml) | A year-end freeze for every capability, and refunds out of office hours need an approval | Decided on the server clock; fixed UTC offsets |
| [human-in-the-loop.toml](human-in-the-loop.toml) | Approvals faster than a reading time do not count, large approvals need a recent strong sign-in, undecided approvals escalate | Which actions need approval is the pack's rule (`requires_approval_gate`) |

Each pack names the GUIDE section that explains its keys. Start a running deployment
with `observe` modes where a pack offers them, read the audit entries it writes, then
enforce.

Policy rules (what needs approval, what is denied) live in Context Packs. Share them
across packs as rule libraries (`contextos.rule_library.v1`), test them with
`ctx test --junit`, and see what a change would do with `ctx simulate`: GUIDE §5 and
`examples/support-refund/authoring`.

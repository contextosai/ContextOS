# ContextOS for Node.js

Two parts, published differently:

- `contextos-client` on npm is the HTTP client for `contextosd` (`client.mjs`, with
  TypeScript types in `client.d.ts`). It has no dependencies and runs anywhere `fetch`
  does: Node.js 18 or newer, edge and serverless runtimes.
- The in-process kernel (`index.mjs`, an N-API addon) is not published. Build it from
  this repository only if you embed the kernel without a server.

## The HTTP client

```sh
npm install contextos-client
```

```ts
import { Client, ToolPaused, ToolBlocked, governedTool } from "contextos-client";

const client = new Client("https://contextos.internal", { token: process.env.CONTEXTOS_TOKEN! });
const run = await client.admit(admissionBody);   // holds the executor generation
const output = await run.callTool("adp_payments.issue_refund", args,
  { approvalMode: "destructive", idempotencyKey: "refund:ord_881", evidenceRefs });
```

Results that are not plain success throw: `ToolPaused` (approval, input, or an unknown
outcome to reconcile: never retry blindly), `ToolBlocked`, `ToolRejected`,
`ToolFailed`. Only requests the server did not process (429, 503) are retried.

`run.checkToolCall(capabilityId, args, options)` answers what `callTool` would do with
the same call (`allowed`, `approval_required`, `escalation_required`, `blocked` or
`rejected`, with reason codes and obligations) without effect: nothing is requested,
reserved or sent, and the check is audited. It is advisory; `not_evaluated` names what
only dispatch decides.

Try it against a local server from a checkout: `./examples/dev-server.sh` prints
`CONTEXTOS_URL` and `CONTEXTOS_TOKEN`. The
[integration guides](https://github.com/contextosai/ContextOS/tree/main/docs/integrations)
show the client inside Mastra, the Vercel AI SDK and the OpenAI Agents SDK.

The client's version matches the `contextosd` release it was published with. Use the
same release on both sides while ContextOS is in alpha: before its first admission the
client emits a `VersionMismatchWarning` when the server is another release, and throws
`IncompatibleServer` for a server with another API generation. `checkServer: false`
skips the check.

## The embedded kernel

```sh
cargo build --release -p contextos-node
cp target/release/libcontextos_node.so bindings/node/contextos.node   # .dylib on macOS
```

```js
import { kernel } from "./bindings/node/index.mjs";
const compiled = await kernel.call("compile", { pack, request, run_context });
```

`CONTEXTOS_NATIVE` overrides the addon's path.

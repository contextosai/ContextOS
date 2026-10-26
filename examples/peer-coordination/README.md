# Peer task coordination

Two admitted read-only peers discover work, race to claim a task, recover an
abandoned lease, reject a stale completion and finish a dependency chain. The
recovered worker reads a synthetic order through the existing governed gateway;
no model key or external account is required.

From the repository or release archive root:

```sh
bash examples/peer-coordination/run.sh
```

Expected output includes:

```text
peers discovered two tasks; dependency blocks premature work
concurrent claims: exactly one winner
abandoned lease reclaimed; stale completion refused
dependency chain completed; evidence remains worker-reported
peer coordination complete; ordinary child acceptance and run completion retained
```

The demonstration deliberately abandons the first worker before it sends any tool
call. A real lease timeout says nothing about prior effects; inspect/reconcile the
previous worker's operations before repeating consequential work. Task evidence
is a worker report, not independent verification or accepted child output. See
[the guide](../../docs/PEER_COORDINATION.md) for the API, limits and trust boundaries.

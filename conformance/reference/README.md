# Pinned TypeScript reference

Copyright (c) 2025-2026 ContextOS. Licensed under Apache-2.0; see
[LICENSE](LICENSE) and [LICENSE-code](LICENSE-code) for the upstream terms.

The `src/lib/contextos/` and `tests/fixtures/` files are copied without modification
from `contextosai/contextosai` at revision
`7e2462fd931a79e3777ede81fb382e0cbf2ff46c`, the source recorded in
[source.json](../source.json). `SHA256SUMS` records the copied files, including the
upstream license files. From this directory, check them with:

```sh
shasum -a 256 -c SHA256SUMS
```

This snapshot makes conformance generation reproducible from a clone of the runtime
repository. Follow [the regeneration instructions](../README.md); the upstream
website repository is not required. Refresh the snapshot, checksums, source pin,
schemas and vectors together when reviewing an intentional specification update.

# Conformance vectors

`vectors/` holds golden inputs and outputs produced by the ContextOS spec's TypeScript
reference (`src/lib/contextos/` in the spec repo). Rust tests load them and require
byte-identical results, so behavior cannot drift silently from the spec.

## Source and licensing

[source.json](source.json) pins the exact upstream revision used for the copied
schemas and generated vectors. [reference/](reference/) contains an unmodified
snapshot of that revision's TypeScript reference and synthetic fixtures, with the
upstream license files and checksums. These files and the schemas are Apache-2.0;
the specification prose is CC BY 4.0. See [reference/LICENSE](reference/LICENSE)
for the upstream licensing boundaries.

The pinned revision was checked by comparing every copied schema and regenerating
all vectors in a temporary directory; vector contents matched after decompression.

## Reproduce

Install Node.js 24 or newer and npm 11.8.0. From this runtime's root:

```sh
(cd conformance/reference && shasum -a 256 -c SHA256SUMS)
npm ci --prefix conformance --ignore-scripts --no-fund
env -u CONTEXTOS_SPEC npm test --prefix conformance
git diff --exit-code -- conformance/vectors schemas
```

No other repository or private access is needed. CI regenerates the vectors from
this snapshot and rejects drift. Rust consumers can build and run the committed
conformance tests without installing Node.

For an intentional spec update, review the upstream contract changes and refresh
the licensed snapshot and its checksums from that exact Git revision. Copy the
affected schemas, regenerate the vectors, run the Rust conformance tests, and update
the source revision in the same change. Maintainers may set `CONTEXTOS_SPEC` to an
upstream checkout for comparison before refreshing the snapshot. Do not hand-edit
vectors or regenerate against an unreviewed moving branch.

Vectors are synthetic reference evidence. They show the runtime matches the reference
semantics; they do not establish deployed conformance of any workflow or environment.

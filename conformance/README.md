# Conformance vectors

`vectors/` holds golden inputs and outputs produced by the ContextOS spec's TypeScript
reference (`src/lib/contextos/` in the spec repo). Rust tests load them and require
byte-identical results, so behavior cannot drift silently from the spec.

## Source and licensing

[source.json](source.json) pins the exact [specification repository](https://github.com/contextosai/contextosai)
revision used for the copied schemas and generated vectors. The reference, schemas,
synthetic fixtures and code examples are licensed under Apache-2.0; specification
prose is CC BY 4.0. The website application's other assets retain their separate
rights. See the source repository's `LICENSE` for the boundaries.

The pinned revision was checked by comparing every copied schema and regenerating
all vectors in a temporary directory; vector contents matched after decompression.

## Reproduce

Install Node.js 24 or newer and the source repository's declared npm version. Run
these commands from this runtime's root; the sibling checkout can live anywhere:

```sh
git clone https://github.com/contextosai/contextosai.git ../contextos-spec
export CONTEXTOS_SPEC="$(cd ../contextos-spec && pwd)"
SPEC_REVISION=$(python3 -c 'import json; print(json.load(open("conformance/source.json"))["revision"])')
git -C "$CONTEXTOS_SPEC" checkout --detach "$SPEC_REVISION"
npm ci --prefix "$CONTEXTOS_SPEC"
"$CONTEXTOS_SPEC/node_modules/.bin/vitest" run --config conformance/generator/vitest.config.mts
git diff --exit-code -- conformance/vectors schemas
```

The source checkout must be accessible to you; opening this runtime does not change
the source repository's GitHub visibility. Rust consumers can build and run the
committed conformance tests without cloning the source repository or installing Node.

For an intentional spec update, review its contract changes, copy the affected
schemas, regenerate the vectors, run the Rust conformance tests, and update the source
revision in the same change. Do not hand-edit vectors or regenerate against an
unreviewed moving branch.

Vectors are synthetic reference evidence. They show the runtime matches the reference
semantics; they do not establish deployed conformance of any workflow or environment.

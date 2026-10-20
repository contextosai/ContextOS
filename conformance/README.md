# Conformance vectors

`vectors/` holds golden inputs and outputs produced by the ContextOS spec's TypeScript
reference (`src/lib/contextos/` in the spec repo). Rust tests load them and require
byte-identical results, so behavior cannot drift silently from the spec.

Regenerate after the spec reference changes:

```sh
CONTEXTOS_SPEC=/path/to/contextosai \
  $CONTEXTOS_SPEC/node_modules/.bin/vitest run --config conformance/generator/vitest.config.mts
```

Vectors are synthetic reference evidence. They show the runtime matches the reference
semantics; they do not establish deployed conformance of any workflow or environment.

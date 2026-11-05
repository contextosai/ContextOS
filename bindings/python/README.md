# ContextOS for Python

Two modules, one package:

- `contextos.client` (and `contextos.aio` for asyncio) talks to `contextosd` over
  HTTP. Standard library only: no compiled code, no dependencies.
- `contextos` itself is the kernel, in-process, through a compiled extension
  (`contextos._native`). You need it only to embed the kernel without a server.

## Install

```sh
pip install --pre contextos-client
```

Published on PyPI as `contextos-client` from 0.1.0-alpha.13; the module is still
`import contextos`. Linux (x86_64 and aarch64, glibc 2.28 or newer) and macOS on
Apple silicon get a wheel with the compiled kernel. Every other platform gets
a pure-Python wheel with the HTTP client only; kernel calls there raise
`native_unavailable`. Use the client release that matches your `contextosd`: before its
first admission the client warns (`VersionMismatchWarning`) when the server is another
release, and refuses (`IncompatibleServer`) a server with another API generation.

## The HTTP client (most agents)

From a checkout instead of the package index, put the package on your path or copy
`bindings/python/contextos/` into your project:

```sh
export PYTHONPATH=/path/to/ContextOS/bindings/python
python3 -c "from contextos.client import Client; print('ok')"
```

Try it against a local server: `./examples/dev-server.sh` prints `CONTEXTOS_URL` and
`CONTEXTOS_TOKEN`, and `examples/support-refund/requests/run.json` is a run you can
admit. `examples/frameworks/` shows the client inside eleven agent frameworks.

`run.check_tool_call(capability_id, args, ...)` answers what `run.call_tool` would do
with the same call (`allowed`, `approval_required`, `escalation_required`, `blocked` or
`rejected`, with reason codes and obligations) without effect: nothing is requested,
reserved or sent, and the check is audited. It is advisory; `not_evaluated` names what
only dispatch decides.

## The embedded kernel

The platform wheels above include it. To build the extension yourself, use
[maturin](https://www.maturin.rs/) (needs the Rust toolchain):

```sh
python3 -m pip install maturin
python3 -m pip install ./bindings/python    # or: cd bindings/python && maturin develop
python3 -c "import contextos; print(contextos.__version__)"
```

Without it, `import contextos` still works for the client; kernel calls raise an error
that says to build the extension.

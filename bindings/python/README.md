# ContextOS for Python

Two modules, one package:

- `contextos.client` (and `contextos.aio` for asyncio) talks to `contextosd` over
  HTTP. Standard library only: no compiled code, no dependencies.
- `contextos` itself is the kernel, in-process, through a compiled extension
  (`contextos._native`). You need it only to embed the kernel without a server.

Nothing is published to PyPI yet (alpha). Install from this repository.

## The HTTP client (most agents)

Put the package on your path, from a checkout or a release archive:

```sh
export PYTHONPATH=/path/to/ContextOS/bindings/python
python3 -c "from contextos.client import Client; print('ok')"
```

or copy `bindings/python/contextos/` into your project. Python 3.9 or newer.

Try it against a local server: `./examples/dev-server.sh` prints `CONTEXTOS_URL` and
`CONTEXTOS_TOKEN`, and `examples/support-refund/requests/run.json` is a run you can
admit. `examples/frameworks/` shows the client inside eleven agent frameworks.

## The embedded kernel

Build the extension with [maturin](https://www.maturin.rs/) (needs the Rust toolchain):

```sh
python3 -m pip install maturin
python3 -m pip install ./bindings/python    # or: cd bindings/python && maturin develop
python3 -c "import contextos; print(contextos.__version__)"
```

Without it, `import contextos` still works for the client; kernel calls raise an error
that says to build the extension.

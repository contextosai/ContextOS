"""Run with: PYTHONPATH=bindings/python python3 bindings/python/tests/test_contextos.py"""
import json
import pathlib
import threading

import contextos

ROOT = pathlib.Path(__file__).resolve().parents[3]
vectors = json.loads((ROOT / "conformance/vectors/compiler.json").read_text())

for case in vectors["cases"][:10]:
    compiled = contextos.compile(case["pack"], case["request"], case["run_context"], case["deps"])
    assert compiled["context_ledger"]["compiled_context_hash"] == case["expected"]["context_ledger"]["compiled_context_hash"], case["name"]

try:
    contextos.call("jsonlogic", {"logic": {"no_such_op": [1]}, "data": None})
    raise AssertionError("expected ContextOSError")
except contextos.ContextOSError as error:
    assert error.code == "jsonlogic_error"

assert contextos.canonicalize({"b": 1, "a": 2})["canonical"] == '{"a":2,"b":1}'
assert contextos.validate("execution-contract", {"control_id": "x", "control_version": "1", "z": 1}, "ControlRef")["valid"] is False

# The GIL is released during kernel calls; concurrent threads must all agree.
case = vectors["cases"][0]
results = []
threads = [threading.Thread(target=lambda: results.append(
    contextos.compile(case["pack"], case["request"], case["run_context"], case["deps"])["context_ledger"]["compiled_context_hash"]))
    for _ in range(8)]
[t.start() for t in threads]
[t.join() for t in threads]
assert len(set(results)) == 1 and len(results) == 8
print("python binding ok")

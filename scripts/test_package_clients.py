"""Tests for scripts/package_clients.py: run with
python3 -m unittest discover -s scripts -p 'test_*.py'"""
import csv
import importlib.util
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
import zipfile

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("package_clients", HERE / "package_clients.py")
pc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pc)


class VersionTest(unittest.TestCase):
    def test_pep440_matches_maturin(self):
        self.assertEqual(pc.pep440("0.1.0-alpha.11"), "0.1.0a11")
        self.assertEqual(pc.pep440("0.2.0-beta.3"), "0.2.0b3")
        self.assertEqual(pc.pep440("1.0.0-rc.1"), "1.0.0rc1")
        self.assertEqual(pc.pep440("1.0.0"), "1.0.0")
        with self.assertRaises(SystemExit):
            pc.pep440("1.0.0-dev")

    def test_facade_reports_the_workspace_version(self):
        pc.check_facade_version(pc.workspace_version())


class PythonWheelTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.wheel = pc.build_python(self.tmp.name)

    def test_name_and_members(self):
        version = pc.pep440(pc.workspace_version())
        self.assertEqual(self.wheel.name, f"contextos-{version}-py3-none-any.whl")
        with zipfile.ZipFile(self.wheel) as archive:
            names = set(archive.namelist())
        package = {n for n in names if n.startswith("contextos/")}
        self.assertEqual(package, {f"contextos/{n}" for n in pc.PY_SOURCES})
        self.assertFalse(any(n.endswith((".so", ".pyd", ".pyc")) for n in names))
        self.assertIn(f"contextos-{version}.dist-info/licenses/LICENSE", names)

    def test_record_covers_every_member(self):
        with zipfile.ZipFile(self.wheel) as archive:
            record_name = next(n for n in archive.namelist() if n.endswith("/RECORD"))
            rows = list(csv.reader(io.StringIO(archive.read(record_name).decode())))
            for path, digest, size in rows:
                if path == record_name:
                    self.assertEqual((digest, size), ("", ""))
                    continue
                data = archive.read(path)
                self.assertEqual(digest, pc._record_hash(data))
                self.assertEqual(int(size), len(data))
            self.assertEqual({r[0] for r in rows}, set(archive.namelist()))

    def test_reproducible(self):
        first = self.wheel.read_bytes()
        again = pc.build_python(self.tmp.name).read_bytes()
        self.assertEqual(first, again)

    def test_client_imports_from_the_wheel_without_the_extension(self):
        code = (
            "import contextos, contextos.client, contextos.aio\n"
            "assert contextos._native is None\n"
            "assert contextos.__version__ == %r\n"
            "try:\n"
            "    contextos.call('canonicalize', {})\n"
            "except contextos.ContextOSError as e:\n"
            "    assert e.code == 'native_unavailable'\n"
            "else:\n"
            "    raise AssertionError('kernel call without the extension')\n"
            "print(contextos.client.Client.__name__)\n"
        ) % pc.workspace_version()
        # -I: the wheel is the only place `contextos` can come from.
        result = subprocess.run(
            [sys.executable, "-I", "-c", f"import sys; sys.path.insert(0, {str(self.wheel)!r})\n" + code],
            capture_output=True, text=True, cwd=self.tmp.name,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "Client")


class NodePackageTest(unittest.TestCase):
    def test_package_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = pc.build_node(tmp)
            manifest = json.loads((out / "package.json").read_text())
            self.assertEqual(manifest["name"], "contextos-client")
            self.assertEqual(manifest["version"], pc.workspace_version())
            self.assertNotIn("private", manifest)
            self.assertEqual(manifest["exports"]["."]["default"], "./client.mjs")
            for name in manifest["files"]:
                self.assertTrue((out / name).is_file(), name)
            # Every relative import resolves inside the package.
            client = (out / "client.mjs").read_text()
            self.assertNotIn('from "./', client)
            self.assertNotIn('from "../', client)


if __name__ == "__main__":
    unittest.main()

import gzip
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("check_conformance.py")
PAYLOAD = b'{"cases":[{"expected":true}]}\n'


class ConformanceDriftTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.vector = self.root / "conformance/vectors/example.json.gz"
        self.plain = self.root / "conformance/vectors/plain.json"
        self.schema = self.root / "schemas/example.json"
        self.vector.parent.mkdir(parents=True)
        self.schema.parent.mkdir()
        self.vector.write_bytes(gzip.compress(PAYLOAD, compresslevel=9, mtime=0))
        self.plain.write_bytes(PAYLOAD)
        self.schema.write_text('{"type":"object"}\n')
        self.git("init", "-q")
        self.git("add", ".")
        self.git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-qm", "baseline")

    def git(self, *args):
        subprocess.run(["git", *args], cwd=self.root, check=True, capture_output=True)

    def check(self):
        return subprocess.run([sys.executable, str(SCRIPT), str(self.root)],
                              capture_output=True, text=True)

    def assert_drift(self, relative):
        result = self.check()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(relative, result.stderr)

    def test_different_compression_and_metadata_with_identical_bytes_pass(self):
        self.vector.write_bytes(gzip.compress(PAYLOAD, compresslevel=1, mtime=123))
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_changed_compressed_payload_fails(self):
        self.vector.write_bytes(gzip.compress(PAYLOAD.replace(b"true", b"false")))
        self.assert_drift("conformance/vectors/example.json.gz")

    def test_formatting_changes_in_decompressed_bytes_fail(self):
        self.vector.write_bytes(gzip.compress(PAYLOAD.replace(b"\":", b"\": ")))
        self.assert_drift("conformance/vectors/example.json.gz")

    def test_corrupt_compressed_vector_fails(self):
        self.vector.write_bytes(b"invalid gzip")
        self.assert_drift("conformance/vectors/example.json.gz")

    def test_plain_vector_and_schema_changes_fail(self):
        for path in [self.plain, self.schema]:
            with self.subTest(path=path):
                original = path.read_bytes()
                path.write_bytes(original + b" ")
                self.assert_drift(path.relative_to(self.root).as_posix())
                path.write_bytes(original)

    def test_missing_file_fails(self):
        self.vector.unlink()
        self.assert_drift("conformance/vectors/example.json.gz")

    def test_unexpected_generated_file_fails(self):
        (self.vector.parent / "extra.json").write_bytes(PAYLOAD)
        self.assert_drift("conformance/vectors/extra.json")


if __name__ == "__main__":
    unittest.main()

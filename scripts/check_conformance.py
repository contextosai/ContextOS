"""Compare generated vector contents and schemas with the committed baseline."""

import argparse
import gzip
from pathlib import Path
import subprocess
import sys


TARGETS = ("conformance/vectors", "schemas")


def check(root):
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=root)

    expected_paths = set(git("ls-tree", "-rz", "--name-only", "HEAD", "--", *TARGETS)
                         .decode().strip("\0").split("\0")) - {""}
    current_paths = set(git("ls-files", "-z", "--cached", "--others", "--exclude-standard",
                            "--", *TARGETS).decode().strip("\0").split("\0")) - {""}
    errors = [f"unexpected generated file: {name}" for name in sorted(current_paths - expected_paths)]
    errors.extend(f"missing generated file: {name}" for name in sorted(expected_paths - current_paths))
    for name in sorted(expected_paths & current_paths):
        try:
            expected = git("show", f"HEAD:{name}")
            current = (root / name).read_bytes()
            if name.endswith(".gz"):
                expected, current = gzip.decompress(expected), gzip.decompress(current)
            if expected != current:
                errors.append(f"content differs from HEAD: {name}")
        except (OSError, EOFError) as error:
            errors.append(f"cannot read generated file: {name}: {error}")
    return errors


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=Path(__file__).resolve().parents[1])
    errors = check(parser.parse_args().root)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        sys.exit(1)
    print("Conformance vector contents and schemas match HEAD.")

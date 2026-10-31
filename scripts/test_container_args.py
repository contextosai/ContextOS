"""The image and the Helm chart must not both pass arguments: Kubernetes `args`
replace the image's CMD but are appended to its ENTRYPOINT."""

import json
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def exec_form(dockerfile: str, instruction: str):
    lines = [l for l in dockerfile.splitlines() if l.startswith(instruction + " ")]
    return json.loads(lines[-1][len(instruction) + 1:]) if lines else None


class ContainerArgs(unittest.TestCase):
    def test_entrypoint_takes_no_arguments_so_chart_args_replace_cmd(self):
        dockerfile = (ROOT / "Dockerfile").read_text()
        self.assertEqual(exec_form(dockerfile, "ENTRYPOINT"), ["/usr/local/bin/contextosd"])
        cmd = exec_form(dockerfile, "CMD")
        deployment = (ROOT / "deploy/helm/contextosd/templates/deployment.yaml").read_text()
        args = re.search(r"^\s*args:\s*(\[.*\])\s*$", deployment, re.M)
        self.assertIsNotNone(args, "the chart states its arguments")
        self.assertEqual(json.loads(args.group(1)), cmd)


if __name__ == "__main__":
    unittest.main()

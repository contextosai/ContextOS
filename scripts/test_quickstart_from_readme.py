import unittest

from quickstart_from_readme import commands


class Commands(unittest.TestCase):
    def test_the_clone_is_skipped_and_the_rest_run_in_order(self):
        readme = "# x\n## Quickstart\ntext\n```sh\ngit clone https://example/x.git\ncd ContextOS\n./examples/a.sh\n\n./examples/b.sh\n```\n## Next\n```sh\nnot me\n```\n"
        self.assertEqual(commands(readme), ["./examples/a.sh", "./examples/b.sh"])


if __name__ == "__main__":
    unittest.main()

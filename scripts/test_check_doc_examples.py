import importlib.util
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location(
    "check_doc_examples", Path(__file__).with_name("check-doc-examples.py")
)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)

EXAMPLE = """//// Module doc.

import warden

// docs:begin shown
pub fn shown() { warden.start }
// docs:end shown

pub fn hidden() { Nil }
"""


class CheckTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.examples = self.root / "usage"
        self.examples.mkdir()
        (self.examples / "shown.gleam").write_text(EXAMPLE)

    def readme(self, body: str) -> list[Path]:
        path = self.root / "README.md"
        path.write_text(body)
        return [path]

    def problems(self, body: str) -> list[str]:
        return checker.check(self.root, self.readme(body), self.examples)

    def test_a_verbatim_block_passes(self):
        body = (
            "<!-- example: usage/shown.gleam shown -->\n\n"
            "```gleam\npub fn shown() { warden.start }\n```\n"
        )
        self.assertEqual(self.problems(body), [])

    def test_a_drifted_block_fails(self):
        body = (
            "<!-- example: usage/shown.gleam shown -->\n\n"
            "```gleam\npub fn shown() { warden.stop }\n```\n"
        )
        self.assertEqual(
            self.problems(body),
            ["README.md: example usage/shown.gleam shown: block differs from the compiled region"],
        )

    def test_an_unshown_region_fails(self):
        self.assertEqual(
            self.problems("No examples here.\n"),
            ["usage/shown.gleam: region `shown` is shown by no README block"],
        )

    def test_a_missing_region_or_file_fails(self):
        missing_region = "<!-- example: usage/shown.gleam other -->\n\n```gleam\nx\n```\n"
        self.assertIn(
            "README.md: example usage/shown.gleam other: no `docs:begin other` region",
            self.problems(missing_region),
        )
        missing_file = "<!-- example: usage/none.gleam shown -->\n\n```gleam\nx\n```\n"
        self.assertIn(
            "README.md: example usage/none.gleam shown: no such file",
            self.problems(missing_file),
        )

    def test_a_marker_without_a_fence_fails(self):
        body = "<!-- example: usage/shown.gleam shown -->\n\nSome prose.\n"
        self.assertIn(
            "README.md: example usage/shown.gleam shown: no ```gleam block follows the marker",
            self.problems(body),
        )


if __name__ == "__main__":
    unittest.main()

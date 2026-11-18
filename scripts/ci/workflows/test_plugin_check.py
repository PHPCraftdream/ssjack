"""The ssjack-ui plugin is validated and tested by the pinned Claude Code CLI in both workflows."""

from pathlib import Path
import re
import unittest

from test_full_trigger import PREDICATE, job

ROOT = Path(__file__).resolve().parents[3]


class PluginCheckTests(unittest.TestCase):
    def test_both_workflows_validate_and_test_the_plugin_with_an_exact_cli_pin(self):
        versions = set()
        for name in ("ci.yml", "feature.yml"):
            block = job((ROOT / ".github/workflows" / name).read_text(encoding="utf-8"), "plugin-check")
            self.assertIn("run: claude plugin validate plugins/ssjack-ui", block)
            self.assertIn("run: claude plugin test plugins/ssjack-ui", block)
            self.assertIn("runs-on: ubuntu-latest", block)
            pin = re.search(r'CLAUDE_CODE_VERSION: "(\d+\.\d+\.\d+)"', block)
            self.assertIsNotNone(pin, name + ": the CLI version must be an exact pin")
            versions.add(pin.group(1))
            self.assertIn("@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}", block)
            self.assertIn('test "$(claude --version | cut -d\' \' -f1)" = "$CLAUDE_CODE_VERSION"', block)
        self.assertEqual(len(versions), 1, "both workflows must pin the same CLI version")

    def test_feature_job_is_skipped_exactly_when_the_full_gate_runs(self):
        block = job((ROOT / ".github/workflows/feature.yml").read_text(encoding="utf-8"), "plugin-check")
        self.assertEqual(re.search(r"^    if: (.+)$", block, re.M).group(1), "${{ !(" + PREDICATE + ") }}")


if __name__ == "__main__":
    unittest.main()

"""Verify the fixed GitHub routing expression without launching a full suite."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
PREDICATE = "github.event_name == 'push' && contains(github.event.head_commit.message, '[ci:full]')"


def job(text, name):
    block = text.split("\n  " + name + ":\n", 1)[1]
    return re.split(r"\n  [a-z-]+:\n", block, maxsplit=1)[0]


class FullTriggerTests(unittest.TestCase):
    def setUp(self):
        self.feature = (ROOT / ".github/workflows/feature.yml").read_text(encoding="utf-8")
        self.full = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    def test_full_and_scoped_guards_are_exact_complements(self):
        full = job(self.feature, "full")
        self.assertEqual(re.search(r"^    if: (.+)$", full, re.M).group(1),
                         "${{ " + PREDICATE + " }}")
        for name in ("impacted", "licenses"):
            block = job(self.feature, name)
            self.assertEqual(re.search(r"^    if: (.+)$", block, re.M).group(1),
                             "${{ !(" + PREDICATE + ") }}")
        self.assertIn("uses: ./.github/workflows/ci.yml", full)
        self.assertIn("source_ref: ${{ github.sha }}", full)

    def test_marked_full_and_normal_pushes_use_distinct_concurrency(self):
        self.assertIn("${{ " + PREDICATE + " && 'full' || 'scoped' }}", self.feature)

    def test_no_automatic_full_branch_or_schedule_trigger(self):
        header = self.full.split("\npermissions:", 1)[0]
        self.assertNotIn("  push:", header)
        self.assertNotIn("  pull_request:", header)
        self.assertNotIn("  schedule:", header)
        self.assertIn("  workflow_dispatch:", header)
        self.assertIn("  workflow_call:", header)
        self.assertNotIn("branches-ignore:", self.feature)

    def test_fixed_token_truth_cases(self):
        # GitHub contains() performs case-insensitive literal inclusion.
        for event, message, expected in (
            ("push", "feat: ordinary feature", False),
            ("push", "feat: full sprint\n\n[ci:full]\n", True),
            ("push", "feat: finish [ci:full]", True),
            ("push", "feat: [ci:FULL]", True),
            ("push", "feat: [ci:fuller]", False),
            ("push", None, False),
            ("pull_request", "[ci:full]", False),
            ("workflow_dispatch", "[ci:full]", False),
        ):
            with self.subTest(event=event, message=message):
                self.assertEqual(event == "push" and "[ci:full]" in (message or "").lower(), expected)

    def test_full_profile_and_release_contract_remain_present(self):
        self.assertIn("SSJACK_TEST_FULL_KDF: '1'", self.full)
        self.assertIn("TestAppstoreMasterFullProfile", self.full)
        self.assertIn("name: verified-cli-", self.full)
        release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertIn("uses: ./.github/workflows/ci.yml", release)

    def test_agent_instructions_cover_both_explicit_routes(self):
        instructions = (ROOT / "CLAUDE.md").read_text(encoding="utf-8")
        self.assertIn("[ci:full]", instructions)
        self.assertIn("Run workflow", instructions)
        self.assertIn("diff-based", instructions)


if __name__ == "__main__":
    unittest.main()

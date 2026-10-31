"""Selection regressions for isolated declarative acceptance."""
import base64
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]


class DeclarativeScopedSelectionTests(unittest.TestCase):
    def test_acceptance_requires_impacted_runtime_package(self):
        feature = (ROOT / ".github/workflows/feature.yml").read_text(encoding="utf-8")
        section = feature.split("  declarative-synthetic:\n", 1)[1].split("  full:\n", 1)[0]
        self.assertIn("fetch-depth: 0", section)
        self.assertIn("id: scope", section)
        self.assertIn('git config --global --add safe.directory "$GITHUB_WORKSPACE"', section)
        self.assertNotIn('safe.directory "*"', section)
        self.assertIn("scripts/ci/plan.py plan --base", section)
        self.assertIn("if: steps.scope.outputs.declarative == 'true'", section)
        self.assertIn("python3 scripts/ci/declarative_scoped.py", section)
        planner = (ROOT / "scripts/ci/plan.py").read_text(encoding="utf-8")
        self.assertIn('str("./internal/declarativeslice" in plan["packages"]).lower()', planner)

    def test_fixture_request_identifiers_are_exact_16_bytes(self):
        files = (ROOT / "internal/declarativeslice").glob("scoped*_test.go")
        identifiers = []
        for path in files:
            identifiers.extend(re.findall(r'"([A-Za-z0-9_-]{22,24})"', path.read_text(encoding="utf-8")))
        self.assertTrue(identifiers)
        for value in identifiers:
            with self.subTest(identifier=value):
                decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
                self.assertEqual(len(decoded), 16)
                self.assertEqual(base64.urlsafe_b64encode(decoded).decode().rstrip("="), value)


if __name__ == "__main__":
    unittest.main()

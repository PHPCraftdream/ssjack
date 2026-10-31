"""Selection regressions for isolated declarative acceptance."""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class DeclarativeScopedSelectionTests(unittest.TestCase):
    def test_acceptance_requires_impacted_runtime_package(self):
        feature = (ROOT / ".github/workflows/feature.yml").read_text(encoding="utf-8")
        section = feature.split("  declarative-synthetic:\n", 1)[1].split("  full:\n", 1)[0]
        self.assertIn("fetch-depth: 0", section)
        self.assertIn("id: scope", section)
        self.assertIn("scripts/ci/plan.py plan --base", section)
        self.assertIn("if: steps.scope.outputs.declarative == 'true'", section)
        self.assertIn("python3 scripts/ci/declarative_scoped.py", section)
        planner = (ROOT / "scripts/ci/plan.py").read_text(encoding="utf-8")
        self.assertIn('str("./internal/declarativeslice" in plan["packages"]).lower()', planner)


if __name__ == "__main__":
    unittest.main()

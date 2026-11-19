"""Regression checks for confidential-delivery CI gating."""
import ast
from pathlib import Path
import re
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts" / "ci"))
from kdfseam import overlay as kdf_overlay
MASTER = ROOT / "internal/appstorecrypto/masterkey/master.go"
INSTALLATION = ROOT / "internal/appstorecrypto/masterkey/installation.go"
RECORD = ROOT / "internal/appstorecrypto/masterkey/record.go"
FEATURE = ROOT / ".github/workflows/feature.yml"
FULL = ROOT / ".github/workflows/ci.yml"
SCOPED = ROOT / "scripts/ci/delivery/delivery_scoped.py"


class DeliveryScopedCIGating(unittest.TestCase):
    def test_delivery_helpers_parse(self):
        for name in ("delivery_pty.py", "delivery_scoped.py"):
            path = ROOT / "scripts/ci/delivery" / name
            with self.subTest(helper=name):
                ast.parse(path.read_text(encoding="utf-8"), filename=name)

    def test_overlay_is_exactly_private_and_production_profile_is_unchanged(self):
        source = MASTER.read_text(encoding="utf-8")
        old, new = kdf_overlay.OLD, kdf_overlay.NEW
        self.assertEqual(source.count(old), 1)
        overlay = source.replace(old, new, 1)
        self.assertIn(new, overlay)
        self.assertIn("argon2.IDKey(password, salt, 1, 1048576, 1, 32)", source)
        self.assertIn("const installationLayers = 1000", INSTALLATION.read_text(encoding="utf-8"))
        self.assertIn('[]byte("ssjack-appstore/v1/master")', source)
        record = RECORD.read_text(encoding="utf-8")
        self.assertIn("const recordLayers = 1000", record)
        self.assertEqual(source.count("aes.NewCipher"), overlay.count("aes.NewCipher"))
        self.assertIn("[4][32]byte", source)
        self.assertIn("for i := range salts", source)
        self.assertIn("fn(owned, salts[i][:])", source)

    def test_feature_gates_delivery_acceptance_on_relevant_scope(self):
        workflow = FEATURE.read_text(encoding="utf-8")
        self.assertRegex(workflow, r"if:\s*steps\.scope\.outputs\.(?:declarative|appstorecli)\s*==\s*'true'\s*\|\|\s*steps\.scope\.outputs\.(?:declarative|appstorecli)\s*==\s*'true'")
        self.assertIn("python3 scripts/ci/delivery/delivery_scoped.py", workflow)

    def test_full_ci_runs_delivery_after_root_metadata_acceptance(self):
        workflow = FULL.read_text(encoding="utf-8")
        self.assertIn("Verify CI selection regressions", workflow)
        self.assertRegex(workflow, r"(?s)  scoped-appstore:.*?run:\s*python3 scripts/ci/appstore/appstore_scoped\.py")
        self.assertRegex(workflow, r"(?s)  delivery-root:\n    name: Root confidential-delivery acceptance\n    runs-on: ubuntu-latest\n    container:\n      image: golang:1.26.0\n      options: --user 0\n    steps:.*?run:\s*\|\n\s*git config --global --add safe\.directory \"\$GITHUB_WORKSPACE\"\n\s*python3 scripts/ci/delivery/delivery_scoped\.py")
        self.assertIn("apt-get update", workflow)
        self.assertIn("apt-get install -y python3", workflow)

    def test_scoped_runner_is_guarded_and_requires_actual_pass_not_skip(self):
        runner = SCOPED.read_text(encoding="utf-8")
        self.assertIn('sys.platform != "linux"', runner)
        self.assertRegex(runner, r"(?i)overlay")
        self.assertIn("SSJACK_TEST_SCOPED_KDF", runner)
        self.assertIn("SSJACK_PUBLIC_CI", runner)
        self.assertIn("TestDeliveryScopedAcceptance", runner)
        self.assertIn('"./cmd/ssjack/internal/appstore/delivery"', runner)
        self.assertRegex(runner, r"(?i)(?:FAIL|SKIP|PASS)")

    def test_delivery_runner_uses_distinct_shared_kdf_variants(self):
        runner = SCOPED.read_text(encoding="utf-8")
        self.assertIn("sys.path.insert(0, str(Path(__file__).resolve().parents[1]))", runner)
        self.assertIn("from kdfseam import overlay as kdf_overlay", runner)
        self.assertIn('kdf_overlay.temporary_overlay("scoped-build")', runner)
        self.assertIn('kdf_overlay.temporary_overlay("scoped-test")', runner)
        self.assertIn('"-overlay", str(build_overlay)', runner)
        self.assertIn(
            '"-overlay", str(test_overlay)',
            runner,
            "the go test must receive the separately generated scoped-test overlay",
        )


if __name__ == "__main__":
    unittest.main()

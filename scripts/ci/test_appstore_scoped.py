"""Static regression checks for the private app-store scoped CI overlay."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
ROOT = Path(__file__).resolve().parents[2]
MASTER = ROOT / "internal" / "appstorecrypto" / "master.go"
SCRIPT = ROOT / "scripts" / "ci" / "appstore_scoped.py"


def load_overlay_module():
    spec = importlib.util.spec_from_file_location("appstore_scoped", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


class AppstoreScopedCIRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = MASTER.read_text(encoding="utf-8")
        cls.module = load_overlay_module()
        cls.workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        cls.feature = (ROOT / ".github" / "workflows" / "feature.yml").read_text(encoding="utf-8")

    def test_overlay_is_a_single_narrow_source_replacement(self):
        module = self.module
        self.assertEqual(self.source.count(module.OLD), 1)
        self.assertIn("argon2.IDKey(password, salt, 1, 1048576, 1, 32)", self.source)
        patched = self.source.replace(module.OLD, module.NEW, 1)
        self.assertEqual(patched.replace(module.NEW, module.OLD, 1), self.source)
        self.assertIn("sha256.Sum256(input)", module.NEW)
        self.assertNotIn("argon2.IDKey(", module.NEW)

    def test_production_has_no_private_selector(self):
        self.assertNotIn("SSJACK_TEST_SCOPED_KDF", self.source)

    def test_workflows_select_scoped_and_production_full_profile_tests(self):
        self.assertIn("python3 scripts/ci/appstore_scoped.py", self.workflow)
        self.assertIn("python3 scripts/ci/appstore_scoped.py", self.feature)
        self.assertRegex(self.workflow, r"TestVault\.\*FullProfile")
        self.assertRegex(self.workflow, r"TestKeyfileFullProfile")
        self.assertRegex(self.workflow, r"TestAppstoreMasterFullProfile")
        self.assertRegex(self.workflow, r"TestAppstoreFullProfileCLI")
        self.assertRegex(self.workflow, r"\./internal/vault .*\./internal/keyfile .*\./internal/appstorecrypto .*\./cmd/ssjack")

    def test_feature_overlay_requires_impacted_cli_package(self):
        self.assertIn(
            "if: runner.os == 'Linux' && steps.scope.outputs.appstorecli == 'true'",
            self.feature,
        )
        planner = (ROOT / "scripts" / "ci" / "plan.py").read_text(encoding="utf-8")
        self.assertIn('str("./cmd/ssjack" in plan["packages"]).lower()', planner)

    @unittest.skipUnless(sys.platform == "linux", "overlay runner is Linux-only")
    def test_main_invokes_only_scoped_race_selection_and_propagates_status(self):
        module = self.module
        observed = {}

        def fake_run(command, **kwargs):
            observed["command"] = command
            observed["kwargs"] = kwargs
            overlay_path = Path(command[command.index("-overlay") + 1])
            overlay = json.loads(overlay_path.read_text(encoding="utf-8"))
            source_path = Path(next(iter(overlay["Replace"].values())))
            patched = source_path.read_text(encoding="utf-8")
            observed["patched"] = patched
            self.assertEqual(patched, self.source.replace(module.OLD, module.NEW, 1))
            return subprocess.CompletedProcess(command, 7)

        with mock.patch.object(module.subprocess, "run", side_effect=fake_run):
            self.assertEqual(module.main(), 7)
        command = observed["command"]
        self.assertEqual(command[0:2], ["go", "test"])
        self.assertIn("-overlay", command)
        self.assertIn("-race", command)
        self.assertEqual(command[command.index("-run") + 1], "^(TestAppstoreScopedCLI.*)$")
        self.assertEqual(command[-1], "./cmd/ssjack")
        self.assertEqual(observed["kwargs"]["check"], False)
        self.assertEqual(observed["kwargs"]["env"]["SSJACK_TEST_SCOPED_KDF"], "1")

    def test_main_fails_closed_when_original_body_is_not_unique(self):
        module = self.module
        with tempfile.TemporaryDirectory() as directory:
            fake_master = Path(directory) / "master.go"
            fake_master.write_text("no expected body", encoding="utf-8")
            with mock.patch.object(module, "MASTER", fake_master), mock.patch.object(
                module.sys, "platform", "linux"
            ), mock.patch.object(module.subprocess, "run") as run:
                with self.assertRaisesRegex(SystemExit, "exactly one"):
                    module.main()
                run.assert_not_called()


if __name__ == "__main__":
    unittest.main()

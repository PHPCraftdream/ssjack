"""Selection regressions for isolated declarative acceptance."""
import base64
import importlib.util
import io
from pathlib import Path
import re
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]


class DeclarativeScopedSelectionTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "linux", "PTY runner is Linux-only")
    def test_pty_close_waits_for_child_exit_before_declaring_timeout(self):
        path = ROOT / "scripts/ci/declarative_scoped.py"
        spec = importlib.util.spec_from_file_location("declarative_scoped", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        proc = mock.Mock()
        proc.poll.return_value = None
        proc.stdout = io.BytesIO(b"")

        def completed_wait(**kwargs):
            proc.returncode = 0
            return 0

        proc.wait.side_effect = completed_wait
        with mock.patch.object(module.pty, "openpty", return_value=(10, 11)), \
                mock.patch.object(module.subprocess, "Popen", return_value=proc), \
                mock.patch.object(module.os, "close"), \
                mock.patch.object(module.select, "select", return_value=([10], [], [])), \
                mock.patch.object(module.os, "read", side_effect=OSError("PTY closed")):
            module.run_cli("fixture", ["declarative", "revoke"], [])
        proc.wait.assert_called_once()
        self.assertGreaterEqual(proc.wait.call_args.kwargs["timeout"], 0)
        self.assertLessEqual(proc.wait.call_args.kwargs["timeout"], 60)
        proc.kill.assert_not_called()

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
        self.assertIn("python3 scripts/ci/text_adapter_scoped.py", section)
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        root_delivery = ci.split("  delivery-root:\n", 1)[1].split("  full-profile:\n", 1)[0]
        self.assertIn("container:\n      image: golang:1.26.0", root_delivery)
        self.assertIn("python3 scripts/ci/text_adapter_scoped.py", root_delivery)
        runner = (ROOT / "scripts/ci/text_adapter_scoped.py").read_text(encoding="utf-8")
        self.assertIn("os.geteuid() != 0", runner)
        self.assertIn('"-test.run", "^TestText(Adapter(Connected|Bounds)|Reverse(Connected|MappingsConnected|LateConnected|ExpiryConnected)|StreamConnected)$"', runner)
        self.assertIn("TestTextAdapterConnected", runner)
        self.assertIn("TestTextReverseConnected", runner)
        self.assertIn("TestTextReverseMappingsConnected", runner)
        self.assertIn("TestTextReverseLateConnected", runner)
        self.assertIn("TestTextReverseExpiryConnected", runner)
        self.assertIn('"TestTextStreamConnected"):', runner)
        planner = (ROOT / "scripts/ci/plan.py").read_text(encoding="utf-8")
        self.assertIn('str("./internal/declarativeslice" in plan["packages"]).lower()', planner)

    def test_text_pair_is_pinned_and_mandatory_in_both_tiers(self):
        feature = (ROOT / ".github/workflows/feature.yml").read_text(encoding="utf-8")
        full = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        for source in (feature, full):
            self.assertIn("  text-pair:\n", source)
            self.assertIn("uses: ./.github/workflows/text-pair.yml", source)
        workflow = (ROOT / ".github/workflows/text-pair.yml").read_text(encoding="utf-8")
        self.assertIn("506ff2a2802bbfa5cf931f735f1b06aaee7f5244", workflow)
        self.assertIn("repository: PHPCraftdream/clawwright", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("python3 scripts/ci/text_pair_scoped.py", workflow)
        runner = (ROOT / "scripts/ci/text_pair_scoped.py").read_text(encoding="utf-8")
        self.assertIn("os.geteuid() != 0", runner)
        self.assertIn("actual != expected", runner)
        self.assertIn('NAME = "TestClawwrightTextPairConnected"', runner)
        self.assertIn("^--- SKIP: {NAME}", runner)
        self.assertIn("^--- PASS: {NAME}", runner)

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

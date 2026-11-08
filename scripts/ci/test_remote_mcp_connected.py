"""Static checks for mandatory private-overlay connected remote-MCP acceptance."""
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
SCRIPT = ROOT / "scripts" / "ci" / "remote_mcp_connected.py"


def load_module():
    spec = importlib.util.spec_from_file_location("remote_mcp_connected", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


class RemoteMCPConnectedCI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()
        cls.policy = (ROOT / "internal" / "mcphttp" / "policy.go").read_text(encoding="utf-8")
        cls.auth = (ROOT / "internal" / "mcphttp" / "auth.go").read_text(encoding="utf-8")
        cls.route = (ROOT / "cmd" / "ssjack" / "remote_mcp_connected_route_linux_amd64_test.go").read_text(encoding="utf-8")
        cls.driver = (ROOT / "cmd" / "ssjack" / "remote_mcp_startup_fullprofile_linux_amd64_test.go").read_text(encoding="utf-8")
        cls.feature = (ROOT / ".github" / "workflows" / "feature.yml").read_text(encoding="utf-8")
        cls.workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    def test_overlay_is_temporary_and_restricts_one_exact_endpoint(self):
        module = self.module
        with tempfile.TemporaryDirectory() as temporary:
            replacements = module.overlay_sources(Path(temporary))
            self.assertEqual(set(replacements), {str(module.POLICY.resolve()), str(module.ROUTE_TEST.resolve())})
            policy = Path(replacements[str(module.POLICY.resolve())]).read_text(encoding="utf-8")
            self.assertIn("RegisterPrivateFixtureRoute", policy)
            self.assertIn('endpoint != "https://coordinator.invalid/mcp"', policy)
            self.assertIn('host != "127.0.0.1"', policy)
            self.assertIn('if policy.endpoint == "https://coordinator.invalid/mcp" && (!ok || policy.host != "coordinator.invalid" || policy.port != "443")', policy)
            self.assertNotIn("InsecureSkipVerify", policy)
            route = Path(replacements[str(module.ROUTE_TEST.resolve())]).read_text(encoding="utf-8")
            self.assertIn("mcphttp.RegisterPrivateFixtureRoute", route)
            self.assertIn('"crypto/x509"', self.route)
            self.assertIn("private remote MCP fixture route is unavailable", self.route)

    def test_production_public_constructor_and_security_profile_remain_closed(self):
        self.assertIn("return newUpstream(ctx, policy, account, policy.transport())", self.auth)
        self.assertIn("if !publicAddress(address)", self.policy)
        self.assertIn("MinVersion: tls.VersionTLS12", self.policy)
        for production in (self.policy, self.auth):
            self.assertNotIn("RegisterPrivateFixtureRoute", production)
            self.assertNotIn("SSJACK_TEST_REMOTE_MCP_CONNECTED", production)

    def test_full_and_feature_workflows_require_each_positive_scenario(self):
        for source in (self.workflow, self.feature):
            self.assertIn("python3 scripts/ci/remote_mcp_connected.py", source)
            self.assertIn("connected-basic connected-bypass connected-active-cancel connected-empty connected-cancel", source)
        self.assertIn("if: runner.os == 'Linux' && steps.scope.outputs.appstorecli == 'true'", self.feature)
        self.assertIn("[ci:full]", self.feature)

    def test_runner_only_runs_full_kdf_startup_case_and_rejects_skipped_or_missing(self):
        module = self.module
        observed = {}

        def fake_run(command, **kwargs):
            observed["command"], observed["kwargs"] = command, kwargs
            overlay = json.loads(Path(command[command.index("-overlay") + 1]).read_text(encoding="utf-8"))
            observed["overlay"] = overlay
            return subprocess.CompletedProcess(command, 0, "--- PASS: TestVaultRemoteMCPStartupFullProfile (1s)\n", None)

        with mock.patch.object(module.sys, "platform", "linux"), mock.patch.object(module.subprocess, "run", side_effect=fake_run):
            self.assertEqual(module.main(), 1)
        command = observed["command"]
        self.assertEqual(command[0:2], ["go", "test"])
        self.assertEqual(command[command.index("-run") + 1], "^TestVaultRemoteMCPStartupFullProfile$")
        self.assertIn("-mod=readonly", command)
        self.assertIn("-p", command)
        self.assertEqual(observed["kwargs"]["env"]["SSJACK_TEST_FULL_KDF"], "1")
        self.assertEqual(observed["kwargs"]["env"]["SSJACK_TEST_REMOTE_MCP_CONNECTED"], "1")
        self.assertNotIn("SSJACK_VAULT_PASSWORD", observed["kwargs"]["env"])
        self.assertEqual(len(observed["overlay"]["Replace"]), 2)

    def test_runner_requires_top_and_per_scenario_pass_not_skips(self):
        source = self.module.SCRIPT.read_text(encoding="utf-8")
        self.assertIn("required += [f\"--- PASS: TestVaultRemoteMCPStartupFullProfile/{name} \"", source)
        self.assertIn("required += [f\"REMOTE-MCP-CONNECTED-OBSERVED:{name}\"", source)
        self.assertIn("if missing or skipped", source)
        self.assertIn("SSJACK_TEST_REMOTE_MCP_CONNECTED", source)

        module = self.module
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "policy.go"
            source.write_text("not a policy", encoding="utf-8")
            with mock.patch.object(module, "POLICY", source), mock.patch.object(module, "sys") as fake_sys, mock.patch.object(module.subprocess, "run") as run:
                fake_sys.platform = "linux"
                with self.assertRaises((SystemExit, ValueError)):
                    module.main()
                run.assert_not_called()


if __name__ == "__main__":
    unittest.main()

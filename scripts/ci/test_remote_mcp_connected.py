"""Static checks for mandatory private-overlay connected remote-MCP acceptance."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import re
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


def named_step(source: str, name: str) -> str:
    lines = source.splitlines()
    marker = f"      - name: {name}"
    starts = [index for index, line in enumerate(lines) if line == marker]
    if len(starts) != 1:
        raise AssertionError(f"expected exactly one workflow step named {name!r}")
    start = starts[0]
    end = next((index for index in range(start + 1, len(lines)) if lines[index].startswith("      - ")), len(lines))
    return "\n".join(lines[start:end])


def named_job(source: str, name: str) -> str:
    lines = source.splitlines()
    marker = f"  {name}:"
    starts = [index for index, line in enumerate(lines) if line == marker]
    if len(starts) != 1:
        raise AssertionError(f"expected exactly one workflow job named {name!r}")
    start = starts[0]
    end = next((index for index in range(start + 1, len(lines)) if lines[index].startswith("  ") and not lines[index].startswith("    ")), len(lines))
    return "\n".join(lines[start:end])


class RemoteMCPConnectedCI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()
        cls.policy = (ROOT / "internal" / "mcphttp" / "policy.go").read_text(encoding="utf-8")
        cls.auth = (ROOT / "internal" / "mcphttp" / "auth.go").read_text(encoding="utf-8")
        cls.route = (ROOT / "cmd" / "ssjack" / "remote_mcp_connected_route_test.go").read_text(encoding="utf-8")
        cls.driver = (ROOT / "cmd" / "ssjack" / "remote_mcp_startup_fullprofile_test.go").read_text(encoding="utf-8")
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

    def test_workflow_gates_run_native_remote_mcp_acceptance_on_all_matrix_platforms(self):
        startup = (
            "continue", "receipt-remembered", "empty", "no-record", "absent-directory", "cancel",
            "esc", "ctrl-c", "stale-ciphertext", "mcp-nonterminal-refusal", "issue-refusal",
            "prepared-launch-no-output-filter",
        )
        connected = ("connected-basic", "connected-bypass", "connected-active-cancel", "connected-empty", "connected-cancel")
        feature_startup = named_step(self.feature, "Remote MCP startup with production KDF")
        feature_connected = named_step(self.feature, "Connected remote MCP startup with production KDF")
        full_startup = named_step(self.workflow, "Native remote MCP startup with production KDF")
        full_connected = named_step(self.workflow, "Native connected remote MCP with production KDF")
        linux_full_profile = named_step(self.workflow, "Verify production vault and app-store master profiles")
        feature_text_owner = named_step(self.feature, "Text owner startup with production KDF")

        self.assertIn("if: runner.os == 'Linux' && steps.scope.outputs.appstorecli == 'true'", feature_text_owner)
        for step in (feature_startup, feature_connected):
            self.assertNotIn("if: runner.os == 'Linux'", step)
            self.assertIn("if: steps.scope.outputs.appstorecli == 'true'", step)
        for step in (full_startup, full_connected):
            self.assertNotIn("runner.os == 'Linux'", step)
        self.assertIn("os: [ubuntu-latest, windows-latest, macos-latest]", named_job(self.workflow, "test"))
        self.assertIn("os: [ubuntu-latest, windows-latest, macos-latest]", named_job(self.feature, "impacted"))
        self.assertIn("runs-on: ubuntu-latest", named_job(self.workflow, "full-profile"))

        startup_steps = (feature_startup, full_startup, linux_full_profile)
        startup_list = f"for name in {' '.join(startup)}; do"
        for step in startup_steps:
            self.assertIn(startup_list, step)
            self.assertIn('"--- PASS: TestVaultRemoteMCPStartupFullProfile/$name "', step)
            self.assertIn('"REMOTE-MCP-STARTUP-OBSERVED:$name"', step)
            self.assertIn("^--- PASS: TestVaultRemoteMCPStartupFullProfile ", step)
            self.assertIn("^[[:space:]]*--- SKIP: TestVaultRemoteMCPStartupFullProfile(/| )", step)
        connected_list = f"for name in {' '.join(connected)}; do"
        for step in (feature_connected, full_connected):
            self.assertIn("python3 scripts/ci/remote_mcp_connected.py", step)
            self.assertIn("^--- PASS: TestVaultRemoteMCPStartupFullProfile ", step)
            self.assertIn(connected_list, step)
            self.assertIn('"--- PASS: TestVaultRemoteMCPStartupFullProfile/$name "', step)
        for step in (feature_startup, full_startup):
            self.assertIn("-p 1", step)
            self.assertIn("-count=1", step)
            self.assertIn("-timeout 900s", step)
            self.assertIn("SSJACK_TEST_FULL_KDF: '1'", step)

        feature_artifact = named_step(self.feature, "Retain native remote MCP acceptance logs")
        full_artifact = named_step(self.workflow, "Retain native remote MCP acceptance logs")
        self.assertIn("if: always() && steps.scope.outputs.appstorecli == 'true'", feature_artifact)
        for artifact in (feature_artifact, full_artifact):
            self.assertIn("remote-mcp-startup.log", artifact)
            self.assertIn("remote-mcp-connected.log", artifact)
            self.assertIn("if-no-files-found: error", artifact)
            self.assertIn("retention-days: 7", artifact)
        self.assertIn("native-remote-mcp-${{ runner.os }}-${{ runner.arch }}-feature", feature_artifact)
        self.assertIn("native-remote-mcp-${{ runner.os }}-${{ runner.arch }}-full", full_artifact)
        self.assertIn("[ci:full]", self.feature)

    def test_generic_remote_mcp_fixture_sources_are_platform_neutral_and_scenarios_exact(self):
        fixture_paths = (
            "cmd/ssjack/remote_mcp_connected_fixture_test.go",
            "cmd/ssjack/remote_mcp_connected_harness_test.go",
            "cmd/ssjack/remote_mcp_connected_lifetime_test.go",
            "cmd/ssjack/remote_mcp_connected_route_test.go",
            "cmd/ssjack/remote_mcp_startup_child_test.go",
            "cmd/ssjack/remote_mcp_startup_driver_test.go",
            "cmd/ssjack/remote_mcp_startup_helpers_test.go",
            "cmd/ssjack/remote_mcp_startup_prepared_launch_test.go",
            "cmd/ssjack/remote_mcp_startup_fullprofile_test.go",
        )
        for relative_path in fixture_paths:
            with self.subTest(path=relative_path):
                source = (ROOT / relative_path).read_text(encoding="utf-8")
                self.assertNotRegex(source, r"(?m)^//(?:go:build[ \t]+|[ \t]+\+build[ \t]+)[^\n]*(?:linux|amd64)")

        expected_startup = (
            "continue", "receipt-remembered", "empty", "no-record", "absent-directory", "cancel",
            "esc", "ctrl-c", "stale-ciphertext", "mcp-nonterminal-refusal", "issue-refusal",
            "prepared-launch-no-output-filter",
        )
        expected_connected = ("connected-basic", "connected-bypass", "connected-active-cancel", "connected-empty", "connected-cancel")
        scenario_lists = [
            tuple(re.findall(r'"([^\"]+)"', body))
            for body in re.findall(r"for _, scenario := range \[\]string\{([^}]*)\}", self.driver)
        ]
        self.assertEqual(scenario_lists, [expected_connected, expected_startup])

    def test_runner_simulates_every_supported_platform_without_skipping_evidence(self):
        module = self.module
        self.assertEqual(module.SUPPORTED_PLATFORMS, ("linux", "darwin", "win32"))
        self.assertEqual(
            re.compile(r"^[ \t]*--- SKIP: TestVaultRemoteMCPStartupFullProfile(?:/[^\s]+)? ", re.MULTILINE).search(
                self.complete_evidence() + "  --- SKIP: TestVaultRemoteMCPStartupFullProfile (0s)\n"
            ).group(0),
            "  --- SKIP: TestVaultRemoteMCPStartupFullProfile ",
        )
        calls = []

        def fake_run(command, **kwargs):
            calls.append((command, kwargs))
            return subprocess.CompletedProcess(command, 0, self.complete_evidence(), None)

        for platform in ("linux", "darwin", "win32"):
            with mock.patch.object(module.sys, "platform", platform), mock.patch.object(
                module.subprocess, "run", side_effect=fake_run
            ) as run:
                self.assertEqual(module.main(), 0)
                run.assert_called_once()
        self.assertEqual(len(calls), 3)
        for command, kwargs in calls:
            self.assertEqual(command[0:2], ["go", "test"])
            self.assertEqual(command[command.index("-p") + 1], "1")
            self.assertEqual(command[command.index("-timeout") + 1], "900s")
            self.assertEqual(kwargs["env"]["SSJACK_TEST_FULL_KDF"], "1")
            self.assertEqual(kwargs["env"]["SSJACK_TEST_REMOTE_MCP_CONNECTED"], "1")

    @staticmethod
    def complete_evidence():
        module = RemoteMCPConnectedCI.module
        lines = ["--- PASS: TestVaultRemoteMCPStartupFullProfile (1s)"]
        lines += [f"--- PASS: TestVaultRemoteMCPStartupFullProfile/{name} (1s)" for name in module.SCENARIOS]
        lines += [f"REMOTE-MCP-CONNECTED-OBSERVED:{name}" for name in module.SCENARIOS]
        return "\n".join(lines) + "\n"

    def test_runner_only_runs_full_kdf_startup_case_and_rejects_skipped_or_missing(self):
        module = self.module
        observed = {}

        def fake_run(command, **kwargs):
            observed["command"], observed["kwargs"] = command, kwargs
            overlay = json.loads(Path(command[command.index("-overlay") + 1]).read_text(encoding="utf-8"))
            observed["overlay"] = overlay
            return subprocess.CompletedProcess(command, 0, self.complete_evidence(), None)

        with mock.patch.object(module.sys, "platform", "linux"), mock.patch.object(module.subprocess, "run", side_effect=fake_run):
            self.assertEqual(module.main(), 0)
        command = observed["command"]
        self.assertEqual(command[0:2], ["go", "test"])
        self.assertEqual(command[command.index("-run") + 1], "^TestVaultRemoteMCPStartupFullProfile$")
        self.assertIn("-mod=readonly", command)
        self.assertEqual(command[command.index("-p") + 1], "1")
        self.assertEqual(command[command.index("-timeout") + 1], "900s")
        self.assertEqual(observed["kwargs"]["env"]["SSJACK_TEST_FULL_KDF"], "1")
        self.assertEqual(observed["kwargs"]["env"]["SSJACK_TEST_REMOTE_MCP_CONNECTED"], "1")
        self.assertNotIn("SSJACK_VAULT_PASSWORD", observed["kwargs"]["env"])
        self.assertEqual(len(observed["overlay"]["Replace"]), 2)
        self.assertEqual(set(observed["overlay"]["Replace"]), {str(module.POLICY.resolve()), str(module.ROUTE_TEST.resolve())})

    def test_runner_rejects_missing_and_skipped_scenario_evidence(self):
        module = self.module
        complete = self.complete_evidence()
        missing_observed = complete.replace("REMOTE-MCP-CONNECTED-OBSERVED:connected-empty\n", "")
        missing_scenario_pass = complete.replace(
            "--- PASS: TestVaultRemoteMCPStartupFullProfile/connected-empty (1s)\n", ""
        )
        skipped_scenario = complete.replace(
            "--- PASS: TestVaultRemoteMCPStartupFullProfile/connected-empty (1s)\n",
            "--- SKIP: TestVaultRemoteMCPStartupFullProfile/connected-empty (0s)\n",
        )
        missing_top_pass = complete.replace("--- PASS: TestVaultRemoteMCPStartupFullProfile (1s)\n", "")
        skipped_top_test = complete.replace(
            "--- PASS: TestVaultRemoteMCPStartupFullProfile (1s)\n",
            "--- SKIP: TestVaultRemoteMCPStartupFullProfile (0s)\n",
        )
        skipped_top_test_with_full_pass = complete + "--- SKIP: TestVaultRemoteMCPStartupFullProfile (0s)\n"
        skipped_with_complete_evidence = complete + "--- SKIP: TestVaultRemoteMCPStartupFullProfile/connected-empty (0s)\n"
        indented_top_skip = complete + "  --- SKIP: TestVaultRemoteMCPStartupFullProfile (0s)\n"
        for output in (missing_observed, missing_scenario_pass, skipped_scenario, missing_top_pass, skipped_top_test, skipped_top_test_with_full_pass, skipped_with_complete_evidence, indented_top_skip):
            with mock.patch.object(module.sys, "platform", "darwin"), mock.patch.object(
                module.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, output, None)
            ):
                self.assertEqual(module.main(), 1)

    def test_runner_propagates_nonzero_subprocess_status(self):
        module = self.module
        failure = subprocess.CompletedProcess([], 23, "simulated go test failure\n", None)
        with mock.patch.object(module.sys, "platform", "linux"), mock.patch.object(
            module.subprocess, "run", return_value=failure
        ):
            self.assertEqual(module.main(), 23)

    def test_runner_fails_closed_on_unsupported_platform_before_sources_or_command(self):
        module = self.module
        with mock.patch.object(module.sys, "platform", "freebsd"), mock.patch.object(module, "overlay_sources") as overlay, mock.patch.object(module.subprocess, "run") as run:
            with self.assertRaises(SystemExit):
                module.main()
        overlay.assert_not_called()
        run.assert_not_called()

    def test_runner_rejects_missing_overlay_source_without_running_command(self):
        module = self.module
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "policy.go"
            source.write_text("not a policy", encoding="utf-8")
            with mock.patch.object(module, "POLICY", source), mock.patch.object(module.sys, "platform", "linux"), mock.patch.object(module.subprocess, "run") as run:
                with self.assertRaises((SystemExit, ValueError)):
                    module.main()
                run.assert_not_called()


if __name__ == "__main__":
    unittest.main()

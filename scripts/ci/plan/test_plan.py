import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import plan


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.graph = [
            {"directory": ".", "import": "example.test/app", "dependencies": []},
            {"directory": "internal/core", "import": "example.test/app/internal/core",
             "dependencies": []},
            {"directory": "internal/consumer", "import": "example.test/app/internal/consumer",
             "dependencies": ["example.test/app/internal/core"]},
            {"directory": "cmd/app", "import": "example.test/app/cmd/app",
             "dependencies": ["example.test/app/internal/consumer", "example.test/app"]},
            {"directory": "internal/independent", "import": "example.test/app/internal/independent",
             "dependencies": []},
        ]

    def selected(self, *paths):
        return plan.select(self.graph, paths)["packages"]

    def test_new_text_adapter_paths_select_owner_and_scoped_reverse_dependencies(self):
        # Model the production package graph: each changed source file selects its
        # owner package, then reverse dependencies drive the scoped workflow outputs.
        graph = [
            {"directory": "cmd/ssjack", "import": "example.test/app/cmd/ssjack",
             "dependencies": ["example.test/app/internal/appstorecrypto",
                             "example.test/app/internal/apptransport",
                             "example.test/app/internal/declarativeslice"]},
            {"directory": "internal/appstorecrypto", "import": "example.test/app/internal/appstorecrypto",
             "dependencies": []},
            {"directory": "internal/apptransport", "import": "example.test/app/internal/apptransport",
             "dependencies": []},
            {"directory": "internal/declarativeauthority", "import": "example.test/app/internal/declarativeauthority",
             "dependencies": []},
            {"directory": "internal/declarativeslice", "import": "example.test/app/internal/declarativeslice",
             "dependencies": ["example.test/app/internal/declarativeauthority"]},
        ]
        cases = {
            "cmd/ssjack/text_adapter.go": {"./cmd/ssjack"},
            "internal/appstorecrypto/text_adapter.go": {"./internal/appstorecrypto", "./cmd/ssjack"},
            "internal/declarativeauthority/text_adapter.go": {"./internal/declarativeauthority", "./internal/declarativeslice", "./cmd/ssjack"},
            "internal/declarativeslice/text_adapter_test.go": {"./internal/declarativeslice", "./cmd/ssjack"},
            "internal/apptransport/server.go": {"./internal/apptransport", "./cmd/ssjack"},
            "internal/apptransport/text_adapter_test.go": {"./internal/apptransport", "./cmd/ssjack"},
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                self.assertEqual(set(plan.select(graph, [path])["packages"]), expected)

    def test_native_owner_acceptance_follows_private_storage_edges(self):
        graph = [
            {"directory": "internal/ownerfs", "import": "app/ownerfs", "dependencies": []},
            {"directory": "internal/appstorenative", "import": "app/native",
             "dependencies": ["app/ownerfs"]},
            {"directory": "internal/appstorefile", "import": "app/file",
             "dependencies": ["app/native"]},
            {"directory": "internal/appstorecrypto", "import": "app/crypto",
             "dependencies": ["app/file"]},
            {"directory": "internal/nativeownercheck", "import": "app/nativeownercheck",
             "dependencies": ["app/crypto", "app/ownerfs"]},
        ]
        for path in ("internal/ownerfs/fs_windows.go", "internal/appstorenative/state.go",
                     "internal/appstorefile/file_other.go", "internal/appstorecrypto/master.go",
                     "internal/nativeownercheck/fullprofile_test.go"):
            with self.subTest(path=path):
                self.assertIn("./internal/nativeownercheck", plan.select(graph, [path])["packages"])

    def test_transitive_reverse_dependencies(self):
        self.assertEqual(self.selected("internal/core/core.go"),
                         ["./cmd/app", "./internal/consumer", "./internal/core"])
        self.assertEqual(self.selected("internal/independent/new_test.go"),
                         ["./internal/independent"])

    def test_test_only_edges(self):
        self.graph[4]["dependencies"] = ["example.test/app/internal/core"]
        self.assertIn("./internal/independent", self.selected("internal/core/core_test.go"))

    def test_rename_selects_old_and_new_owners(self):
        self.assertEqual(self.selected("internal/core/old.go", "internal/independent/new.go"),
                         ["./cmd/app", "./internal/consumer", "./internal/core",
                          "./internal/independent"])

    def test_deleted_package_broadens(self):
        result = plan.select(self.graph, ["internal/deleted/gone.go"])
        self.assertEqual(len(result["packages"]), len(self.graph))
        self.assertTrue(result["reasons"])

    def test_dependency_ci_and_unknown_changes_broaden(self):
        for path in ["go.mod", "go.sum", "go.work", ".github/workflows/feature.yml",
                     "scripts/ci/plan/plan.py", "unknown/config.yaml", "scripts/unknown.py"]:
            with self.subTest(path=path):
                result = plan.select(self.graph, [path])
                self.assertEqual(len(result["packages"]), len(self.graph))
                self.assertTrue(result["reasons"])

    def test_empty_and_docs(self):
        self.assertEqual(self.selected(), [])
        self.assertEqual(self.selected("docs/usage.md"), [])

    def test_documentation_directory_does_not_hide_code(self):
        self.graph.append({"directory": "docs/example", "import": "example.test/app/docs/example",
                           "dependencies": []})
        self.assertEqual(self.selected("docs/example/main.go"), ["./docs/example"])
        result = plan.select(self.graph, ["docs/deleted/main.go"])
        self.assertEqual(len(result["packages"]), len(self.graph))
        self.assertTrue(result["reasons"])

    def test_embedded_subdirectory_selects_owner(self):
        self.graph[4]["inputs"] = ["internal/independent/assets/file.json",
                                   "internal/independent/assets/README.md"]
        self.assertEqual(self.selected("internal/independent/assets/file.json"),
                         ["./internal/independent"])
        self.assertEqual(self.selected("internal/independent/assets/README.md"),
                         ["./internal/independent"])
        self.assertEqual(self.selected("README.md"), [])

    def test_installer_selection(self):
        for path in ["install.sh", "install.ps1", "tests/installers.sh",
                     "tests/fixtures/installbinary/main.go"]:
            self.assertTrue(plan.select(self.graph, [path])["installers"])
        self.assertFalse(plan.select(self.graph, ["internal/core/core.go"])["installers"])

    def test_source_builders_select_installer_smoke_and_cli_regressions(self):
        graph = self.graph + [
            {"directory": "cmd/ssjack", "import": "example.test/ssjack",
             "dependencies": ["example.test/ssjack/internal/keys"]},
            {"directory": "cmd/ssjack/internal/keys", "import": "example.test/ssjack/internal/keys",
             "dependencies": []},
        ]
        for path in ("build.sh", "build.ps1"):
            with self.subTest(path=path):
                result = plan.select(graph, [path])
                self.assertTrue(result["installers"])
                self.assertEqual(result["packages"], ["./cmd/ssjack",
                                                      "./cmd/ssjack/internal/keys"])
                self.assertFalse(result["reasons"])
        root = Path(__file__).resolve().parents[3]
        for name in ("feature.yml", "ci.yml"):
            source = (root / ".github" / "workflows" / name).read_text(encoding="utf-8")
            self.assertIn("sh ./build.sh --install-dir", source)
            self.assertIn(".\\build.ps1 -InstallDir", source)
            self.assertIn("-NoPathUpdate", source)

    def test_cli_family_split_runs_every_cli_package_including_test_only(self):
        # The split layout keeps cmd/ssjack as the facade and relocates packages
        # under cmd/ssjack/internal; terminalacceptance is test-only, so no
        # production import edge reaches it. Any CLI change still runs it all,
        # which is what preserves the appstorecli gate.
        graph = self.graph + [
            {"directory": "cmd/ssjack", "import": "example.test/ssjack",
             "dependencies": ["example.test/ssjack/internal/terminal"]},
            {"directory": "cmd/ssjack/internal/terminal",
             "import": "example.test/ssjack/internal/terminal",
             "dependencies": ["example.test/app/internal/core"],
             "inputs": ["cmd/ssjack/internal/terminal/prompts/wording.md"]},
            {"directory": "cmd/ssjack/internal/terminalacceptance",
             "import": "example.test/ssjack/internal/terminalacceptance",
             "dependencies": []},
        ]
        family = {"./cmd/ssjack", "./cmd/ssjack/internal/terminal",
                  "./cmd/ssjack/internal/terminalacceptance"}
        for path in ("cmd/ssjack/startup_password.go",
                     "cmd/ssjack/internal/terminal/prompt.go",
                     "cmd/ssjack/internal/terminal/prompt_test.go",
                     "cmd/ssjack/internal/terminalacceptance/replay_test.go",
                     "cmd/ssjack/internal/terminal/prompts/wording.md"):
            with self.subTest(path=path):
                result = plan.select(graph, [path])
                self.assertEqual(set(result["packages"]), family)
                self.assertIn("./cmd/ssjack", result["packages"])

    def test_non_cli_changes_do_not_expand_the_cli_family(self):
        graph = self.graph + [
            {"directory": "cmd/ssjack", "import": "example.test/ssjack",
             "dependencies": ["example.test/app/internal/consumer"]},
            {"directory": "cmd/ssjack/internal/terminal",
             "import": "example.test/ssjack/internal/terminal", "dependencies": []},
            {"directory": "cmd/ssjack-lab", "import": "example.test/ssjacklab",
             "dependencies": []},
        ]
        self.assertEqual(plan.select(graph, ["internal/independent/new_test.go"])["packages"],
                         ["./internal/independent"])

    def test_sibling_prefix_directory_never_matches_the_cli_family(self):
        graph = self.graph + [
            {"directory": "cmd/ssjack", "import": "example.test/ssjack", "dependencies": []},
            {"directory": "cmd/ssjack/internal/terminal",
             "import": "example.test/ssjack/internal/terminal", "dependencies": []},
            {"directory": "cmd/ssjack-lab", "import": "example.test/ssjacklab",
             "dependencies": []},
        ]
        result = plan.select(graph, ["cmd/ssjack-lab/lab.go"])
        self.assertEqual(result["packages"], ["./cmd/ssjack-lab"])

    def test_discovered_cli_package_via_reverse_edge_expands_the_family(self):
        graph = self.graph + [
            {"directory": "cmd/ssjack/internal/terminal",
             "import": "example.test/ssjack/internal/terminal",
             "dependencies": ["example.test/app/internal/terminalconsumer"]},
            {"directory": "internal/terminalconsumer",
             "import": "example.test/app/internal/terminalconsumer",
             "dependencies": []},
            {"directory": "cmd/ssjack", "import": "example.test/ssjack", "dependencies": []},
        ]
        result = plan.select(graph, ["internal/terminalconsumer/consumer_test.go"])
        self.assertEqual(set(result["packages"]),
                         {"./cmd/ssjack", "./cmd/ssjack/internal/terminal",
                          "./internal/terminalconsumer"})

    def test_cycles_terminate(self):
        self.graph[1]["dependencies"] = ["example.test/app/internal/consumer"]
        self.assertEqual(self.selected("internal/core/core.go"),
                         ["./cmd/app", "./internal/consumer", "./internal/core"])

    def test_go_json_stream_preserves_test_imports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            raw = json.dumps({"Dir": str(root / "core"), "ImportPath": "example.test/core",
                              "Imports": ["a"], "TestImports": ["b"], "XTestImports": ["c"]})
            with patch.object(subprocess, "check_output", return_value=raw + "\n  "):
                self.assertEqual(plan.graph(root)[0]["dependencies"], ["a", "b", "c"])
            with patch.object(subprocess, "check_output", return_value=""):
                with self.assertRaises(RuntimeError):
                    plan.graph(root)

    def test_changed_paths_include_deleted_and_renamed_paths(self):
        with patch.object(subprocess, "check_output", return_value=b"old/a.go\0new/b.go\0") as run:
            self.assertEqual(plan.changes("base", "HEAD"), ["old/a.go", "new/b.go"])
            self.assertIn("--no-renames", run.call_args.args[0])
        self.assertEqual(plan.changes("0" * 40, "HEAD"), [".github/unknown-base"])
        failure = subprocess.CalledProcessError(1, "git")
        with patch.object(plan, "commit_exists", return_value=True), \
                patch.object(subprocess, "check_output", side_effect=failure):
            with self.assertRaises(subprocess.CalledProcessError):
                plan.changes("existing-base", "HEAD")
        with patch.object(plan, "commit_exists", return_value=False), \
                patch.object(subprocess, "check_output", side_effect=subprocess.CalledProcessError(128, "git")):
            self.assertEqual(plan.changes("force-pushed-away", "HEAD"), [".github/unknown-base"])

    def test_formatting_failure_retains_nonzero_diff_output(self):
        selected = json.dumps({"packages": ["./internal/example"]})
        diagnostic = "diff fixture.go.orig fixture.go\n-old\n+new\n"
        result = subprocess.CompletedProcess(["gofmt", "-d"], 1, diagnostic)
        with patch("sys.argv", ["plan.py", "test", "--output", "unused.json"]), \
                patch.object(Path, "read_text", return_value=selected), \
                patch.object(Path, "glob", return_value=[Path("fixture.go")]), \
                patch.object(subprocess, "check_output", return_value="fixture.go\n"), \
                patch.object(subprocess, "run", return_value=result) as run:
            with self.assertRaises(RuntimeError) as failure:
                plan.main()
        self.assertIn("Go formatting differs:\nfixture.go\n", str(failure.exception))
        self.assertIn(diagnostic, str(failure.exception))
        run.assert_called_once()
        self.assertEqual(run.call_args.args[0], ["gofmt", "-d", "fixture.go"])
        self.assertFalse(run.call_args.kwargs["check"])

    def _run_test_mode(self, argv, runner_os="Windows"):
        selected = json.dumps({"packages": ["./internal/example"]})
        with patch("sys.argv", argv), \
                patch.object(Path, "read_text", return_value=selected), \
                patch.object(Path, "glob", return_value=[Path("fixture.go")]), \
                patch.object(subprocess, "check_output", return_value=""), \
                patch.dict(os.environ, {"RUNNER_OS": runner_os}), \
                patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
            plan.main()
        return run.call_args.args[0]

    def test_overlay_flag_added_only_with_value(self):
        command = self._run_test_mode(
            ["plan.py", "test", "--output", "unused.json",
             "--overlay", "/runner/temp/kdf-overlay.json"])
        self.assertIn("-overlay", command)
        self.assertEqual(command[command.index("-overlay") + 1],
                         "/runner/temp/kdf-overlay.json")
        plain = self._run_test_mode(["plan.py", "test", "--output", "unused.json"])
        self.assertNotIn("-overlay", plain)
        for flag in ("-mod=readonly", "-count=1", "-timeout=180s"):
            self.assertIn(flag, command)
            self.assertIn(flag, plain)

    def test_overlay_flag_precedes_race_and_packages(self):
        command = self._run_test_mode(
            ["plan.py", "test", "--output", "unused.json",
             "--overlay", "/runner/temp/kdf-overlay.json"],
            runner_os="Linux")
        self.assertLess(command.index("-overlay"), command.index("-race"))
        self.assertLess(command.index("-race"),
                        command.index("./internal/example"))


if __name__ == "__main__":
    unittest.main()

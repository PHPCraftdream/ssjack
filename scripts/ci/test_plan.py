import json
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
                     "scripts/ci/plan.py", "unknown/config.yaml", "scripts/unknown.py"]:
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
        with patch.object(subprocess, "check_output", side_effect=subprocess.CalledProcessError(1, "git")):
            with self.assertRaises(subprocess.CalledProcessError):
                plan.changes("missing", "HEAD")

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


if __name__ == "__main__":
    unittest.main()

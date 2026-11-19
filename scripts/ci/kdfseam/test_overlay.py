"""Static regression checks for the shared KDF seam overlay helper."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
ROOT = Path(__file__).resolve().parents[3]
MASTER = ROOT / "internal" / "appstorecrypto" / "masterkey" / "master.go"
SCRIPT = ROOT / "scripts" / "ci" / "kdfseam" / "overlay.py"


def load_overlay_module():
    spec = importlib.util.spec_from_file_location("kdfseam_overlay", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


class KdfSeamOverlayRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = MASTER.read_text(encoding="utf-8")
        cls.module = load_overlay_module()

    def fake_environment(self, temp: Path):
        return {
            "GITHUB_ACTIONS": "true",
            "RUNNER_TEMP": str(temp),
        }

    def assert_digest_declaration(self):
        self.assertRegex(
            self.source,
            r"(?m)^const kdfSeamDigest = \"%s\"$" % self.module.REAL_KEY_DIGEST,
        )
        self.assertRegex(
            self.module.REAL_KEY_DIGEST, r"^[0-9a-f]{64}$"
        )

    def real_key_declaration(self):
        return f'const kdfSeamKey = "{self.module.REAL_KEY}"'

    def test_digest_declaration_matches_helper_key_digest(self):
        self.assert_digest_declaration()

    def test_helper_is_the_only_place_the_real_key_is_stored(self):
        self.assertNotIn(self.module.REAL_KEY, self.source)
        helper = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("REAL_KEY = ", helper)
        for script in (ROOT / "scripts" / "ci").rglob("*.py"):
            if script == SCRIPT:
                continue
            self.assertNotIn(self.module.REAL_KEY, script.read_text(encoding="utf-8"))

    def test_variants_apply_only_the_intended_edit(self):
        module = self.module
        placeholder = module.PLACEHOLDER
        key_line = f'const kdfSeamKey = "{placeholder}"'
        real_key_line = self.real_key_declaration()
        for variant in ("test", "scoped-test", "scoped-build"):
            patched = module.patched_source(self.source, variant)
            with self.subTest(variant=variant):
                if variant == "test":
                    self.assertEqual(patched.count(module.NEW), 0)
                    self.assertEqual(patched.count(real_key_line), 1)
                    self.assertEqual(patched.replace(real_key_line, key_line, 1), self.source)
                elif variant == "scoped-test":
                    self.assertEqual(patched.count(module.NEW), 1)
                    self.assertEqual(patched.count(real_key_line), 1)
                    self.assertEqual(
                        patched.replace(real_key_line, key_line, 1).replace(
                            module.NEW, module.OLD, 1
                        ),
                        self.source,
                    )
                else:
                    self.assertEqual(patched.count(module.NEW), 1)
                    self.assertEqual(patched.count(placeholder), 2)
                    self.assertNotIn(module.REAL_KEY, patched)
                    self.assertEqual(
                        patched, self.source.replace(module.OLD, module.NEW, 1)
                    )

    def test_substitution_targets_the_declaration_line_not_an_earlier_mention(self):
        module = self.module
        with_comment = "// see " + module.EXPECTED_KEY_LINE + " below\n" + self.source
        patched = module.patched_source(with_comment, "test")
        self.assertIn("// see " + module.EXPECTED_KEY_LINE + " below", patched)
        self.assertEqual(patched.count(self.real_key_declaration()), 1)

    def test_non_placeholder_declarations_fail_closed_for_all_variants(self):
        module = self.module
        cases = {
            "key already patched": self.source.replace(
                module.EXPECTED_KEY_LINE, self.real_key_declaration(), 1
            ),
            "placeholder drifted": self.source.replace(
                module.EXPECTED_PLACEHOLDER_LINE,
                'const kdfSeamPlaceholder = "other"',
                1,
            ),
        }
        for name, tampered in cases.items():
            for variant in ("test", "scoped-test", "scoped-build"):
                with self.subTest(case=name, variant=variant):
                    with self.assertRaises(SystemExit):
                        module.patched_source(tampered, variant)

    def test_only_the_key_line_is_replaced_not_the_placeholder(self):
        patched = self.module.patched_source(self.source, "test")
        self.assertEqual(patched.count(self.module.PLACEHOLDER), 1)
        self.assertIn(self.module.EXPECTED_PLACEHOLDER_LINE, patched)

    def test_unrecognized_variant_fails_closed(self):
        with self.assertRaises(SystemExit):
            self.module.patched_source(self.source, "nope")
        with self.assertRaises(SystemExit):
            self.module.patched_source(self.source, "scoped")

    def write_failure(self, tampered, expect_fragment, variant="test"):
        module = self.module
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            runner_temp = directory / "runner-temp"
            runner_temp.mkdir()
            fake = directory / "master.go"
            fake.write_text(tampered, encoding="utf-8")
            with mock.patch.object(module, "MASTER", fake), mock.patch.dict(
                os.environ, self.fake_environment(runner_temp), clear=True
            ):
                with self.assertRaises(SystemExit) as caught:
                    with module.temporary_overlay(variant):
                        pass
                self.assertIn(expect_fragment, str(caught.exception))
                self.assertNotIn(module.REAL_KEY, str(caught.exception))
            self.assertEqual(list(runner_temp.iterdir()), [])
            self.assertEqual(fake.read_text(encoding="utf-8"), tampered)

    def test_digest_mismatch_fails_closed_before_writing(self):
        tampered = self.source.replace(self.module.REAL_KEY_DIGEST, "0" * 64, 1)
        self.write_failure(tampered, "digest mismatch")

    def test_missing_or_duplicate_declarations_fail_closed(self):
        source = self.source
        cases = (
            source.replace("const kdfSeamKey", "const kdfSeamKeyX", 1),
            source.replace(
                self.module.EXPECTED_PLACEHOLDER_LINE,
                self.module.EXPECTED_PLACEHOLDER_LINE
                + "\n"
                + self.module.EXPECTED_PLACEHOLDER_LINE,
                1,
            ),
            source.replace("const kdfSeamDigest", "const kdfSeamDigestX", 1),
            source.replace("func argonDerive", "func argonDeriveX", 1),
        )
        for tampered in cases[:3]:
            self.write_failure(tampered, "expected exactly one")
        self.write_failure(
            cases[3], "expected exactly one existing argonDerive body", "scoped-test"
        )

    def test_overlay_requires_ci_environment(self):
        module = self.module
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}, clear=True):
            with self.assertRaises(SystemExit):
                with module.temporary_overlay("test"):
                    pass
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}, clear=True):
            with self.assertRaises(SystemExit):
                with module.temporary_overlay("test"):
                    pass
        with mock.patch.dict(
            os.environ,
            {"GITHUB_ACTIONS": "true", "RUNNER_TEMP": "relative/temp"},
            clear=True,
        ):
            with self.assertRaises(SystemExit):
                with module.temporary_overlay("test"):
                    pass

    def test_runner_temp_inside_repository_fails_closed(self):
        module = self.module
        inside = ROOT / "scripts" / "ci" / "kdfseam"
        with mock.patch.dict(
            os.environ, self.fake_environment(inside), clear=True
        ):
            with self.assertRaises(SystemExit):
                with module.temporary_overlay("test"):
                    pass

    def test_temporary_overlay_writes_and_cleans_ci_overlay(self):
        module = self.module
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            runner_temp = directory / "runner-temp"
            runner_temp.mkdir()
            with mock.patch.dict(
                os.environ, self.fake_environment(runner_temp), clear=True
            ):
                with module.temporary_overlay("test") as overlay:
                    self.assertTrue(overlay.is_absolute())
                    self.assertEqual(overlay.name, "overlay.json")
                    self.assertEqual(
                        overlay.parent.parent.resolve(), runner_temp.resolve()
                    )
                    data = json.loads(overlay.read_text(encoding="utf-8"))
                    source_path = Path(next(iter(data["Replace"])))
                    patched = Path(
                        data["Replace"][next(iter(data["Replace"]))]
                    ).read_text(encoding="utf-8")
                    self.assertEqual(source_path, module.MASTER.resolve())
                    self.assertIn(self.real_key_declaration(), patched)
                    self.assertNotIn(module.REAL_KEY, json.dumps(data))
                    self.assertEqual(
                        {p.resolve() for p in runner_temp.iterdir()},
                        {overlay.parent.resolve()},
                    )
            self.assertEqual(list(runner_temp.iterdir()), [])

    def test_cli_prints_and_persists_absolute_overlay_path_via_mocked_runner_temp(self):
        module = self.module
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            runner_temp = directory / "runner-temp"
            runner_temp.mkdir()
            with mock.patch.dict(
                os.environ, self.fake_environment(runner_temp), clear=True
            ), mock.patch.object(module.sys, "argv", ["overlay.py", "test"]):
                buffer = io.StringIO()
                with contextlib.redirect_stdout(buffer):
                    self.assertEqual(module.main(), 0)
            printed = buffer.getvalue().splitlines()
            self.assertEqual(len(printed), 1)
            overlay = Path(printed[0])
            self.assertTrue(overlay.is_absolute())
            self.assertTrue(overlay.exists())
            self.assertEqual(
                json.loads(overlay.read_text(encoding="utf-8"))["Replace"],
                {
                    str(module.MASTER.resolve()): str(
                        (overlay.parent / "master.go").resolve()
                    )
                },
            )
            self.assertEqual(overlay.parent.parent.resolve(), runner_temp.resolve())

    def test_emit_writes_a_bare_lf_line_to_a_binary_stdout(self):
        class Console(io.TextIOWrapper):
            pass

        raw = io.BytesIO()
        console = Console(raw, encoding="utf-8", newline="\r\n")
        with contextlib.redirect_stdout(console):
            self.module._emit("D:/runner/overlay.json")
        self.assertEqual(raw.getvalue(), b"D:/runner/overlay.json\n")

    def test_diagnostics_never_contain_the_real_key(self):
        module = self.module
        with mock.patch.dict(
            os.environ,
            self.fake_environment(Path(tempfile.gettempdir()) / "kdfseam-unused"),
            clear=True,
        ):
            with self.assertRaises(SystemExit) as caught:
                module.patched_source("no declarations here", "test")
            self.assertNotIn(module.REAL_KEY, str(caught.exception))


if __name__ == "__main__":
    unittest.main()

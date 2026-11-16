"""Static regression checks for cross-userland file-transfer acceptance."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
CI = ROOT / ".github" / "workflows" / "ci.yml"
FEATURE = ROOT / ".github" / "workflows" / "feature.yml"
ACCEPTANCE = ROOT / "internal" / "transferacceptance"

LINUX_SCENARIOS = (
    "roundtrip-file-both-directions",
    "roundtrip-directory-both-directions",
    "roundtrip-zero-byte-and-empty-directory",
    "roundtrip-names-with-spaces-and-non-ascii",
    "secrets-never-reach-results",
    "overwrite-replaces-file-and-directory",
    "overwrite-failure-leaves-old-destination",
    "refuse-path-traversal",
    "refuse-absolute-and-drive-paths",
    "refuse-symlink-in-source-tree",
    "refuse-symlink-destination",
    "refuse-download-forbidden-control-directory",
    "refuse-destination-exists",
    "refuse-overwrite-without-confirm",
    "refuse-unknown-root",
    "refuse-no-registered-roots",
    "refuse-over-limit-size-and-entries",
    "refuse-unapproved-target",
    "failure-connection-killed-mid-stream",
    "failure-hash-mismatch-corruption",
    "failure-cancel-mid-transfer",
    "failure-unsupported-remote",
    "failure-unsupported-publication-primitive",
    "manager-concurrency-and-duplicate-destination",
)
BUSYBOX_SCENARIOS = (
    "roundtrip-file-both-directions",
    "roundtrip-directory-basic-both-directions",
    "roundtrip-zero-byte-and-empty-directory",
    "roundtrip-names-with-spaces-and-non-ascii",
    "overwrite-replaces-file-and-directory",
    "refuse-symlink-destination",
    "overwrite-failure-leaves-old-destination",
    "refuse-destination-exists",
    "failure-hash-mismatch-corruption",
)


def named_step(source: str, name: str) -> str:
    lines = source.splitlines()
    marker = f"      - name: {name}"
    starts = [index for index, line in enumerate(lines) if line == marker]
    if len(starts) != 1:
        raise AssertionError(f"expected exactly one workflow step named {name!r}")
    start = starts[0]
    end = next((index for index in range(start + 1, len(lines)) if lines[index].startswith("      - ")), len(lines))
    return "\n".join(lines[start:end])


def test_body(source: str, name: str) -> str:
    match = re.search(rf"(?ms)^func {re.escape(name)}\(t \*testing\.T\) \{{(.*?)(?=^func |\Z)", source)
    if match is None:
        raise AssertionError(f"missing Go test {name}")
    return match.group(1)


class TransferUserlandsCI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ci = CI.read_text(encoding="utf-8")
        cls.feature = FEATURE.read_text(encoding="utf-8")
        cls.harness = (ACCEPTANCE / "harness_test.go").read_text(encoding="utf-8")
        cls.linux = (ACCEPTANCE / "harness_linux_test.go").read_text(encoding="utf-8")

    def test_full_acceptance_is_shared_and_strict_on_linux_and_macos(self):
        self.assertTrue(self.harness.startswith("//go:build linux || darwin\n"))
        self.assertTrue(self.linux.startswith("//go:build linux\n"))
        self.assertEqual(
            tuple(re.findall(r't\.Run\("([^"]+)"', test_body(self.harness, "TestTransferAcceptance"))),
            LINUX_SCENARIOS,
        )
        self.assertIn("PATH=/usr/bin:/bin:/usr/sbin:/sbin", self.harness)
        self.assertIn("SSJACK_REMOTE_SHELL=/bin/sh", self.harness)
        for workflow in (self.ci, self.feature):
            linux_step = named_step(workflow, "File transfer acceptance on the real stack (Linux)")
            macos_step = named_step(workflow, "File transfer acceptance on the real stack (macOS)")
            for step, platform in ((linux_step, "Linux"), (macos_step, "macOS")):
                self.assertIn(f"if: runner.os == '{platform}'", step)
                self.assertIn("-run '^TestTransferAcceptance$'", step)
                self.assertIn(f"for name in {' '.join(LINUX_SCENARIOS)}; do", step)
                self.assertIn('"--- PASS: TestTransferAcceptance/$name "', step)
                self.assertIn("^[[:space:]]*--- SKIP: TestTransferAcceptance(/| )", step)
            self.assertEqual(
                re.findall(r'grep -q -- "--- PASS: TestTransferAcceptance/([^ ]+) ', linux_step),
                re.findall(r'grep -q -- "--- PASS: TestTransferAcceptance/([^ ]+) ', macos_step),
            )

    def test_missing_publication_primitive_is_a_real_restricted_fixture(self):
        failure_source = (ACCEPTANCE / "failures_test.go").read_text(encoding="utf-8")
        body = test_body(failure_source, "scenarioFailureUnsupportedPublicationPrimitive")
        self.assertIn('"PATH=" + bin', body)
        self.assertIn('"SSJACK_REMOTE_SHELL=/bin/sh"', body)
        self.assertIn('mv := filepath.Join(bin, "mv")', body)
        self.assertIn('filepath.Join(bin, "perl")', body)
        self.assertIn("failure-unsupported-publication-primitive", test_body(self.harness, "TestTransferAcceptance"))
        self.assertIn("assertTreeSnapshot(t, s.rootDir", body)
        self.assertIn("assertTreeSnapshot(t, s.sandbox", body)

    def test_busybox_runs_real_applets_and_guards_the_explicit_subset(self):
        self.assertIn('os.Getenv("SSJACK_TRANSFER_BUSYBOX_BIN")', self.harness)
        self.assertIn('filepath.Join(dir, "sh")', self.harness)
        self.assertIn('"PATH=" + dir', self.harness)
        self.assertIn('"SSJACK_REMOTE_SHELL=" + shell', self.harness)
        self.assertEqual(
            tuple(re.findall(r't\.Run\("([^"]+)"', test_body(self.linux, "TestTransferBusyboxAcceptance"))),
            BUSYBOX_SCENARIOS,
        )
        for workflow in (self.ci, self.feature):
            step = named_step(workflow, "File transfer acceptance subset under busybox userland (Linux)")
            self.assertIn("if: runner.os == 'Linux'", step)
            self.assertIn("busybox --list", step)
            self.assertIn('ln -s "$(command -v busybox)" "$bin/$applet"', step)
            self.assertIn('SSJACK_TRANSFER_BUSYBOX_BIN="$bin"', step)
            self.assertIn("-run '^TestTransferBusyboxAcceptance$'", step)
            self.assertIn(f"for name in {' '.join(BUSYBOX_SCENARIOS)}; do", step)
            self.assertIn('"--- PASS: TestTransferBusyboxAcceptance/$name "', step)
            self.assertIn("^[[:space:]]*--- SKIP: TestTransferBusyboxAcceptance(/| )", step)


if __name__ == "__main__":
    unittest.main()

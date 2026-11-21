"""Regression checks for confidential-delivery CI gating."""
import ast
from contextlib import redirect_stderr, redirect_stdout
from io import BytesIO, StringIO
from pathlib import Path
import re
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts" / "ci"))
from kdfseam import overlay as kdf_overlay
from delivery import delivery_scoped

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


@unittest.skipUnless(sys.platform == "linux", "delivery PTY imports are Linux-only")
class DeliveryPTYCleanup(unittest.TestCase):
    def test_cleanup_preserves_primary_failure(self):
        from delivery import delivery_pty

        pid, master, slave, read_fd, write_fd = 42, 10, 11, 12, 13
        for failure, now, stdout_bytes in (("timeout", 121, 0), ("stdout-overflow", 1, 5)):
            for cleanup in ("reap-failed", "ok"):
                with self.subTest(failure=failure, cleanup=cleanup):
                    wait_result = ChildProcessError() if cleanup == "reap-failed" else (pid, 9)
                    fake_os = Mock(WNOHANG=delivery_pty.os.WNOHANG, **{
                        "pipe.return_value": (read_fd, write_fd),
                        "fork.return_value": pid,
                        "read.return_value": b"xxxxx",
                        "waitpid.side_effect": [(0, 0), wait_result],
                        "waitstatus_to_exitcode.return_value": -9,
                    })
                    fake_time = Mock(**{"monotonic.side_effect": [0, 0, now, now, now]})
                    fake_pty = Mock(**{"openpty.return_value": (master, slave)})
                    fake_select = Mock(**{"select.return_value": ([read_fd], [], [])})
                    emit = Mock()
                    with patch.multiple(delivery_pty, os=fake_os, time=fake_time, pty=fake_pty,
                                        select=fake_select, emit=emit, LIMIT=4), \
                            patch.object(sys, "argv", ["delivery_pty.py", "unused-child"]), \
                            patch.object(sys, "stdin", Mock(buffer=BytesIO(b"[]"))):
                        self.assertEqual(delivery_pty.main(), 124)
                    self.assertEqual(fake_os.waitpid.call_count, 2)
                    fake_os.kill.assert_called_once_with(pid, delivery_pty.signal.SIGKILL)
                    emit.assert_called_once_with({
                        "failure": failure, "cleanup": cleanup, "child_pid": pid,
                        "child_exit": -256 if cleanup == "reap-failed" else -9,
                        "prompts_answered": 0, "stdout_bytes": stdout_bytes,
                        "terminal_bytes": 0, "elapsed_ms": now * 1000,
                    })


PTY = (b"delivery pty evidence: class=envelope-decode cleanup=unknown wrapper_pid=14 wrapper_exit=1"
       b" child_pid=0 child_exit=-256 prompts_answered=-1 stdout_bytes=-1 terminal_bytes=-1 elapsed_ms=-1")
RACE = (
    b"delivery race event: round=secret-wins elapsed_ms=19 event=marker_seen detail=secret.admitted",
    b"delivery race failure: round=secret-wins condition=metadata_admitted detail=deadline_missing"
    b" driver_waiting=regular driver_release=missing",
    b"delivery race receipt: round=secret-wins phase=lock_held baseline_len=0 expected_len=0 observed_len=unknown"
    b" failure_len=0 failure_status=missing",
    b"delivery race side: round=secret-wins phase=failure side=metadata stage=calling helper=in_flight"
    b" wrapper_pid=0 wrapper_exit=-256 child_pid=0 child_exit=-256"
    b" planned=regular apply=regular calling=regular admitted=missing result=missing",
    b"delivery race side: round=secret-wins phase=after_cleanup side=metadata helper=returned"
    b" wrapper_pid=14 wrapper_exit=1 child_pid=15 child_exit=-9 join=complete cleanup=ok",
    b"delivery race event: round=metadata-wins elapsed_ms=60000 event=lock_acquire_failed detail=deadline",
    b"delivery race event: round=metadata-wins elapsed_ms=42 event=winner_state detail=SUCCEEDED",
    b"delivery race event: round=metadata-wins elapsed_ms=42 event=loser_delivery detail=WITHHELD",
)
PASS = b"--- PASS: TestDeliveryScopedAcceptance (1.00s)\n"
SKIP = b"--- SKIP: TestDeliveryScopedAcceptance (0.00s)\n"


class DeliveryScopedDiagnostics(unittest.TestCase):
    def test_only_whole_structured_records_are_forwarded(self):
        event = b"=== RUN   TestDeliveryScopedAcceptance/secret-wins"
        output = b"\n".join((
            event,
            b"        delivery_concurrent_test.go:343: raw-message",
            b"        unexpected.go:22: raw-message",
            b"        /private/delivery_concurrent_test.go:22: raw-message",
            b"        delivery_concurrent_test.go:22: " + PTY,
            b"goroutine 1 [running]:",
            b"child says " + event,
            event + b" suffix",
            event + b"/../../path",
            event + b"/nested",
            b"=== RUN   TestDeliveryScopedAcceptance/unknown-case",
            b"    --- SKIP: TestDeliveryScopedAcceptance/unknown-case (0.00s)",
            b"=== RUN   TestOtherAcceptance",
            PTY,
            b"            " + PTY.replace(b"envelope-decode", b"unrecognized"),
            b"            " + PTY.replace(b" cleanup=unknown", b""),
            b"            " + PTY.replace(b"cleanup=unknown", b"cleanup=unrecognized"),
            b"            " + PTY.replace(b"wrapper_pid=14", b"wrapper_pid=12345678901"),
            b"            " + PTY.replace(b"prompts_answered=-1", b"prompts_answered=-2"),
            b"            " + PTY + b" suffix",
            b"child says\x0b" + PTY,
            b"            " + RACE[0].replace(b"secret.admitted", b"secret.unknown"),
            b"            " + RACE[1].replace(b"deadline_missing", b"deadline_raw-message"),
            b"            " + RACE[2].replace(b"failure_status=missing", b"failure_status=raw-message"),
            b"            " + RACE[-1].replace(b"WITHHELD", b"SUCCEEDED"),
            b"            " + RACE[3].replace(b"stage=calling", b"stage=unknown"),
            b"            " + RACE[4].replace(b" join=complete", b""),
            b"            " + RACE[4].replace(b"join=complete", b"join=unrecognized"),
            b"            " + RACE[4].replace(b" cleanup=ok", b""),
            b"            " + RACE[4].replace(b"cleanup=ok", b"cleanup=unknown"),
            b"            " + RACE[4] + b" cleanup=io_error",
            b"            " + RACE[4].replace(b"join=complete", b"join=complete join=timeout"),
            b"            " + RACE[4].replace(b"join=complete cleanup=ok", b"cleanup=ok join=complete"),
            *(b"            " + line for line in (PTY, *RACE)),
            PTY,
        ))
        self.assertEqual(list(delivery_scoped.diagnostic_lines(output)), [
            b"test event: " + event,
            b"failure location: delivery_concurrent_test.go:343",
            b"failure location: delivery_concurrent_test.go:22",
            PTY, *RACE,
        ])

    def test_immediate_go_log_continuations_forward_cleanup_records(self):
        records = (
            PTY.replace(b"cleanup=unknown", b"cleanup=ok"),
            PTY.replace(b"cleanup=unknown", b"cleanup=reap-failed"),
            RACE[4],
            RACE[4].replace(b"join=complete", b"join=timeout"),
            RACE[4].replace(b"cleanup=ok", b"cleanup=io_error"),
            RACE[4].replace(b"join=complete cleanup=ok", b"join=timeout cleanup=io_error"),
        )
        output = b"\n".join((
            b"    delivery_concurrent_test.go:295: failure diagnostics:",
            *(b"        " + record for record in records),
            b"",
        ))
        self.assertEqual(list(delivery_scoped.diagnostic_lines(output)), [
            b"failure location: delivery_concurrent_test.go:295", *records,
        ])

    def test_late_pty_suffix_is_atomic_and_only_forwarded_for_returned_helpers(self):
        base = RACE[4]
        late = (base + b" pty_class=timeout pty_cleanup=reap-failed"
                b" prompts_answered=2 stdout_bytes=12 terminal_bytes=34 elapsed_ms=56")
        unknown = (base + b" pty_class=envelope-decode pty_cleanup=unknown"
                   b" prompts_answered=-1 stdout_bytes=-1 terminal_bytes=-1 elapsed_ms=-1")
        ok = late.replace(b"pty_cleanup=reap-failed", b"pty_cleanup=ok")
        records = (
            base, late, unknown, ok,
            base + b" pty_class=timeout",
            late.replace(b" pty_cleanup=reap-failed", b""),
            late.rsplit(b" ", 1)[0],
            late.replace(b"pty_class=timeout", b"pty_class=unrecognized"),
            late.replace(b"pty_cleanup=reap-failed", b"pty_cleanup=io_error"),
            late.replace(b"prompts_answered=2", b"prompts_answered=-2"),
            late.replace(b"stdout_bytes=12", b"stdout_bytes=1234567"),
            late.replace(b"terminal_bytes=34", b"terminal_bytes=raw"),
            late.replace(b"stdout_bytes=12 terminal_bytes=34", b"terminal_bytes=34 stdout_bytes=12"),
            late.replace(b"helper=returned", b"helper=in_flight"),
            late + b" elapsed_ms=57",
        )
        output = b"\n".join([*(b"        " + record for record in records), b""])
        self.assertEqual(list(delivery_scoped.diagnostic_lines(output)), [base, late, unknown, ok])

    def test_join_only_failure_is_forwarded_on_eight_space_continuation(self):
        failure = (b"delivery race failure: round=secret-wins condition=helper_join detail=timeout"
                   b" driver_waiting=regular driver_release=regular")
        output = b"\n".join((
            b"        " + failure,
            b"        " + failure.replace(b"detail=timeout", b"detail=unknown"),
            b"        " + failure.replace(b"condition=helper_join", b"condition=helpers_complete"),
            b"",
        ))
        self.assertEqual(list(delivery_scoped.diagnostic_lines(output)), [failure])

    def test_requires_exact_root_pass_and_rejects_scoped_skips(self):
        child_skip = b"    --- SKIP: TestDeliveryScopedAcceptance/secret-wins (0.00s)\n"
        for output, returncode, expected in (
            (PASS, 0, None),
            (PASS, 1, "failed"),
            (b"child log: " + PASS, 0, "missing PASS"),
            (PASS.replace(b" (", b"/secret-wins ("), 0, "missing PASS"),
            (PASS.rstrip(b"\n") + b" suffix\n", 0, "missing PASS"),
            (PASS + SKIP, 0, "unexpected SKIP"),
            (PASS + child_skip, 0, "unexpected SKIP"),
            (PASS + child_skip.replace(b"secret-wins", b"new-case"), 0, "unexpected SKIP"),
            (PASS + child_skip.lstrip().replace(b"secret-wins", b"new-case/nested"), 0, "unexpected SKIP"),
        ):
            with self.subTest(output=output, returncode=returncode):
                with patch.object(delivery_scoped.subprocess, "run", return_value=subprocess.CompletedProcess([], returncode, output)):
                    with redirect_stdout(StringIO()) as stdout, redirect_stderr(StringIO()) as stderr:
                        if expected is None:
                            delivery_scoped.run_acceptance([], {})
                            self.assertEqual(stdout.getvalue(), "delivery acceptance test PASS\n")
                            self.assertEqual(stderr.getvalue(), "")
                        else:
                            with self.assertRaises(SystemExit) as exit_:
                                delivery_scoped.run_acceptance([], {})
                            self.assertEqual(exit_.exception.code, 1)
                            self.assertEqual(stderr.getvalue().splitlines()[0], f"delivery acceptance test {expected}")

    def test_watchdog_reports_bounded_partial_stdout_without_exception_details(self):
        pty_record = b"        " + PTY
        race_record = b"            " + RACE[0]
        partial = b"\xff raw-output\n" + pty_record + b"\n" + pty_record
        timeout = subprocess.TimeoutExpired(["private-command"], 300, output=partial, stderr=race_record + b"\n")
        with patch.object(delivery_scoped.subprocess, "run", side_effect=timeout) as run:
            with redirect_stderr(StringIO()) as stderr, self.assertRaises(SystemExit) as exit_:
                delivery_scoped.run_acceptance([], {})
        self.assertEqual(exit_.exception.code, 1)
        self.assertEqual(run.call_args.kwargs["timeout"], 300)
        self.assertEqual(stderr.getvalue().splitlines(), [
            "delivery acceptance test failed: class=watchdog-timeout", PTY.decode("ascii"),
        ])
        with patch.object(delivery_scoped, "MAX_DIAGNOSTIC_BYTES", len(pty_record)):
            self.assertEqual(list(delivery_scoped.diagnostic_lines(pty_record + b"\n")), [])

    def test_failure_line_cap_prioritizes_structured_records(self):
        event = b"=== RUN   TestDeliveryScopedAcceptance/secret-wins"
        output = b"\n".join((
            event,
            b"        delivery_concurrent_test.go:343: raw-message",
            b"        " + PTY,
            b"=== RUN   TestDeliveryScopedAcceptance/metadata-wins",
            b"        " + RACE[5],
            b"",
        ))
        for budget, expected in (
            (1, [PTY]),
            (2, [PTY, RACE[5]]),
            (5, [b"test event: " + event, b"failure location: delivery_concurrent_test.go:343",
                 PTY, b"test event: === RUN   TestDeliveryScopedAcceptance/metadata-wins", RACE[5]]),
        ):
            with self.subTest(budget=budget), patch.object(delivery_scoped, "MAX_DIAGNOSTIC_LINES", budget):
                with redirect_stderr(StringIO()) as stderr, self.assertRaises(SystemExit):
                    delivery_scoped.report_failure("failed", output)
                self.assertEqual(stderr.getvalue().splitlines(), [
                    "delivery acceptance test failed", *(line.decode("ascii") for line in expected),
                ])


if __name__ == "__main__":
    unittest.main()

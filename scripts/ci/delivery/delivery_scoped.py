#!/usr/bin/env python3
"""Build nonsecret native delivery fixtures and run the public-CI test."""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from kdfseam import overlay as kdf_overlay


GO_TEST_WATCHDOG_SECONDS = 300
MAX_DIAGNOSTIC_BYTES = 256 * 1024
MAX_DIAGNOSTIC_LINES = 96
TEST_ROOT = rb"TestDeliveryScopedAcceptance"
TEST_NAME = TEST_ROOT + (
    rb"(?:/(?:secret-wins|metadata-wins|lost|partial|wrong-secret|wrong-ready|wait|"
    rb"actual-revocation|legacy-metadata-only-registration|tampered-snapshot-ciphertext|"
    rb"anchor-unavailable|infrastructurecontrols|missing-grant|recipient-uid|"
    rb"desired-schema-id|projection-schema-id|expired|revoked|reference-substitution|"
    rb"store-substitution|driver-digest|consumer-digest|target|purpose|policy|"
    rb"desired-schema|projection-schema|installation-digest|encoded-hash|"
    rb"directory-device|directory-inode))?"
)
DURATION = rb" \([0-9]{1,3}\.[0-9]{2}s\)"
ROOT_PASS = re.compile(rb"--- PASS: " + TEST_ROOT + DURATION)
SCOPED_SKIP = re.compile(
    rb"(?:--- SKIP: " + TEST_ROOT + rb"|(?: {4})*--- SKIP: " + TEST_ROOT + rb"/\S+)" + DURATION
)
RUN_EVENT = re.compile(rb"=== RUN   " + TEST_NAME)
RESULT_EVENT = re.compile(rb"(?: {4}){0,3}(--- (?:PASS|FAIL|SKIP): " + TEST_NAME + DURATION + rb")")
SOURCE_LOCATION = re.compile(
    rb"(?: {4}){1,4}((?:delivery_acceptance_test|delivery_concurrent_test|"
    rb"delivery_concurrent_unsupported_test)\.go:[1-9][0-9]{0,3}): [^\x00-\x1f\x7f]{1,512}"
)
PROCESS_FIELDS = (
    rb" wrapper_pid=[0-9]{1,10} wrapper_exit=-?[0-9]{1,3}"
    rb" child_pid=[0-9]{1,10} child_exit=-?[0-9]{1,3}"
)
PTY_CLASS = (
    rb"(?:input|spawn|timeout|stdout-overflow|stdout-decode|"
    rb"io|reap|prompts|child-exit|refusal|preflight|wrapper-exec|envelope-size|"
    rb"envelope-decode|envelope-shape|envelope-range|envelope-trailing|envelope-class|"
    rb"disclosure|success)"
)
PTY_CLEANUP = rb"(?:ok|reap-failed|unknown)"
PTY_COUNTERS = (
    rb" prompts_answered=(?:-1|[0-9]{1,3})"
    rb" stdout_bytes=(?:-1|[0-9]{1,6}) terminal_bytes=(?:-1|[0-9]{1,6})"
    rb" elapsed_ms=(?:-1|[0-9]{1,6})"
)
PTY_EVIDENCE = re.compile(
    rb"delivery pty evidence: class=" + PTY_CLASS + rb" cleanup=" + PTY_CLEANUP + PROCESS_FIELDS + PTY_COUNTERS
)
SIDE = rb"(?:secret|metadata)"
ROUND = rb" round=(?:secret-wins|metadata-wins)"
ERROR_CLASS = rb"(?:missing|permission_denied|io_error)"
MARKER_STATUS = rb"(?:regular|not_regular|" + ERROR_CLASS + rb")"
MARKER = rb"(?:" + SIDE + rb"\.(?:planned|apply|calling|admitted|result)|driver\.(?:waiting|release))"
RACE_EVENT = re.compile(
    rb"delivery race event:" + ROUND + rb" elapsed_ms=[0-9]{1,6} event=(?:"
    rb"(?:helper_launched|helper_returned) detail=" + SIDE + rb"|"
    rb"(?:marker_seen|marker_written|cleanup_write|cleanup_write_failed) detail=" + MARKER + rb"|"
    rb"(?:lock_acquired|lock_released|cleanup_lock_released|cleanup_lock_release_failed) detail=cas|"
    rb"(?:lock_open_failed|lock_acquire_failed|lock_release_failed) detail=(?:deadline|" + ERROR_CLASS + rb")|"
    rb"(?:winner_state|loser_state) detail=(?:SUCCEEDED|FAILED|UNKNOWN|invalid)|"
    rb"(?:winner_delivery|loser_delivery) detail=(?:RECEIVED|WITHHELD|UNKNOWN|empty|invalid))"
)
RACE_FAILURE = re.compile(
    rb"delivery race failure:" + ROUND + rb" condition=(?:helper_join detail=timeout|(?:"
    rb"unknown|marker_reset|lock_open|lock_acquire|receipt_read|" + SIDE + rb"_(?:planned|calling|admitted|result)|"
    rb"plan_decode|plan_id_missing|plan_revision_mismatch|marker_write|driver_waiting|"
    rb"receipt_changed_under_lock|early_result|early_result_stat|lock_release|helpers_complete|"
    rb"cli_error|harness_incomplete|result_decode|result_id_missing|winner_state|winner_delivery|"
    rb"loser_state|loser_delivery|receipt_delta|state_read|state_decode|state_operation)"
    rb" detail=(?:unknown|deadline(?:_(?:missing|contended|interrupted|one_returned|none_returned))?|"
    rb"helper_returned_before_marker|both|length_mismatch|invalid_json|mismatch|" + SIDE + rb"|" + MARKER_STATUS + rb"))"
    rb" driver_waiting=" + MARKER_STATUS + rb" driver_release=" + MARKER_STATUS
)
LENGTH = rb"(?:unknown|[0-9]{1,10})"
RACE_RECEIPT = re.compile(
    rb"delivery race receipt:" + ROUND + rb" phase=(?:baseline|lock_held|final)"
    rb" baseline_len=" + LENGTH + rb" expected_len=" + LENGTH + rb" observed_len=" + LENGTH +
    rb" failure_len=" + LENGTH + rb" failure_status=" + MARKER_STATUS
)
HELPER_PROCESS = rb" helper=(?:returned|in_flight|not_launched)" + PROCESS_FIELDS
RACE_SIDE_FAILURE = re.compile(
    rb"delivery race side:" + ROUND + rb" phase=failure side=" + SIDE +
    rb" stage=(?:not_launched|launched|planned|apply|calling|admitted|driver_waiting|result)" + HELPER_PROCESS +
    b"".join(b" " + field + b"=" + MARKER_STATUS for field in (b"planned", b"apply", b"calling", b"admitted", b"result"))
)
RACE_CLEANUP_FIELDS = rb" join=(?:complete|timeout) cleanup=(?:ok|io_error)"
RACE_SIDE_CLEANUP = re.compile(
    rb"delivery race side:" + ROUND + rb" phase=after_cleanup side=" + SIDE + rb"(?:" +
    HELPER_PROCESS + RACE_CLEANUP_FIELDS + rb"| helper=returned" + PROCESS_FIELDS + RACE_CLEANUP_FIELDS +
    rb" pty_class=" + PTY_CLASS + rb" pty_cleanup=" + PTY_CLEANUP + PTY_COUNTERS + rb")"
)
# time.Duration.String after millisecond truncation: positive subsecond values
# use integer ms; longer values use seconds with optional minute/hour fields.
ENV_POSITIVE_1_TO_59 = rb"(?:[1-9]|[1-5][0-9])"
ENV_0_TO_59 = rb"(?:[0-9]|[1-5][0-9])"
ENV_SECONDS_SUFFIX = rb"(?:\.[0-9]{0,2}[1-9])?s"
ENV_DURATION = (
    rb"(?:0s|[1-9][0-9]{0,2}ms|" + ENV_POSITIVE_1_TO_59 + ENV_SECONDS_SUFFIX +
    rb"|(?:[1-9][0-9]{0,6}h" + ENV_0_TO_59 + rb"|" + ENV_POSITIVE_1_TO_59 + rb")m" +
    ENV_0_TO_59 + ENV_SECONDS_SUFFIX + rb")"
)
ENV_POSITIVE = rb"[1-9][0-9]{0,18}"
ENVIRONMENT = re.compile(
    rb"environment: pass=(?:(?P<tracked>[1-9][0-9]{0,19})|unknown) num_cpu=" + ENV_POSITIVE +
    rb" gomaxprocs=" + ENV_POSITIVE + rb" process_elapsed>=" + ENV_DURATION +
    rb" test_elapsed(?(tracked)=|>=)" + ENV_DURATION + rb" goroutines=" + ENV_POSITIVE +
    rb" goos/goarch=linux/amd64"
)
EVIDENCE = (
    PTY_EVIDENCE, RACE_EVENT, RACE_FAILURE, RACE_RECEIPT, RACE_SIDE_FAILURE, RACE_SIDE_CLEANUP, ENVIRONMENT,
)
EVIDENCE_LINE = re.compile(rb"(?: {4}){2,4}([^ ].*)")


def diagnostic_lines(stdout):
    lines = (stdout or b"")[:MAX_DIAGNOSTIC_BYTES].split(b"\n")
    for line in lines[:-1]:
        if len(line) > 640:
            continue
        if event := RUN_EVENT.fullmatch(line):
            yield b"test event: " + event[0]
        elif event := RESULT_EVENT.fullmatch(line):
            yield b"test event: " + event[1]
        elif location := SOURCE_LOCATION.fullmatch(line):
            yield b"failure location: " + location[1]
        elif record := EVIDENCE_LINE.fullmatch(line):
            if any(schema.fullmatch(record[1]) for schema in EVIDENCE):
                yield record[1]


def report_failure(status, stdout):
    print(f"delivery acceptance test {status}", file=sys.stderr)
    lines = list(diagnostic_lines(stdout))
    if len(lines) > MAX_DIAGNOSTIC_LINES:
        lines.sort(key=lambda line: not line.startswith((b"delivery ", b"environment: ")))
    for line in lines[:MAX_DIAGNOSTIC_LINES]:
        print(line.decode("ascii"), file=sys.stderr)
    raise SystemExit(1)


def run_acceptance(command, env):
    try:
        result = subprocess.run(command, cwd=ROOT, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=GO_TEST_WATCHDOG_SECONDS)
    except subprocess.TimeoutExpired as timeout:
        partial_stdout = timeout.stdout
    else:
        output = result.stdout
        lines = output.split(b"\n")[:-1]
        passed = any(ROOT_PASS.fullmatch(line) for line in lines)
        skipped = any(SCOPED_SKIP.fullmatch(line) for line in lines)
        if result.returncode != 0 or not passed or skipped:
            status = "failed" if result.returncode != 0 else "unexpected SKIP" if skipped else "missing PASS"
            report_failure(status, output)
        print("delivery acceptance test PASS")
        return
    report_failure("failed: class=watchdog-timeout", partial_stdout)


def build(source, package, output, ldflags=()):
    command = ["go", "build", "-mod=readonly", "-trimpath", "-buildmode=exe"]
    if ldflags:
        command += ["-ldflags", " ".join(ldflags)]
    command += ["-o", str(output), package]
    subprocess.run(command, cwd=source, env={**os.environ, "CGO_ENABLED": "0"}, check=True)
    os.chmod(output, 0o755)
    with output.open("r+b") as image:
        image.seek(40)
        image.write(bytes(8))
        image.seek(58)
        image.write(bytes(6))


def main():
    if sys.platform != "linux":
        raise SystemExit("delivery acceptance is Linux-only")
    with tempfile.TemporaryDirectory(prefix="ssjack-delivery-ci-") as tmp:
        artifacts = Path(tmp)
        os.chmod(artifacts, 0o755)
        driver = artifacts / "driver"
        consumer = artifacts / "consumer"
        harness = artifacts / "harness"
        cli = artifacts / "ssjack"
        build(ROOT, "./internal/declarativeslice/tests/fixtures/syntheticdriver", driver)
        race_driver = artifacts / "driver-race"
        build(ROOT, "./internal/declarativeslice/tests/fixtures/syntheticdriver", race_driver, ("-X main.admissionProbe=on",))
        build(ROOT, "./internal/declarativeslice/tests/fixtures/secretconsumer", consumer)
        for mode in ("lost", "partial", "wrong-ready", "wrong-secret", "wait"):
            build(ROOT, "./internal/declarativeslice/tests/fixtures/secretconsumer", artifacts / f"consumer-{mode}",
                  (f"-X main.behavior={mode}",))
        build(ROOT, "./internal/declarativeslice/tests/fixtures/secretharness", harness)
        # The shared overlay accelerates only Argon2 derivation in this isolated CI process.
        with kdf_overlay.temporary_overlay("scoped-build") as build_overlay, kdf_overlay.temporary_overlay("scoped-test") as test_overlay:
            env = {**os.environ, "SSJACK_TEST_SCOPED_KDF": "1"}
            subprocess.run(["go", "build", "-mod=readonly", "-trimpath", "-overlay", str(build_overlay), "-o", str(cli), "./cmd/ssjack"], cwd=ROOT, env=env, check=True)
            env.update({"SSJACK_PUBLIC_CI": "1", "SSJACK_DELIVERY_CLI": str(cli),
                        "SSJACK_DELIVERY_ARTIFACTS": str(artifacts), "SSJACK_DELIVERY_DRIVER": str(driver)})
            run_acceptance(["go", "test", "-mod=readonly", "-overlay", str(test_overlay), "-count=1", "-v", "-timeout=240s", "-run", "^TestDeliveryScopedAcceptance$", "./cmd/ssjack/internal/appstore/delivery"], env)


if __name__ == "__main__":
    main()

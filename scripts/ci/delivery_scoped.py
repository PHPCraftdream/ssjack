#!/usr/bin/env python3
"""Build nonsecret native delivery fixtures and run the public-CI test."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]


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
        # The private overlay accelerates only Argon2 derivation in this isolated CI process.
        from appstore_scoped import OLD, NEW, MASTER
        source = MASTER.read_text(encoding="utf-8")
        if source.count(OLD) != 1:
            raise SystemExit("expected one isolated KDF overlay target")
        overlay_source = artifacts / "master.go"
        overlay_source.write_text(source.replace(OLD, NEW, 1), encoding="utf-8")
        overlay = artifacts / "overlay.json"
        overlay.write_text(json.dumps({"Replace": {str(MASTER.resolve()): str(overlay_source.resolve())}}), encoding="utf-8")
        env = {**os.environ, "SSJACK_TEST_SCOPED_KDF": "1"}
        subprocess.run(["go", "build", "-mod=readonly", "-trimpath", "-overlay", str(overlay), "-o", str(cli), "./cmd/ssjack"], cwd=ROOT, env=env, check=True)
        env.update({"SSJACK_PUBLIC_CI": "1", "SSJACK_DELIVERY_CLI": str(cli),
                    "SSJACK_DELIVERY_ARTIFACTS": str(artifacts), "SSJACK_DELIVERY_DRIVER": str(driver)})
        result = subprocess.run(["go", "test", "-mod=readonly", "-overlay", str(overlay), "-count=1", "-v", "-timeout=240s", "-run", "^TestDeliveryScopedAcceptance$", "./cmd/ssjack"], cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=240)
        output = result.stdout
        passed = "PASS: TestDeliveryScopedAcceptance" in output
        skipped = "SKIP: TestDeliveryScopedAcceptance" in output
        if result.returncode != 0 or not passed or skipped:
            status = "failed" if result.returncode != 0 else "missing PASS" if not passed else "unexpected SKIP"
            print(f"delivery acceptance test {status}", file=sys.stderr)
            for line in output.splitlines():
                event = re.search(r"(?:=== RUN|--- (?:PASS|FAIL|SKIP):)\s+(Test[A-Za-z0-9_/.-]+)", line)
                location = re.search(r"([A-Za-z0-9_]+\.go:\d+):", line)
                if event:
                    print("test event: " + event.group(0), file=sys.stderr)
                if location:
                    print("failure location: " + location.group(1), file=sys.stderr)
            raise SystemExit(1)
        print("delivery acceptance test PASS")


if __name__ == "__main__":
    main()

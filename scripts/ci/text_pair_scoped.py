"""Run the pinned Clawwright/keeper/SSH composition in isolated public CI."""

import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
NAME = "TestClawwrightTextPairConnected"
STREAM_NAME = "TestClawwrightTextStreamPairConnected"


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("paired authority acceptance requires root")
    claw = Path(os.environ["SSJACK_CLAWWRIGHT_PAIR_ROOT"]).resolve(strict=True)
    expected = os.environ["EXPECTED_CLAWWRIGHT_COMMIT"]
    if not re.fullmatch(r"[0-9a-f]{40}", expected):
        raise SystemExit("a full Clawwright commit is required")
    actual = subprocess.check_output(
        ["git", "-C", str(claw), "rev-parse", "HEAD"], text=True
    ).strip()
    if actual != expected:
        raise SystemExit("Clawwright checkout does not match the acceptance pin")
    source = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    print(f"Paired source: ssjack={source} clawwright={actual}", flush=True)
    with tempfile.TemporaryDirectory(prefix="ssjack-text-pair-") as temporary:
        directory = Path(temporary)
        directory.chmod(0o755)
        binary = directory / "appstorecrypto.test"
        subprocess.run(
            ["go", "test", "-c", "-mod=readonly", "-o", str(binary), "./internal/appstorecrypto"],
            cwd=ROOT,
            check=True,
            timeout=180,
        )
        binary.chmod(0o755)
        env = os.environ.copy()
        env["SSJACK_CLAWWRIGHT_PAIR_CI"] = "1"
        env["SSJACK_CLAWWRIGHT_PAIR_ROOT"] = str(claw)
        completed = subprocess.run(
            [str(binary), "-test.v", "-test.run", f"^({NAME}|{STREAM_NAME})$", "-test.timeout=300s"],
            cwd=ROOT,
            env=env,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=330,
        )
        sys.stdout.write(completed.stdout)
        if completed.returncode != 0:
            return completed.returncode
        if re.search(rf"(?m)^--- SKIP: {NAME}(?:\s|$)", completed.stdout):
            raise SystemExit("paired acceptance was skipped")
        if not re.search(rf"(?m)^--- PASS: {NAME}(?:\s|$)", completed.stdout):
            raise SystemExit("paired acceptance did not report PASS")
        if re.search(rf"(?m)^--- SKIP: {STREAM_NAME}(?:\s|$)", completed.stdout):
            raise SystemExit("stream paired acceptance was skipped")
        if not re.search(rf"(?m)^--- PASS: {STREAM_NAME}(?:\s|$)", completed.stdout):
            raise SystemExit("stream paired acceptance did not report PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

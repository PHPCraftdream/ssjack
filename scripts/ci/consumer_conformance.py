"""Run the consumer conformance kit against a supplied or synthetic consumer."""

import argparse
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
NAME = "TestConsumerConformance"
STREAM_NAME = "TestConsumerStreamConformance"
SYNTHETIC_ARGS = '["--consumer","synthetic"]'
CONSUMER_VARIABLES = (
    "SSJACK_CONSUMER_ARGS",
    "SSJACK_CONSUMER_DEPLOY_NAME",
    "SSJACK_CONSUMER_BACKUP_NAME",
    "SSJACK_CONSUMER_WORKDIR",
    "SSJACK_CONSUMER_ENV",
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--synthetic",
        action="store_true",
        help="build and run the in-repository synthetic consumer instead of SSJACK_CONSUMER_COMMAND",
    )
    options = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        raise SystemExit("consumer conformance requires Linux and root")
    env = os.environ.copy()
    if not options.synthetic and not env.get("SSJACK_CONSUMER_COMMAND"):
        raise SystemExit("SSJACK_CONSUMER_COMMAND is required without --synthetic")
    source = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    with tempfile.TemporaryDirectory(prefix="ssjack-consumer-conformance-", dir="/tmp") as temporary:
        directory = Path(temporary)
        directory.chmod(0o755)
        if options.synthetic:
            consumer = directory / "syntheticconsumer"
            subprocess.run(
                ["go", "build", "-mod=readonly", "-trimpath", "-o", str(consumer), "./internal/syntheticconsumer"],
                cwd=ROOT,
                check=True,
                timeout=180,
            )
            consumer.chmod(0o755)
            for name in CONSUMER_VARIABLES:
                env.pop(name, None)
            env["SSJACK_CONSUMER_COMMAND"] = str(consumer)
            env["SSJACK_CONSUMER_ARGS"] = SYNTHETIC_ARGS
        label = env.get("SSJACK_CONSUMER_REVISION", "unlabeled")
        print(
            f"Conformance source: ssjack={source} consumer={env['SSJACK_CONSUMER_COMMAND']} revision={label}",
            flush=True,
        )
        binary = directory / "appstorecrypto.test"
        subprocess.run(
            ["go", "test", "-c", "-mod=readonly", "-o", str(binary), "./internal/appstorecrypto"],
            cwd=ROOT,
            check=True,
            timeout=180,
        )
        binary.chmod(0o755)
        env["SSJACK_CONSUMER_CONFORMANCE"] = "1"
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
        for name in (NAME, STREAM_NAME):
            if re.search(rf"(?m)^--- SKIP: {name}(?:\s|$)", completed.stdout):
                raise SystemExit(f"{name} was skipped")
            if not re.search(rf"(?m)^--- PASS: {name}(?:\s|$)", completed.stdout):
                raise SystemExit(f"{name} did not report PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

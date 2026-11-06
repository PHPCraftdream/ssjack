#!/usr/bin/env python3
"""Run the connected text-adapter acceptance in a Linux root container."""
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    if sys.platform != "linux":
        raise SystemExit("connected text-adapter acceptance is Linux-only")
    if os.geteuid() != 0:
        raise SystemExit("connected text-adapter acceptance requires root")
    with tempfile.TemporaryDirectory(prefix="ssjack-text-adapter-", dir="/tmp") as tempdir:
        Path(tempdir).chmod(0o755)
        binary = Path(tempdir) / "acceptance"
        build = subprocess.run(["go", "test", "-mod=readonly", "-c", "-o", str(binary), "./internal/appstorecrypto"], cwd=ROOT, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        sys.stdout.write(build.stdout)
        if build.returncode != 0:
            return build.returncode
        binary.chmod(0o755)
        cli = Path(tempdir) / "ssjack"
        build_cli = subprocess.run(["go", "build", "-mod=readonly", "-trimpath", "-o", str(cli), "./cmd/ssjack"], cwd=ROOT, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        sys.stdout.write(build_cli.stdout)
        if build_cli.returncode != 0:
            return build_cli.returncode
        cli.chmod(0o755)
        env = os.environ.copy()
        env["SSJACK_TEXT_OWNER_CLI"] = str(cli)
        env["SSJACK_TEXT_OWNER_BRIDGE"] = str(ROOT / "scripts" / "ci" / "owner_pty_bridge.py")
        env["SSJACK_TEXT_ADAPTER_CI_ACCEPTANCE"] = "1"
        acceptance = subprocess.run([str(binary), "-test.v", "-test.run", "^TestText(Adapter(Connected|Bounds)|Reverse(Connected|MappingsConnected|LateConnected|ExpiryConnected)|(Reverse)?StreamConnected|OwnerCLIConnected)$", "-test.timeout=480s"], cwd=ROOT, env=env, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=540)
        sys.stdout.write(acceptance.stdout)
        if acceptance.returncode != 0:
            return acceptance.returncode
        for name in ("TestTextAdapterConnected", "TestTextOwnerCLIConnected", "TestTextAdapterBounds", "TestTextReverseConnected", "TestTextReverseMappingsConnected", "TestTextReverseLateConnected", "TestTextReverseExpiryConnected", "TestTextStreamConnected", "TestTextReverseStreamConnected"):
            if re.search(rf"(?m)^--- SKIP: {re.escape(name)}(?:\s|$)", acceptance.stdout):
                raise SystemExit(f"{name} was skipped")
            if not re.search(rf"(?m)^--- PASS: {re.escape(name)}(?:\s|$)", acceptance.stdout):
                raise SystemExit(f"{name} did not report PASS")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

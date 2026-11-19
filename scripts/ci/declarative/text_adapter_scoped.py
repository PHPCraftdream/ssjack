#!/usr/bin/env python3
"""Run the connected text-adapter acceptance in a Linux root container."""
from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from kdfseam import overlay as kdf_overlay

ROOT = Path(__file__).resolve().parents[3]
PACKAGES = ("connected", "reverse", "stream")


def main() -> int:
    if sys.platform != "linux":
        raise SystemExit("connected text-adapter acceptance is Linux-only")
    if os.geteuid() != 0:
        raise SystemExit("connected text-adapter acceptance requires root")
    with tempfile.TemporaryDirectory(prefix="ssjack-text-adapter-", dir="/tmp") as tempdir:
        Path(tempdir).chmod(0o755)
        binaries = []
        with kdf_overlay.temporary_overlay("test") as overlay:
            for package in PACKAGES:
                binary = Path(tempdir) / package
                build = subprocess.run(["go", "test", "-mod=readonly", "-overlay", str(overlay), "-c", "-o", str(binary), "./internal/appstorecrypto/" + package], cwd=ROOT, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                sys.stdout.write(build.stdout)
                if build.returncode != 0:
                    return build.returncode
                binary.chmod(0o755)
                binaries.append(binary)
        cli = Path(tempdir) / "ssjack"
        build_cli = subprocess.run(["go", "build", "-mod=readonly", "-trimpath", "-o", str(cli), "./cmd/ssjack"], cwd=ROOT, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        sys.stdout.write(build_cli.stdout)
        if build_cli.returncode != 0:
            return build_cli.returncode
        cli.chmod(0o755)
        env = os.environ.copy()
        env["SSJACK_TEXT_OWNER_CLI"] = str(cli)
        env["SSJACK_TEXT_OWNER_BRIDGE"] = str(ROOT / "scripts" / "ci" / "owner" / "owner_pty_bridge.py")
        env["SSJACK_TEXT_ADAPTER_CI_ACCEPTANCE"] = "1"
        output = ""
        for binary in binaries:
            acceptance = subprocess.run([str(binary), "-test.v", "-test.run", "^TestText(Adapter(Connected|Bounds)|Reverse(Connected|MappingsConnected|LateConnected|ExpiryConnected)|(Reverse)?StreamConnected|OwnerCLIConnected)$", "-test.timeout=480s"], cwd=ROOT, env=env, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=540)
            sys.stdout.write(acceptance.stdout)
            if acceptance.returncode != 0:
                return acceptance.returncode
            output += acceptance.stdout
        for name in ("TestTextAdapterConnected", "TestTextOwnerCLIConnected", "TestTextAdapterBounds", "TestTextReverseConnected", "TestTextReverseMappingsConnected", "TestTextReverseLateConnected", "TestTextReverseExpiryConnected", "TestTextStreamConnected", "TestTextReverseStreamConnected"):
            if re.search(rf"(?m)^--- SKIP: {re.escape(name)}(?:\s|$)", output):
                raise SystemExit(f"{name} was skipped")
            if not re.search(rf"(?m)^--- PASS: {re.escape(name)}(?:\s|$)", output):
                raise SystemExit(f"{name} did not report PASS")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

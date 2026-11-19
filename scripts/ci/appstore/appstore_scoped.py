#!/usr/bin/env python3
"""Run the private scoped CLI acceptance test with a temporary source overlay."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from kdfseam import overlay as kdf_overlay


def main() -> int:
    if sys.platform != "linux":
        raise SystemExit("scoped CLI overlay is Linux-only")
    with kdf_overlay.temporary_overlay("scoped-test") as overlay:
        env = os.environ.copy()
        env["SSJACK_TEST_SCOPED_KDF"] = "1"
        command = ["go", "test", "-mod=readonly", "-overlay", str(overlay), "-race", "-count=1", "-timeout=180s", "-run", "^(TestAppstoreScopedCLI.*)$", "./cmd/ssjack/internal/appstore"]
        return subprocess.run(command, cwd=ROOT, env=env, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())

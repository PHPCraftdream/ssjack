#!/usr/bin/env python3
"""Run the private scoped CLI acceptance test with a temporary source overlay."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
MASTER = ROOT / "internal" / "appstorecrypto" / "master.go"
OLD = '''func argonDerive(password, salt []byte) []byte {
\tpart := argon2.IDKey(password, salt, 1, 1048576, 1, 32)
\truntime.GC()
\treturn part
}'''
NEW = '''func argonDerive(password, salt []byte) []byte {
\tinput := append(append([]byte(nil), password...), salt...)
\tsum := sha256.Sum256(input)
\tclear(input)
\truntime.KeepAlive(argon2.IDKey)
\treturn append([]byte(nil), sum[:]...)
}'''


def main() -> int:
    if sys.platform != "linux":
        raise SystemExit("scoped CLI overlay is Linux-only")
    source = MASTER.read_text(encoding="utf-8")
    if source.count(OLD) != 1:
        raise SystemExit("expected exactly one existing argonDerive body")
    with tempfile.TemporaryDirectory(prefix="ssjack-scoped-ci-") as temporary:
        overlay_source = Path(temporary) / "master.go"
        overlay_source.write_text(source.replace(OLD, NEW, 1), encoding="utf-8")
        overlay = Path(temporary) / "overlay.json"
        overlay.write_text(json.dumps({"Replace": {str(MASTER.resolve()): str(overlay_source.resolve())}}), encoding="utf-8")
        env = os.environ.copy()
        env["SSJACK_TEST_SCOPED_KDF"] = "1"
        command = ["go", "test", "-mod=readonly", "-overlay", str(overlay), "-race", "-count=1", "-timeout=180s", "-run", "^(TestAppstoreScopedCLI.*)$", "./cmd/ssjack"]
        return subprocess.run(command, cwd=ROOT, env=env, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())

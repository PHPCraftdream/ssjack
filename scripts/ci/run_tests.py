#!/usr/bin/env python3
"""Run every unittest folder under scripts/ci; unpackaged subfolders are not discovered recursively."""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def test_folders(root=HERE):
    return sorted({path.parent for path in root.rglob("test_*.py")})


def main():
    folders = test_folders()
    if not folders:
        print("run_tests: no test_*.py found under " + str(HERE), file=sys.stderr)
        return 1
    failed = []
    for folder in folders:
        name = folder.relative_to(HERE).as_posix()
        print("run_tests: " + name, flush=True)
        command = [sys.executable, "-m", "unittest", "discover", "-s", str(folder), "-p", "test_*.py"]
        if subprocess.run(command, check=False).returncode != 0:
            failed.append(name)
    if failed:
        print("run_tests: failed: " + ", ".join(failed), file=sys.stderr)
        return 1
    print("run_tests: " + str(len(folders)) + " folders passed", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

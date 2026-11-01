#!/usr/bin/env python3
"""Build exact-source binaries, run a sealed synthetic container, emit typed hashes only."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
CAPS = {"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID", "KILL"}
PRODUCT_BASE = "2997e692cdc24f5b9a5aa23cadc3b22ab1b32f02"
NAMES = {"ssjack", "conductor", "harness", "driver", "consumer"}
PHASE = "inputs"

def invoke(args, *, cwd=None, env=None, check=True, capture=True):
    return subprocess.run(args, cwd=cwd, env=env, check=check, text=True,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.PIPE if capture else None)

def build(package, output, sha):
    env = {"PATH": os.environ["PATH"], "HOME": "/tmp", "CGO_ENABLED": "0", "GOFLAGS": "", "GOTOOLCHAIN": "local"}
    args = ["go", "build", "-mod=readonly", "-trimpath", "-buildmode=exe"]
    if package == "./cmd/ssjack":
        args += ["-ldflags", "-X github.com/PHPCraftdream/ssjack/internal/buildinfo.Commit=" + sha]
    args += ["-o", str(output), package]
    invoke(args, cwd=ROOT, env=env)
    os.chmod(output, 0o755)
    if package.endswith("syntheticdriver") or package.endswith("secretconsumer"):
        with output.open("r+b") as image:
            image.seek(40); image.write(bytes(8)); image.seek(58); image.write(bytes(6))

def main():
    global PHASE
    sha, scoped, run_id = (os.environ.get(k, "") for k in ("SOURCE_SHA", "SCOPED_RUN_ID", "GITHUB_RUN_ID"))
    if not re.fullmatch(r"[a-f0-9]{40}", sha) or not scoped.isdigit() or not run_id.isdigit():
        raise RuntimeError("immutable CI inputs required")
    if invoke(["git", "rev-parse", "HEAD"], cwd=ROOT).stdout.strip() != sha:
        raise RuntimeError("checkout SHA mismatch")
    parent = Path(tempfile.mkdtemp(prefix="ssjack-lab-build-", dir="/tmp"))
    os.chmod(parent, 0o700)
    stage = parent / "lab"
    stage.mkdir(mode=0o755)
    container = "ssjack-standalone-lab-" + str(os.getpid())
    created = False
    try:
        products = (("ssjack", "./cmd/ssjack"), ("conductor", "./cmd/ssjack-lab"),
                    ("driver", "./internal/declarativeslice/tests/fixtures/syntheticdriver"),
                    ("consumer", "./internal/declarativeslice/tests/fixtures/secretconsumer"),
                    ("harness", "./internal/declarativeslice/tests/fixtures/secretharness"))
        staged_hashes = {}
        for name, package in products:
            PHASE = "build-" + name
            output = stage / name
            build(package, output, sha)
            staged_hashes[name] = hashlib.sha256(output.read_bytes()).hexdigest()
        for helper in ("isolation.py", "delivery_pty.py"):
            shutil.copyfile(ROOT / "scripts/lab" / helper, stage / helper)
        for path in stage.iterdir():
            os.chmod(path, 0o755)
        PHASE = "pull-image"
        image = "python:3.13-slim"
        invoke(["docker", "pull", image])
        envs = ("PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8",
                "GITHUB_SHA=" + sha, "GITHUB_RUN_ID=" + run_id)
        create = ["docker", "create", "--name", container, "--network=none", "--cap-drop=ALL",
                  "--cap-add=CHOWN", "--cap-add=DAC_OVERRIDE", "--cap-add=FOWNER", "--cap-add=SETGID",
                  "--cap-add=SETUID", "--cap-add=KILL",
                  "--security-opt=no-new-privileges", "--pids-limit=128", "--memory=4g", "--memory-swap=4g",
                  "--ulimit", "core=0", "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=256m"]
        for value in envs:
            create += ["--env", value]
        create += ["--entrypoint", "/usr/bin/env", image, "-i", *envs, "/usr/local/bin/python3", "/lab/isolation.py"]
        PHASE = "create-container"
        invoke(create)
        created = True
        PHASE = "copy-artifacts"
        invoke(["docker", "cp", str(stage), container + ":/lab"])
        PHASE = "inspect-policy"
        info = json.loads(invoke(["docker", "inspect", container]).stdout)[0]
        host = info["HostConfig"]
        checks = {
            "unprivileged": not host["Privileged"], "no-binds": not host["Binds"],
            "network-none": host["NetworkMode"] == "none", "private-pid": not host["PidMode"],
            "private-ipc": host["IpcMode"] in ("", "private"),
            "exact-capabilities": set(host["CapAdd"] or []) == CAPS,
            "drop-all": host["CapDrop"] == ["ALL"],
            "no-new-privileges": "no-new-privileges" in (host["SecurityOpt"] or []),
        }
        if not all(checks.values()):
            failed = ",".join(name for name, passed in checks.items() if not passed)
            prefixed = set(host["CapAdd"] or []) == {"CAP_" + name for name in CAPS}
            print(f"standalone-lab: policy failed={failed} prefixed-capabilities={prefixed}", file=sys.stderr)
            raise RuntimeError("container policy mismatch")
        mounts = info.get("Mounts") or []
        if any(m.get("Type") != "tmpfs" or m.get("Destination") != "/tmp" for m in mounts):
            raise RuntimeError("unexpected mount")
        PHASE = "application"
        run = invoke(["docker", "start", "-a", "-i", container], check=False)
        state = json.loads(invoke(["docker", "inspect", container]).stdout)[0]["State"]
        if run.returncode != 0 or state.get("ExitCode") != 0 or run.stderr:
            reason = {"standalone-lab: isolation failed": "isolation", "ssjack-lab: synthetic lab failed": "conductor"}.get((run.stderr or "").strip(), "withheld")
            code = state.get("ExitCode")
            if isinstance(code, int):
                print(f"standalone-lab: application reason={reason} exit={code}", file=sys.stderr)
            raise RuntimeError("isolated execution failed")
        PHASE = "evidence"
        output = run.stdout or ""
        if len(output.encode()) > 16384:
            raise RuntimeError("result exceeds limit")
        lines = [line for line in output.splitlines() if line]
        if len(lines) != 1:
            raise RuntimeError("unexpected result framing")
        evidence = json.loads(lines[0])
        expected_keys = {"result", "product_base", "source_revision", "run_id", "binary_sha256"}
        hashes = evidence.get("binary_sha256")
        if (set(evidence) != expected_keys or evidence.get("result") != "synthetic-delivery-complete"
                or evidence.get("product_base") != PRODUCT_BASE or evidence.get("source_revision") != sha
                or evidence.get("run_id") != run_id or not isinstance(hashes, dict) or set(hashes) != NAMES
                or hashes != staged_hashes or any(not re.fullmatch(r"[a-f0-9]{64}", v) for v in hashes.values())):
            raise RuntimeError("invalid evidence")
        safe = {"result": evidence["result"], "product_base": PRODUCT_BASE, "source_revision": sha,
                "run_id": run_id, "scoped_run_id": scoped, "product_full_run_id": "41247965179", "image_id": info["Image"], "binary_sha256": staged_hashes}
        print(json.dumps(safe, separators=(",", ":")))
    finally:
        if created:
            subprocess.run(["docker", "rm", "-f", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        shutil.rmtree(parent, ignore_errors=True)

if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        code = error.returncode if isinstance(error, subprocess.CalledProcessError) else None
        print(f"standalone-lab: failed stage={PHASE} exit={code}", file=sys.stderr)
        raise SystemExit(1)

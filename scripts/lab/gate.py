#!/usr/bin/env python3
"""Fail-closed verification of pinned parent and scoped source CI evidence."""
import json
import os
import re
import subprocess
import sys

PRODUCT_BASE = "2997e692cdc24f5b9a5aa23cadc3b22ab1b32f02"
PRODUCT_FULL_RUN = "41247965179"
ALLOWED = {
    ".github/workflows/standalone-lab.yml",
    "cmd/ssjack-lab/anchor_linux.go", "cmd/ssjack-lab/cli_linux.go",
    "cmd/ssjack-lab/evidence_linux.go", "cmd/ssjack-lab/lab_linux.go",
    "cmd/ssjack-lab/main_linux.go", "cmd/ssjack-lab/state_linux.go",
    "cmd/ssjack-lab/store_linux.go", "scripts/lab/README.md",
    "scripts/lab/delivery_pty.py", "scripts/lab/gate.py",
    "scripts/lab/isolation.py", "scripts/lab/run.py",
}
FULL_JOBS = {"Go tests (ubuntu-latest)", "Go tests (windows-latest)", "Go tests (macos-latest)",
             "License policy audit", "Go race detector", "Scoped app-store CLI acceptance",
             "Root confidential-delivery acceptance", "Encrypted vault with production 1 GiB KDF"}
SCOPED_JOBS = {"Scoped Go tests (ubuntu-latest)", "Scoped Go tests (windows-latest)",
               "Scoped Go tests (macos-latest)", "Root-isolated synthetic authority acceptance",
               "License policy audit"}


def command(args):
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                       text=True, timeout=60, check=True)
    return p.stdout


def git(args):
    return command(["git", *args])


def api(repo, endpoint):
    return json.loads(command(["gh", "api", f"repos/{repo}/{endpoint}"]))


def verify_run(repo, run_id, sha, path, expected):
    run = api(repo, f"actions/runs/{run_id}")
    if (run.get("id") != int(run_id) or run.get("head_sha") != sha or run.get("path") != path
            or run.get("status") != "completed" or run.get("conclusion") != "success"
            or run.get("event") not in {"push", "pull_request", "workflow_dispatch"}
            or run.get("repository", {}).get("full_name", "").lower() != repo.lower()
            or run.get("head_repository", {}).get("full_name", "").lower() != repo.lower()
            or run.get("repository", {}).get("private") is not False):
        raise ValueError("run identity/status mismatch")
    jobs = set()
    for page in range(1, 6):
        data = api(repo, f"actions/runs/{run_id}/jobs?per_page=100&page={page}")
        for job in data.get("jobs", []):
            name = job.get("name", "")
            if name in expected:
                if job.get("status") != "completed" or job.get("conclusion") != "success":
                    raise ValueError("required job unsuccessful")
                jobs.add(name)
        if len(data.get("jobs", [])) < 100:
            break
    if jobs != expected:
        raise ValueError("required jobs missing")


def main():
    repo = os.environ["GITHUB_REPOSITORY"]
    source = os.environ["SOURCE_SHA"]
    scoped_id = os.environ["SCOPED_RUN_ID"]
    if (not re.fullmatch(r"[a-f0-9]{40}", source) or source == PRODUCT_BASE
            or not scoped_id.isdigit()):
        raise ValueError("invalid immutable inputs")
    if git(["rev-parse", "HEAD"]).strip() != source:
        raise ValueError("checkout mismatch")
    if git(["merge-base", "--is-ancestor", PRODUCT_BASE, source]) is None:
        raise ValueError("base ancestry check failed")
    raw = git(["diff", "--name-status", "--no-renames", "-z", PRODUCT_BASE, source]).split("\0")
    entries = [(raw[i], raw[i + 1]) for i in range(0, len(raw) - 1, 2)]
    if len(entries) != len(ALLOWED) or {p for status, p in entries} != ALLOWED or any(s != "A" for s, _ in entries):
        raise ValueError("source diff outside exact additions allowlist")
    tree = git(["ls-tree", "-r", "-z", source]).split("\0")
    modes = {}
    for entry in tree:
        if entry:
            meta, path = entry.split("\t", 1)
            modes[path] = meta.split()[0]
    if any(modes.get(path) not in {"100644", "100755"} for path in ALLOWED):
        raise ValueError("unexpected source object mode")
    historical = api(repo, f"actions/runs/{PRODUCT_FULL_RUN}")
    path = historical.get("path")
    if path == ".github/workflows/ci.yml":
        verify_run(repo, PRODUCT_FULL_RUN, PRODUCT_BASE, path, FULL_JOBS)
    elif path == ".github/workflows/feature.yml":
        feature_full_jobs = {"Explicit full sprint gate / " + name for name in FULL_JOBS}
        verify_run(repo, PRODUCT_FULL_RUN, PRODUCT_BASE, path, feature_full_jobs)
    else:
        raise ValueError("pinned historical run has unsupported workflow path")
    verify_run(repo, scoped_id, source, ".github/workflows/feature.yml", SCOPED_JOBS)
    print(json.dumps({"product_base": PRODUCT_BASE, "product_full_run_id": PRODUCT_FULL_RUN,
                      "scoped_run_id": scoped_id, "source_revision": source}, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("standalone-lab: immutable CI evidence check failed", file=sys.stderr)
        raise SystemExit(1)

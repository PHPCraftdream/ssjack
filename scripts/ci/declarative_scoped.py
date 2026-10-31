#!/usr/bin/env python3
"""Root-container-only real CLI and lifecycle acceptance orchestration."""
import datetime
import hashlib
import os
import pty
import select
import subprocess
import sys
import time


def run_cli(binary, args, answers):
    master, slave = pty.openpty()
    proc = subprocess.Popen([binary, *args], stdin=slave, stdout=subprocess.PIPE, stderr=slave, close_fds=True)
    os.close(slave)
    pending = bytearray()
    prompts = list(answers)
    deadline = time.monotonic() + 60
    while proc.poll() is None and time.monotonic() < deadline:
        ready, _, _ = select.select([master], [], [], 0.1)
        if not ready:
            continue
        try:
            pending.extend(os.read(master, 4096))
        except OSError:
            break
        if prompts:
            expected, answer = prompts[0]
            if expected.encode() in pending:
                os.write(master, answer.encode() + b"\n")
                prompts.pop(0)
                pending.clear()
    os.close(master)
    if proc.poll() is None:
        proc.kill()
        raise RuntimeError("CLI prompt timed out: " + str(args))
    output = proc.stdout.read().decode(errors="replace")
    if proc.returncode != 0 or prompts:
        raise RuntimeError("CLI command failed: " + str(args) + " " + output)


def register(binary, ref, digest, expiry):
    run_cli(binary, ["declarative", "register"], [
        ("Exact canonical metadata placeholder: ", ref),
        ("Repeat exact canonical reference: ", ref),
        ("Independent installed driver SHA256: ", digest),
        ("Repeat independently verified SHA256: ", digest),
        ("Type the exact target identifier to authorize: ", "target"),
        ("Expiry RFC3339 UTC (within 30 days): ", expiry),
        ("Keeper effective UID (non-root): ", "65534"),
        ("Repeat keeper UID: ", "65534"),
        ("Type REGISTER SYNTHETIC METADATA GRANT: ", "REGISTER SYNTHETIC METADATA GRANT"),
    ])


def revoke(binary, ref):
    run_cli(binary, ["declarative", "revoke"], [
        ("Exact canonical placeholder to revoke: ", ref),
        ("Repeat exact canonical reference: ", ref),
    ])


def build_driver(source, fixture_name, destination, tags=None):
    command=["go","build","-mod=readonly","-trimpath","-buildmode=exe","-ldflags=-s -w"]
    if tags: command.extend(["-tags",tags])
    command.extend(["-o",destination,"./internal/declarativeslice/tests/fixtures/"+fixture_name])
    subprocess.run(command,cwd=source,env={**os.environ,"CGO_ENABLED":"0"},check=True)
    with open(destination, "r+b") as image:
        image.seek(40)
        image.write(bytes(8))
        image.seek(58)
        image.write(bytes(6))
    os.chmod(destination, 0o755)
    with open(destination, "rb") as image:
        return hashlib.sha256(image.read()).hexdigest()


def run_probe(test_binary, source, env, demote, test_name):
    result = subprocess.run([test_binary, "-test.v", "-test.run", "^" + test_name + "$"], cwd=source, env=env, preexec_fn=demote, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if result.returncode != 0 or "PASS: " + test_name not in result.stdout or "SKIP: " + test_name in result.stdout:
        raise RuntimeError(test_name + " failed or skipped: " + result.stdout)
    print(result.stdout, flush=True)


def wait_ready(path, proc):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            output = proc.communicate(timeout=5)[0]
            raise RuntimeError("live-session probe exited before ready barrier: " + output)
        if os.path.exists(path):
            return
        time.sleep(0.02)
    proc.kill()
    output = proc.communicate(timeout=5)[0]
    raise RuntimeError("live-session probe did not reach ready barrier: " + path + "\n" + output)


def live_probe(test_binary, source, env, demote, coord, phase, before_release):
    env = {**env, "SSJACK_DECLARATIVE_CI_COORD_DIR": coord, "SSJACK_DECLARATIVE_CI_PHASE": phase}
    for name in os.listdir(coord):
        os.unlink(os.path.join(coord, name))
    proc = subprocess.Popen([test_binary, "-test.v", "-test.run", "^TestScopedLiveAuthorityRecheck$"], cwd=source, env=env, preexec_fn=demote, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    wait_ready(os.path.join(coord, phase + ".ready"), proc)
    before_release()
    with open(os.path.join(coord, phase + ".go"), "w") as signal:
        signal.write("go")
    output = proc.communicate(timeout=40)[0]
    if proc.returncode != 0 or "PASS: TestScopedLiveAuthorityRecheck" not in output or "SKIP: TestScopedLiveAuthorityRecheck" in output:
        raise RuntimeError("live " + phase + " recheck failed or skipped: " + output)
    print(output, flush=True)


def utc_after(seconds):
    return (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=seconds)).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def main():
    binary, source = map(os.path.abspath, sys.argv[1:3])
    driver = "/usr/libexec/ssjack-synthetic-driver"
    os.makedirs("/usr/libexec", exist_ok=True)
    ref = '{"$ssjack":{"format":"ssjack-secret-ref-v1","object_id":"00000000000000000000000000000002","snapshot_id":"00000000000000000000000000000004","store_id":"00000000000000000000000000000001","version_id":"00000000000000000000000000000003"}}'
    run_cli(binary, ["declarative", "setup"], [("Type SETUP DECLARATIVE SYNTHETIC METADATA ONLY: ", "SETUP DECLARATIVE SYNTHETIC METADATA ONLY")])
    golden = build_driver(source, "syntheticdriver", driver)
    register(binary, ref, golden, utc_after(86400))
    test_binary = "/tmp/ssjack-declarative-acceptance"
    subprocess.run(["go", "test", "-mod=readonly", "-c", "-o", test_binary, "./internal/declarativeslice"], cwd=source, check=True)
    env = {**os.environ, "SSJACK_DECLARATIVE_CI_ACCEPTANCE": "1", "HOME": "/tmp"}
    def demote():
        os.setgid(65534)
        os.setuid(65534)
    run = subprocess.run([test_binary, "-test.v", "-test.run", "^TestScopedSynthetic.*Acceptance$"], cwd=source, env=env, preexec_fn=demote, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if run.returncode != 0 or "PASS: TestScopedSyntheticBrokerAcceptance" not in run.stdout or "PASS: TestScopedSyntheticNegativeAcceptance" not in run.stdout:
        raise RuntimeError("synthetic acceptance failed or skipped: " + run.stdout)
    print(run.stdout, flush=True)

    coord = "/tmp/ssjack-live-authority"
    os.makedirs(coord, exist_ok=True)
    os.chown(coord, 65534, 65534)
    run_probe(test_binary, source, env, demote, "TestScopedPlanExpiry")
    live_probe(test_binary, source, env, demote, coord, "revoke", lambda: revoke(binary, ref))
    register(binary, ref, golden, utc_after(86400))

    short_expiry = utc_after(5)
    register(binary, ref, golden, short_expiry)
    expiry_epoch = datetime.datetime.fromisoformat(short_expiry.replace("Z", "+00:00")).timestamp()
    time.sleep(max(0, expiry_epoch - time.time() + 2))
    run_probe(test_binary, source, env, demote, "TestScopedAuthorityUnavailable")
    revoke(binary, ref)

    for name in ("oversizeddriver", "unknowndriver"):
        bad_digest = build_driver(source, name, driver)
        register(binary, ref, bad_digest, utc_after(86400))
        run_probe(test_binary, source, env, demote, "TestScopedDriverOutputRefused")
        revoke(binary, ref)

    lost_digest=build_driver(source,"syntheticdriver",driver,"task231_lostreply")
    register(binary,ref,lost_digest,utc_after(86400))
    run_probe(test_binary,source,env,demote,"TestScopedLostReplyReconcilesCommittedOperation")
    run_probe(test_binary,source,env,demote,"TestScopedInFlightCancellationPreservesCommittedEffect")
    revoke(binary,ref)
    golden=build_driver(source,"syntheticdriver",driver)
    register(binary, ref, golden, utc_after(86400))
    original = open(driver, "rb").read()
    try:
        def tamper():
            with open(driver, "r+b") as image:
                image.seek(-1, os.SEEK_END)
                byte = image.read(1)
                image.seek(-1, os.SEEK_END)
                image.write(bytes([byte[0] ^ 1]))
        live_probe(test_binary, source, env, demote, coord, "code", tamper)
    finally:
        with open(driver, "wb") as image:
            image.write(original)
    revoke(binary, ref)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Prompt-aware PTY bridge; never returns child terminal data or raw failures."""
import base64
import fcntl
import json
import os
import pty
import select
import signal
import sys
import termios
import time

PROMPTS = (
    "Exact HTTPS anchor endpoint: ", "Repeat exact endpoint from independent source: ",
    "Existing storeID (32 hex characters): ", "Repeat exact storeID from independent source: ",
    "Anchor signing public key raw 32-byte base64: ", "Repeat signing public key from independent source: ",
    "CA certificate DER base64 (one root only): ", "Client certificate chain DER base64 (leaf first, max 8): ",
    "CA SHA256 fingerprint from independent source: ", "Client leaf SHA256 fingerprint from independent source: ",
    "Client PKCS#8 private key DER base64: ", "New application-store master secret: ",
    "Confirm application-store master secret: ", "Application-store master secret: ", "Secret (max 16 KiB): ",
    "Exact canonical delivery reference: ", "Exact canonical confidential-delivery reference: ",
    "Type SETUP DECLARATIVE SYNTHETIC METADATA ONLY: ", "Repeat exact canonical reference: ",
    "Trusted absolute StorePath (human verified, never supplied by model tooling): ", "Repeat exact StorePath: ",
    "Verified store directory device number: ", "Repeat directory device number: ",
    "Verified store directory inode number: ", "Repeat directory inode number: ",
    "Independently verified encrypted InstallationSHA256: ",
    "Current snapshot EncodedHash from independently verified keeper CLI: ",
    "Independent driver SHA256: ", "Repeat driver SHA256: ", "Independent consumer SHA256: ",
    "Repeat consumer SHA256: ", "Type exact target identifier: ", "Expiry RFC3339 UTC (within 24 hours): ",
    "Keeper effective UID (non-root): ", "Repeat keeper UID: ",
    "Type REGISTER SYNTHETIC CONFIDENTIAL DELIVERY GRANT: ",
    "Exact canonical confidential-delivery reference to revoke: ",
    "Type REVOKE SYNTHETIC CONFIDENTIAL DELIVERY GRANT: ",
)
HIDDEN = ("master secret", "secret (", "private key", "new application-store master", "confirm application-store master")


def main():
    if len(sys.argv) < 2:
        return 64
    try:
        answers = json.load(sys.stdin.buffer)
        if not isinstance(answers, list):
            return 64
        if not sys.argv[1].startswith("/lab/"):
            return 64
        pending = []
        for answer in answers:
            if not isinstance(answer, dict) or set(answer) != {"prompt", "answer"} or answer["prompt"] not in PROMPTS:
                return 64
            decoded = base64.b64decode(answer["answer"], validate=True)
            pending.append((answer["prompt"].encode(), decoded + b"\n", answer["prompt"].lower()))
    except (ValueError, TypeError, KeyError):
        return 64

    master, slave = pty.openpty()
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(master); os.close(read_fd); os.setsid(); fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
            os.dup2(slave, 0); os.dup2(write_fd, 1); os.dup2(slave, 2)
            if slave > 2: os.close(slave)
            if write_fd > 2: os.close(write_fd)
            uid = int(os.environ["SSJACK_DELIVERY_UID"])
            if os.geteuid() == 0:
                os.setgid(uid); os.setuid(uid)
            os.execv(sys.argv[1], sys.argv[1:])
        except BaseException:
            os._exit(127)

    os.close(slave); os.close(write_fd)
    terminal = bytearray(); output = bytearray(); status = None
    deadline = time.monotonic() + 240
    try:
        while status is None:
            if time.monotonic() >= deadline:
                os.killpg(pid, signal.SIGKILL)
                break
            ready, _, _ = select.select([master, read_fd], [], [], 0.05)
            for fd in ready:
                try:
                    chunk = os.read(fd, 4096)
                except OSError:
                    chunk = b""
                if fd == read_fd:
                    if len(output) + len(chunk) > 65536:
                        os.killpg(pid, signal.SIGKILL)
                        break
                    output.extend(chunk)
                elif chunk:
                    terminal.extend(chunk)
                    while pending and pending[0][0] in terminal:
                        prompt, answer, label = pending[0]
                        attrs = termios.tcgetattr(master)
                        if any(secret in label for secret in HIDDEN) and attrs[3] & termios.ECHO:
                            echo_deadline = time.monotonic() + 2
                            while attrs[3] & termios.ECHO and time.monotonic() < echo_deadline:
                                select.select([], [], [], 0.01)
                                attrs = termios.tcgetattr(master)
                            if attrs[3] & termios.ECHO:
                                return 65
                        pending.pop(0)
                        pos = terminal.find(prompt) + len(prompt)
                        del terminal[:pos]
                        os.write(master, answer)
                        answer = b""
                    if len(terminal) > 65536:
                        del terminal[:-65536]
            done, wait_status = os.waitpid(pid, os.WNOHANG)
            if done:
                status = os.waitstatus_to_exitcode(wait_status)
                drain_deadline = time.monotonic() + 0.5
                while time.monotonic() < drain_deadline:
                    ready, _, _ = select.select([read_fd], [], [], 0.01)
                    if not ready:
                        break
                    chunk = os.read(read_fd, 4096)
                    if not chunk:
                        break
                    if len(output) + len(chunk) > 65536:
                        return 65
                    output.extend(chunk)
        if status is None:
            _, wait_status = os.waitpid(pid, 0)
            status = os.waitstatus_to_exitcode(wait_status)
            return 124

        text = bytes(terminal).decode("utf-8", "replace").replace("\r", "\n")
        refusal = ""
        allowed = ("no active delivery grant", "no unique active delivery grant", "application-store setup failed", "declarative authority unavailable or invalid")
        if status != 0:
            for line in (item.strip() for item in text.splitlines()):
                if line.startswith("ssjack: ") and line[8:] in allowed:
                    refusal = line[8:]
                    break
            if not refusal or len(answers) - len(pending) < 1:
                return 65
        elif pending:
            return 65
        result = {"exit_code": status, "prompts_answered": len(answers) - len(pending),
                  "refusal": refusal, "stdout": bytes(output).decode("utf-8", "replace")}
        sys.stdout.write(json.dumps(result, separators=(",", ":")))
        return 0
    finally:
        for buffer in (terminal, output):
            buffer[:] = b"\0" * len(buffer)
        os.close(master); os.close(read_fd)
        try:
            os.killpg(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            _, wait_status = os.waitpid(pid, 0)
            _ = wait_status
        except ChildProcessError:
            pass


if __name__ == "__main__":
    try:
        result = main()
    except Exception:
        os.write(2, b"delivery-pty: failed\n")
        result = 1
    raise SystemExit(result)

#!/usr/bin/env python3
"""CI-only prompt-bound PTY runner; terminal data is never returned."""
from __future__ import annotations

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


def main() -> int:
    if len(sys.argv) < 2:
        return 64
    try:
        answers = json.load(sys.stdin.buffer)
        if not isinstance(answers, list) or any(
            not isinstance(x, dict) or not isinstance(x.get("prompt"), str)
            or not isinstance(x.get("answer"), str) for x in answers
        ):
            return 64
        pending = [(x["prompt"].encode(), base64.b64decode(x["answer"], validate=True) + b"\n") for x in answers]
        if any(not p or not a for p, a in pending):
            return 64
    except (ValueError, TypeError, KeyError):
        return 64
    master, slave = pty.openpty()
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(master)
            os.close(read_fd)
            os.setsid()
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
            os.dup2(slave, 0)
            os.dup2(write_fd, 1)
            os.dup2(slave, 2)
            if slave > 2:
                os.close(slave)
            if write_fd > 2:
                os.close(write_fd)
            uid = int(os.environ.get("SSJACK_DELIVERY_UID", "65534"))
            if os.geteuid() == 0:
                os.setgid(uid)
                os.setuid(uid)
            os.execv(sys.argv[1], sys.argv[1:])
        except BaseException:
            os._exit(127)
    os.close(slave)
    os.close(write_fd)
    output = bytearray()
    terminal = bytearray()
    deadline = time.monotonic() + 120
    status = None
    timed_out = False
    try:
        while True:
            if time.monotonic() >= deadline:
                timed_out = True
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            ready, _, _ = select.select([master, read_fd], [], [], 0.05)
            for fd in ready:
                try:
                    chunk = os.read(fd, 4096)
                except OSError:
                    chunk = b""
                if fd == read_fd:
                    if len(output) + len(chunk) > 65536:
                        timed_out = True
                        try:
                            os.kill(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        break
                    output.extend(chunk)
                elif chunk:
                    terminal.extend(chunk)
                    while pending and pending[0][0] in terminal:
                        prompt, answer = pending.pop(0)
                        pos = terminal.find(prompt) + len(prompt)
                        del terminal[:pos]
                        os.write(master, answer)
                        answer = b""
                    if len(terminal) > 65536:
                        del terminal[:-65536]
            done, wait_status = os.waitpid(pid, os.WNOHANG)
            if done:
                status = os.waitstatus_to_exitcode(wait_status)
                break
        # Drain safe stdout after child exit.
        while True:
            ready, _, _ = select.select([read_fd], [], [], 0)
            if not ready:
                break
            chunk = os.read(read_fd, 4096)
            if not chunk:
                break
            if len(output) + len(chunk) > 65536:
                timed_out = True
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                break
            if len(output) + len(chunk) > 65536:
                timed_out = True
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                break
            output.extend(chunk)
        if timed_out:
            return 124
        refusal = ""
        text = bytes(terminal).decode("utf-8", "replace")
        allowed = ("no active delivery grant", "no unique active delivery grant",
                   "application-store setup failed", "invalid declarative slice request",
                   "declarative authority unavailable or invalid")
        lines = [line.strip() for line in text.replace("\r", "\n").splitlines()]
        if status is not None and status != 0:
            for line in lines:
                if line.startswith("ssjack: ") and line[8:] in allowed:
                    refusal = line[8:]
                    break
        if refusal:
            if status != 1 or len(answers) - len(pending) < 1:
                return 65
            result = {"exit_code": status,
                      "prompts_answered": len(answers) - len(pending),
                      "refusal": refusal,
                      "stdout": bytes(output[:65536]).decode("utf-8", "replace")}
            sys.stdout.buffer.write(json.dumps(result, separators=(",", ":")).encode())
            return 0
        if pending:
            return 65
        if status != 0:
            return status if status > 0 else 128 - status
        result = {"exit_code": 0, "prompts_answered": len(answers), "refusal": "",
                  "stdout": bytes(output[:65536]).decode("utf-8", "replace")}
        sys.stdout.buffer.write(json.dumps(result, separators=(",", ":")).encode())
        return 0
    finally:
        output[:] = b"\0" * len(output)
        terminal[:] = b"\0" * len(terminal)
        for _, answer in pending:
            answer = b""
        os.close(master)
        os.close(read_fd)
        if status is None:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)


if __name__ == "__main__":
    raise SystemExit(main())

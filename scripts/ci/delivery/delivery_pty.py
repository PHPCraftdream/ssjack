#!/usr/bin/env python3
"""CI-only prompt-bound PTY runner; raw terminal data is never returned.

Failure JSON contains exactly these keys (numbers are JSON integers):

- failure: string, the first failure class: input (64); spawn, io, reap,
  refusal, prompts, stdout-decode (65); timeout, stdout-overflow (124);
  or child-exit (positive child exit code, or 128 plus the signal number).
  Parent cancellation via KeyboardInterrupt uses the current phase class.
- cleanup: string, exactly ok if no child was spawned or reaping was confirmed,
  or reap-failed if a spawned child was not confirmed reaped after cleanup.
- child_pid: 0 before a successful parent fork, otherwise a positive OS PID.
- child_exit: -256 if unknown, 0..255 for a normal exit, or the negated OS
  signal number for a signal exit. A known exit is retained for every class.
- prompts_answered: 0 through the number of supplied prompts for valid input
  (0 for invalid input); counts only answers fully written.
- stdout_bytes: 0..69632, buffered stdout bytes, including an overflow chunk.
- terminal_bytes: 0..69632, retained PTY buffer bytes, not total PTY bytes read;
  a failure during prompt handling can occur before trimming to 65536 bytes.
- elapsed_ms: 0..600000, elapsed monotonic milliseconds, truncated and clamped.

Cleanup does not overwrite the first failure class or its process exit code.
An initial wait error can be the first failure (reap) even if cleanup later
confirms reaping and obtains the child exit. A wait error alone does not
confirm reaping. Failure JSON includes neither raw stream. Success and accepted
refusal use the existing result schema instead.
"""
from __future__ import annotations

import base64
import errno
import fcntl
import json
import os
import pty
import select
import signal
import sys
import termios
import time


LIMIT = 65536
CHUNK = 4096


def emit(result: dict) -> None:
    sys.stdout.buffer.write(json.dumps(result, separators=(",", ":")).encode())
    sys.stdout.buffer.flush()


class Failure(Exception):
    def __init__(self, label: str, code: int):
        self.label = label
        self.code = code


def main() -> int:
    started = time.monotonic()
    pid = answered = 0
    status = None
    output = bytearray()
    terminal = bytearray()
    master = slave = read_fd = write_fd = None
    reaped = False
    failure = None
    result = None
    phase = "input"

    def poll_child() -> bool:
        nonlocal reaped, status
        try:
            done, wait_status = os.waitpid(pid, os.WNOHANG)
            if done:
                reaped = True
                status = os.waitstatus_to_exitcode(wait_status)
        except Exception:
            raise Failure("reap", 65) from None
        return reaped

    def close(fd: int | None) -> None:
        if fd is not None:
            os.close(fd)

    def append_stdout(chunk: bytes) -> None:
        output.extend(chunk)
        if len(output) > LIMIT:
            raise Failure("stdout-overflow", 124)

    try:
        if len(sys.argv) < 2:
            raise Failure("input", 64)
        answers = json.load(sys.stdin.buffer)
        if not isinstance(answers, list) or any(
            not isinstance(x, dict) or not isinstance(x.get("prompt"), str)
            or not isinstance(x.get("answer"), str) for x in answers
        ):
            raise Failure("input", 64)
        pending = [(x["prompt"].encode(), base64.b64decode(x["answer"], validate=True) + b"\n") for x in answers]
        if any(not p or not a for p, a in pending):
            raise Failure("input", 64)
        phase = "spawn"
        master, slave = pty.openpty()
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            run_child(master, slave, read_fd, write_fd)
        phase = "io"
        deadline = time.monotonic() + 120
        fd, slave = slave, None
        close(fd)
        fd, write_fd = write_fd, None
        close(fd)
        os.set_blocking(master, False)
        readers = [master, read_fd]
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Failure("timeout", 124)
            ready, _, _ = select.select(readers, [], [], min(0.05, remaining))
            for fd in ready:
                try:
                    chunk = os.read(fd, CHUNK)
                except BlockingIOError:
                    continue
                except OSError as exc:
                    if fd != master or exc.errno != errno.EIO:
                        raise
                    chunk = b""
                if not chunk:
                    readers.remove(fd)
                elif fd == read_fd:
                    append_stdout(chunk)
                else:
                    terminal.extend(chunk)
                    while pending and pending[0][0] in terminal:
                        prompt, answer = pending.pop(0)
                        pos = terminal.find(prompt) + len(prompt)
                        del terminal[:pos]
                        sent = 0
                        while sent < len(answer):
                            remaining = deadline - time.monotonic()
                            if remaining <= 0:
                                raise Failure("timeout", 124)
                            try:
                                sent += os.write(master, memoryview(answer)[sent:])
                            except BlockingIOError:
                                select.select([], [master], [], remaining)
                        answered += 1
                        answer = b""
                    if len(terminal) > LIMIT:
                        del terminal[:-LIMIT]
            if poll_child():
                break

        if read_fd in readers:
            while select.select([read_fd], [], [], 0)[0]:
                chunk = os.read(read_fd, CHUNK)
                if not chunk:
                    break
                append_stdout(chunk)

        refusal = ""
        if status != 0:
            text = bytes(terminal).decode("utf-8", "replace")
            allowed = ("no active delivery grant", "no unique active delivery grant",
                       "application-store setup failed", "invalid declarative slice request",
                       "declarative authority unavailable or invalid")
            for line in text.replace("\r", "\n").splitlines():
                line = line.strip()
                if line.startswith("ssjack: ") and line[8:] in allowed:
                    refusal = line[8:]
                    break
        if refusal:
            if status != 1 or answered < 1:
                raise Failure("refusal", 65)
        elif pending:
            raise Failure("prompts", 65)
        elif status != 0:
            raise Failure("child-exit", status if status > 0 else 128 - status)
        try:
            stdout = output.decode("utf-8", "strict")
        except UnicodeDecodeError:
            raise Failure("stdout-decode", 65) from None
        result = {"exit_code": status, "prompts_answered": answered,
                  "refusal": refusal, "stdout": stdout, "child_pid": pid}
    except Failure as exc:
        failure = exc
    except (Exception, KeyboardInterrupt):
        failure = Failure(phase, 64 if phase == "input" else 65)
    finally:
        if pid and not reaped:
            try:
                if not poll_child():
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    cleanup_deadline = time.monotonic() + 2
                    while not poll_child():
                        remaining = cleanup_deadline - time.monotonic()
                        if remaining <= 0:
                            raise Failure("reap", 65)
                        time.sleep(min(0.01, remaining))
            except (Exception, KeyboardInterrupt):
                if failure is None:
                    failure = Failure("reap", 65)
        for fd in (master, slave, read_fd, write_fd):
            try:
                close(fd)
            except OSError:
                if failure is None:
                    failure = Failure("io", 65)
        stdout_bytes, terminal_bytes = len(output), len(terminal)
        output[:] = b"\0" * stdout_bytes
        terminal[:] = b"\0" * terminal_bytes

    if failure is not None:
        emit({"failure": failure.label,
              "cleanup": "reap-failed" if pid and not reaped else "ok",
              "child_pid": pid,
              "child_exit": -256 if status is None else status,
              "prompts_answered": answered, "stdout_bytes": stdout_bytes,
              "terminal_bytes": terminal_bytes,
              "elapsed_ms": min(600000, max(0, int((time.monotonic() - started) * 1000)))})
        return failure.code
    emit(result)
    return 0


def run_child(master: int, slave: int, read_fd: int, write_fd: int) -> None:
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
        text_fd = int(os.environ.get("SSJACK_DELIVERY_TEXT_FD", "-1"))
        if text_fd >= 0:
            os.set_inheritable(text_fd, True)
        os.execv(sys.argv[1], sys.argv[1:])
    except BaseException:
        os._exit(127)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Exception, KeyboardInterrupt):
        os._exit(65)

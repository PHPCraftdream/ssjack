"""Owned terminal output and process-exit coordination for CI drivers."""
import os
import re
from pathlib import Path
import signal
import subprocess
import threading
import time


class TerminalOutput:
    """Drain a control client even while the driver waits for pane exit."""
    def __init__(self, stream, limit=8 * 1024 * 1024):
        self.stream, self.limit = stream, limit
        self.data = bytearray()
        self.condition = threading.Condition()
        self.sequence, self.seen, self.offset = 0, 0, 0
        self.ended, self.overflow = False, False
        self.thread = threading.Thread(target=self.read)
        self.thread.start()

    def read(self):
        try:
            while True:
                chunk = os.read(self.stream.fileno(), 32768)
                if not chunk:
                    return
                with self.condition:
                    if len(self.data) + len(chunk) <= self.limit and not self.overflow:
                        self.data.extend(chunk)
                    else:
                        self.overflow = True
                    self.sequence += 1
                    self.condition.notify_all()
        finally:
            with self.condition:
                self.ended = True
                self.condition.notify_all()

    def next(self, seconds, phase):
        with self.condition:
            changed = self.condition.wait_for(lambda: self.sequence != self.seen or self.ended, seconds)
            if self.overflow:
                raise RuntimeError("synthetic terminal output exceeded its bound")
            if not changed:
                raise RuntimeError("synthetic terminal timed out at phase: " + phase)
            if self.ended and self.sequence == self.seen:
                raise RuntimeError("synthetic terminal ended at phase: " + phase)
            self.seen = self.sequence

    def take(self):
        with self.condition:
            chunk = bytes(self.data[self.offset:])
            self.offset = len(self.data)
            return chunk

    def finish(self):
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise RuntimeError("synthetic terminal output reader did not join")
        if self.overflow:
            raise RuntimeError("synthetic terminal output exceeded its bound")
        return bytes(self.data)

def exit_status_ready(value):
    status, separator, signal_name = value.strip().partition(b":")
    return separator == b":" and bool(status or signal_name)


def menu_index(content, label):
    rows = re.findall(rb"^(?:> |  )(.+)$", content, re.M)
    if label not in rows:
        raise RuntimeError("synthetic terminal menu item is not visible")
    return rows.index(label)


def process_identity(pid):
    if isinstance(pid, bytes):
        if not pid.isdigit():
            return None
        pid = int(pid)
    if not isinstance(pid, int) or pid <= 1:
        return None
    try:
        with Path("/proc", str(pid), "stat").open("rb") as stream:
            raw = stream.read(4097)
        if len(raw) > 4096:
            return None
        fields = raw.rsplit(b")", 1)[1].split()
        return fields[0], int(fields[1]), int(fields[19])
    except (OSError, IndexError, ValueError):
        return None


def server_identity(pid):
    state = process_identity(pid)
    if state is None or state[0] in (b"Z", b"X"):
        raise RuntimeError("owned terminal server identity unavailable")
    return pid, state[2]


def owns_zombie(owner, pane_pid):
    child, parent = process_identity(pane_pid), process_identity(owner[0])
    return (child is not None and parent is not None and child[0] == b"Z"
            and child[1] == owner[0] and parent[0] not in (b"Z", b"X")
            and parent[2] == owner[1])


def wake_owned_zombie(owner, pane_pid):
    if (not hasattr(signal, "SIGCHLD") or not hasattr(os, "pidfd_open")
            or not hasattr(signal, "pidfd_send_signal") or not owns_zombie(owner, pane_pid)):
        return False
    descriptor = None
    try:
        # Pin the parent before rechecking ownership; never signal a reused PID.
        descriptor = os.pidfd_open(owner[0])
        if not owns_zombie(owner, pane_pid):
            return False
        try:
            signal.pidfd_send_signal(descriptor, signal.SIGCHLD, None, 0)
        except OSError:
            raise RuntimeError("owned terminal reaping wakeup failed; no retry") from None
    except OSError:
        return False
    finally:
        if descriptor is not None:
            os.close(descriptor)
    print("Owned terminal zombie required a SIGCHLD wakeup.")
    return True


def reaper_signal_state(owner):
    state = process_identity(owner[0])
    if state is None or state[2] != owner[1] or not hasattr(signal, "SIGCHLD"):
        return None, None
    try:
        with Path("/proc", str(owner[0]), "status").open("rb") as stream:
            raw = stream.read(8193)
        if len(raw) > 8192:
            return None, None
        fields = dict(line.split(b":", 1) for line in raw.splitlines() if b":" in line)
        bit = 1 << (int(signal.SIGCHLD) - 1)
        return bool(int(fields[b"SigBlk"], 16) & bit), bool(int(fields[b"SigCgt"], 16) & bit)
    except (OSError, KeyError, ValueError):
        return None, None


def wait_for_exit(prefix, owner, seconds, environment):
    deadline = time.monotonic() + seconds

    def remaining():
        left = deadline - time.monotonic()
        if left <= 0:
            raise RuntimeError("synthetic terminal exit deadline expired")
        return left

    def command(*arguments, timeout=None):
        return subprocess.run(prefix + list(arguments), stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, env=environment, check=True,
                              timeout=min(remaining(), 5 if timeout is None else timeout)).stdout.strip()

    state = command("display-message", "-p", "-t", "owner", "#{pane_dead_status}:#{pane_dead_signal}")
    if exit_status_ready(state):
        return False
    pane = command("display-message", "-p", "-t", "owner", "#{pane_pid}")
    woke = wake_owned_zombie(owner, pane)
    try:
        left = remaining()
        command("wait-for", "finished", timeout=max(0.001, left - min(5, left / 2)))
    except subprocess.TimeoutExpired:
        state = command("display-message", "-p", "-t", "owner", "#{pane_dead_status}:#{pane_dead_signal}")
        if exit_status_ready(state):
            return woke
        if not woke:
            woke = wake_owned_zombie(owner, pane)
            if woke:
                print("Owned terminal exit wakeup followed a stalled completion barrier.")
        try:
            command("wait-for", "finished", timeout=remaining())
        except subprocess.TimeoutExpired:
            if woke:
                blocked, caught = reaper_signal_state(owner)
                raise RuntimeError("owned terminal zombie was not reaped after its wakeup: signal-blocked=%s signal-caught=%s" % (blocked, caught)) from None
            child, parent = process_identity(pane), process_identity(owner[0])
            raise RuntimeError("synthetic terminal exit stalled: child=%s parent=%s owner=%s epoch-matches=%s pidfd=%s" % (
                child[0].decode("ascii", "replace")[:1] if child else "-",
                child[1] if child else -1, owner[0],
                parent is not None and parent[2] == owner[1],
                hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"))) from None
    state = command("display-message", "-p", "-t", "owner", "#{pane_dead_status}:#{pane_dead_signal}")
    if not exit_status_ready(state):
        raise RuntimeError("terminal completion notification has no reaped status")
    return woke

"""Drive synthetic owner import: owner_import.py EXECUTABLE DATABASE ARCHIVE.
Stdin lines: database password, wrong and correct archive passwords, leak strings.
"""
import os
import signal
import subprocess
import sys
import time
import uuid
import threading


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

IMPORT_ITEM = b"> Import credentials and values"
PREVIEW_ROWS = [
    b"Archive: encrypted",
    b'Server "legacy"',
    b'Account "main" / login "first" / "key"',
    b'Account "second" / login "second" / "password"',
    b'Secret "initial" / scope: global',
    b'Secret "local2" / scope: server "legacy"',
]


def cancelled(_signal, _frame):
    raise RuntimeError("synthetic terminal parent cancelled")


def read_input():
    lines = []
    while len(lines) < 64:
        line = sys.stdin.buffer.readline(16386)
        if not line:
            break
        lines.append(line.rstrip(b"\n"))
    if len(lines) < 3 or not all(lines[:3]) or any(len(line) > 16384 for line in lines):
        raise RuntimeError("invalid synthetic fixture input")
    return lines[0], lines[1], lines[2], [line for line in lines[3:] if line]


def cursor_line(content):
    for line in content.splitlines():
        if line.startswith(b"> "):
            return line
    return None


def has_line(content, prefix):
    return any(line.startswith(prefix) for line in content.splitlines())


def exit_status_ready(value):
    status, separator, signal_name = value.strip().partition(b":")
    return separator == b":" and bool(status or signal_name)


def main():
    signal.signal(signal.SIGTERM, cancelled)
    executable, database, archive = sys.argv[1:]
    database_password, wrong_password, archive_password, leaks = read_input()
    secrets = [database_password, wrong_password, archive_password] + leaks
    socket = "ssjack-import-" + uuid.uuid4().hex
    prefix = ["tmux", "-L", socket, "-f", "/dev/null"]
    # Several production-KDF passes (unlock plus three archive reads) are slow.
    environment = dict(os.environ, TERM="xterm-256color", SSJACK_OWNER_TUI_CHILD="1",
                       SSJACK_OWNER_TUI_CHILD_SECONDS="580")
    deadline = time.monotonic() + 600
    control, output = None, None
    server_pid = None
    transcript = b""

    def remaining():
        seconds = deadline - time.monotonic()
        if seconds <= 0:
            raise RuntimeError("synthetic terminal interaction timed out")
        return seconds

    def tmux(*arguments, data=None):
        return subprocess.run(prefix + list(arguments), input=data, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, env=environment,
                              check=True, timeout=remaining()).stdout

    def screen():
        content = tmux("capture-pane", "-p", "-t", "owner")
        if any(secret in content for secret in secrets):
            raise RuntimeError("synthetic terminal exposed private input")
        return content

    def pump(phase):
        output.next(remaining(), phase)

    def close_control():
        if control is None:
            return b""
        control.stdin.close()
        control.terminate()
        try:
            control.wait(timeout=5)
        except subprocess.TimeoutExpired:
            control.kill()
            control.wait(timeout=5)
        captured = output.finish() if output is not None else b""
        control.stdout.close()
        return captured

    def wait_until(predicate, phase):
        while True:
            content = screen()
            if predicate(content):
                return content
            pump(phase)

    def expect(text):
        needle = text.encode()
        return wait_until(lambda content: needle in content, text)

    def paste(value):
        tmux("load-buffer", "-", data=value)
        tmux("paste-buffer", "-d", "-t", "owner")

    def keys(*values):
        tmux("send-keys", "-t", "owner", *values)

    def open_import():
        # Root lists connection points first, so the Import row depth varies.
        downs = 0
        while not has_line(screen(), IMPORT_ITEM):
            if downs >= 40:
                raise RuntimeError("Import credentials and values is not reachable")
            before = cursor_line(screen())
            keys("Down")
            downs += 1
            wait_until(lambda content: cursor_line(content) != before, "cursor movement")
        keys("Enter")
        expect("Archive file")
        expect("Archive password")

    def submit_import(password):
        # Form focus: 0 path, 1 password, 2 [Apply]; Tab moves forward.
        paste(archive.encode())
        keys("Tab")
        paste(password)
        expect("<hidden; entered>")
        keys("Tab")
        expect("> [Apply]")
        keys("Enter")

    def preview(password):
        open_import()
        submit_import(password)
        expect("Import preview")
        wait_until(lambda content: all(row in content for row in PREVIEW_ROWS), "preview rows")

    try:
        tmux("new-session", "-d", "-s", "owner", "-x", "160", "-y", "40",
             "sh", "-c", 'stty -echo; exec "$@"', "owner-cli", executable,
             "-test.run=^TestOwnerInteractivePTYChild$", "--", "--interactive", "--vault", database)
        owned_pid = int(tmux("display-message", "-p", "-t", "owner", "#{pid}").strip())
        if owned_pid <= 1:
            raise RuntimeError("invalid owned terminal server identity")
        server_pid = owned_pid
        tmux("set-option", "-w", "-t", "owner", "remain-on-exit", "on")
        tmux("set-hook", "-g", "pane-died", "wait-for -S finished")
        control = subprocess.Popen(prefix + ["-C", "attach-session", "-t", "owner"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, env=environment)
        output = TerminalOutput(control.stdout)
        expect("Vault secret:")
        paste(database_password + b"\n")
        expect("owner database")

        # 1. Wrong archive password: refused, nothing staged.
        open_import()
        submit_import(wrong_password)
        expect("wrong archive password")
        wait_until(lambda content: b"Archive file" not in content, "form closed")

        # 2. Correct password: preview, then Esc cancels and drops it.
        preview(archive_password)
        keys("Escape")
        wait_until(lambda content: b"Import preview" not in content and b"Import credentials and values" in content,
                   "preview cancelled")

        # 3. Correct password again: preview, explicit confirmation, import.
        preview(archive_password)
        expect("> [Confirm import")
        keys("Enter")
        expect("Confirmation")
        paste(b"IMPORT")
        keys("Tab")
        expect("> [Apply]")
        keys("Enter")
        expect("Import complete")

        # Up from the first root item wraps to Exit.
        keys("Up")
        expect("> Exit")
        keys("Enter")
        try:
            if not exit_status_ready(tmux("display-message", "-p", "-t", "owner", "#{pane_dead_status}:#{pane_dead_signal}")):
                subprocess.run(prefix + ["wait-for", "finished"], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, env=environment, check=True,
                               timeout=min(remaining(), 75))
        except subprocess.TimeoutExpired:
            # PTY EOF alone is not reaped status; a complete result survives a lost hook.
            if not exit_status_ready(tmux("display-message", "-p", "-t", "owner", "#{pane_dead_status}:#{pane_dead_signal}")):
                content = screen()
                raise RuntimeError("synthetic terminal exit stalled: working=%s exit-stopped=%s selected-exit=%s list-changed=%s root=%s ssh-failed=%s preview=%s" % (
                    b"Working; please wait" in content, b"Exit stopped:" in content,
                    has_line(content, b"> Exit"), b"The list changed;" in content,
                    b"Database / Global scope" in content, b"SSH connection failed" in content,
                    b"Import preview" in content)) from None
        status = tmux("display-message", "-p", "-t", "owner", "#{pane_dead_status}").strip()
        content = screen()
        if status != b"0" or b"PASS" not in content:
            raise RuntimeError("synthetic terminal child failed: exit-zero=%s status-empty=%s pass=%s go-failure=%s context-ended=%s terminal=%s save=%s unlock=%s" % (
                status == b"0", not status, b"PASS" in content, b"--- FAIL:" in content, b"context-ended=true" in content,
                b"reason=terminal" in content, b"reason=save" in content, b"reason=unlock" in content))
        transcript = close_control()
        if any(secret in transcript for secret in secrets):
            raise RuntimeError("synthetic terminal exposed private input")
        print("Synthetic owner import terminal interaction accepted.")
    finally:
        try:
            close_control()
        finally:
            if server_pid is not None:
                try:
                    result = subprocess.run(prefix + ["display-message", "-p", "-t", "owner", "#{pane_dead}:#{pane_pid}"],
                                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5)
                    dead, pane = result.stdout.strip().split(b":")
                    pane_pid = int(pane)
                    if dead == b"0" and pane_pid > 1:
                        os.kill(pane_pid, signal.SIGKILL)
                except (OSError, ValueError, subprocess.SubprocessError):
                    pass
                try:
                    os.kill(server_pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        sys.exit(str(error))

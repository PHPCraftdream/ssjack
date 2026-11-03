"""Drive a synthetic owner database using real terminal screen snapshots."""
import os
import select
import signal
import subprocess
import sys
import time
import uuid


def cancelled(_signal, _frame):
    raise RuntimeError("synthetic terminal parent cancelled")


def main():
    signal.signal(signal.SIGTERM, cancelled)
    executable, database = sys.argv[1:]
    password = sys.stdin.buffer.readline(16386).rstrip(b"\n")
    if not password or len(password) > 16384:
        raise RuntimeError("invalid synthetic fixture input")
    socket = "ssjack-owner-" + uuid.uuid4().hex
    prefix = ["tmux", "-L", socket, "-f", "/dev/null"]
    environment = dict(os.environ, TERM="xterm-256color", SSJACK_OWNER_TUI_CHILD="1")
    deadline = time.monotonic() + 90
    control = None
    server_pid = None
    transcript = bytearray()

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
        if password in content or b"synthetic-cancelled-private" in content:
            raise RuntimeError("synthetic terminal exposed private input")
        return content

    def expect(text):
        needle = text.encode()
        while needle not in screen():
            if not select.select([control.stdout], [], [], remaining())[0]:
                raise RuntimeError("synthetic terminal timed out at phase: " + text)
            chunk = os.read(control.stdout.fileno(), 32768)
            if not chunk:
                raise RuntimeError("synthetic terminal ended at phase: " + text)
            transcript.extend(chunk)
            if len(transcript) > 1024 * 1024:
                raise RuntimeError("synthetic terminal output exceeded its bound")

    def paste(value):
        tmux("load-buffer", "-", data=value)
        tmux("paste-buffer", "-d", "-t", "owner")

    def keys(*values):
        tmux("send-keys", "-t", "owner", *values)

    try:
        tmux("new-session", "-d", "-s", "owner", "-x", "120", "-y", "40",
             "sh", "-c", 'stty -echo; exec "$@"', "owner-cli", executable,
             "-test.run=^TestOwnerInteractivePTYChild$", "--", "--interactive", "--vault", database,
             "--server", "legacy", "--account", "second")
        owned_pid = int(tmux("display-message", "-p", "-t", "owner", "#{pid}").strip())
        if owned_pid <= 1:
            raise RuntimeError("invalid owned terminal server identity")
        server_pid = owned_pid
        tmux("set-option", "-w", "-t", "owner", "remain-on-exit", "on")
        tmux("set-hook", "-g", "pane-died", "wait-for -S finished")
        control = subprocess.Popen(prefix + ["-C", "attach-session", "-t", "owner"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=environment)
        expect("Vault secret:")
        paste(password + b"\n")
        expect("owner database")
        expect('Account "second"')
        keys("Escape")
        expect("[Rename server]")
        keys("Enter")
        expect("Server name:")
        paste(b"pty-renamed")
        keys("Tab", "Enter")
        expect("Change applied.")
        expect('Server "pty-renamed"')
        keys("Down", "Down", "Enter")
        expect("Account name:")
        paste(b"cancelled")
        keys("Tab")
        paste(b"cancelled-login")
        keys("Tab", "Tab")
        paste(b"synthetic-cancelled-private")
        expect("<hidden; entered>")
        keys("Escape")
        expect("[Add SSH account]")
        keys("Escape")
        expect("[Add server]")
        keys("Escape")
        expect("Global secrets")
        keys("Down", "Down", "Down", "Down", "Down", "Enter")
        tmux("wait-for", "finished")
        status = tmux("display-message", "-p", "-t", "owner", "#{pane_dead_status}").strip()
        if status != b"0" or b"PASS" not in screen():
            raise RuntimeError("synthetic terminal child failed")
        if password in transcript or b"synthetic-cancelled-private" in transcript:
            raise RuntimeError("synthetic terminal exposed private input")
        print("Synthetic owner terminal interaction accepted.")
    finally:
        if control is not None:
            control.terminate()
            try:
                control.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                control.kill()
                control.communicate()
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

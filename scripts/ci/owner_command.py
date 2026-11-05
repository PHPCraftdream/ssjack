"""Drive one parameterized owner command in an owned synthetic tmux terminal."""
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid

spec = importlib.util.spec_from_file_location("owner_import_driver", Path(__file__).with_name("owner_import.py"))
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)


def main():
    executable, database, server, mode = sys.argv[1:]
    lines = sys.stdin.buffer.read(32770).splitlines()
    if mode not in ("cancel", "apply") or len(lines) != 2 or not all(lines):
        raise RuntimeError("invalid synthetic owner-command input")
    password, credential = lines
    private = [password, credential]
    prefix = ["tmux", "-L", "ssjack-command-" + uuid.uuid4().hex, "-f", "/dev/null"]
    environment = dict(os.environ, TERM="xterm-256color", SSJACK_OWNER_COMMAND_CHILD="1",
                       SSJACK_OWNER_COMMAND_CANCEL="1" if mode == "cancel" else "0")
    deadline = time.monotonic() + 180
    control, output, server_pid = None, None, None

    def remaining():
        seconds = deadline - time.monotonic()
        if seconds <= 0:
            raise RuntimeError("synthetic owner command timed out")
        return seconds

    def tmux(*arguments, data=None):
        return subprocess.run(prefix + list(arguments), input=data, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, env=environment, check=True,
                              timeout=remaining()).stdout

    def screen():
        content = tmux("capture-pane", "-p", "-t", "owner")
        if any(value in content for value in private):
            raise RuntimeError("owner command exposed private input")
        return content

    def expect(text):
        while text not in screen():
            output.next(remaining(), "owner command")

    def paste(value):
        tmux("load-buffer", "-", data=value)
        tmux("paste-buffer", "-d", "-t", "owner")

    def close_control():
        nonlocal control
        if control is None:
            return b""
        owned, control = control, None
        owned.stdin.close()
        owned.terminate()
        try:
            owned.wait(timeout=5)
        except subprocess.TimeoutExpired:
            owned.kill()
            owned.wait(timeout=5)
        captured = output.finish()
        owned.stdout.close()
        return captured

    signal.signal(signal.SIGTERM, shared.cancelled)
    try:
        tmux("new-session", "-d", "-s", "owner", "-x", "160", "-y", "40",
             "sh", "-c", 'stty -echo; exec "$@"', "owner-command", executable,
             "-test.run=^TestOwnerCommandPTYChild$", "--", "--vault", database,
             "owner", "add-account", "--server", server, "--account", "cli-added",
             "--login", "cli-user", "--auth", "password", "--usage", "agent")
        server_pid = int(tmux("display-message", "-p", "-t", "owner", "#{pid}").strip())
        if server_pid <= 1:
            raise RuntimeError("invalid owned terminal identity")
        identity = shared.server_identity(server_pid)
        tmux("set-option", "-w", "-t", "owner", "remain-on-exit", "on")
        tmux("set-hook", "-g", "pane-died", "wait-for -S finished")
        control = subprocess.Popen(prefix + ["-C", "attach-session", "-t", "owner"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, env=environment)
        output = shared.TerminalOutput(control.stdout)
        expect(b"Vault secret:")
        paste(password + b"\n")
        expect(b"> Credential:")
        expect(b"parameter; read-only")
        paste(credential)
        expect(b"<hidden; entered>")
        if mode == "cancel":
            tmux("send-keys", "-t", "owner", "Escape")
        else:
            tmux("send-keys", "-t", "owner", "Tab")
            expect(b"> [Apply]")
            tmux("send-keys", "-t", "owner", "Enter")
        shared.wait_for_exit(prefix, identity, min(remaining(), 75), environment)
        content = screen()
        if tmux("display-message", "-p", "-t", "owner", "#{pane_dead_status}").strip() != b"0" or b"PASS" not in content:
            raise RuntimeError("synthetic owner-command child failed")
        if mode == "apply" and b"Owner command completed; encrypted persistence confirmed." not in content:
            raise RuntimeError("owner command did not report durable completion")
        transcript = close_control()
        if any(value in transcript for value in private):
            raise RuntimeError("owner command exposed private input")
        print("Synthetic parameterized owner command accepted: " + mode)
    finally:
        try:
            close_control()
        finally:
            if server_pid is not None and server_pid > 1:
                try:
                    reply = subprocess.run(prefix + ["display-message", "-p", "-t", "owner", "#{pane_dead}:#{pane_pid}"],
                                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5)
                    dead, pane = reply.stdout.strip().split(b":")
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

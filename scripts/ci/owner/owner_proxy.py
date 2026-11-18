"""Configure a synthetic per-server proxy through the real Bubble Tea terminal."""
import importlib.util
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import uuid


spec = importlib.util.spec_from_file_location("owner_import_driver", Path(__file__).with_name("owner_import.py"))
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)


def cancelled(_signal, _frame):
    raise RuntimeError("synthetic proxy terminal parent cancelled")


def main():
    signal.signal(signal.SIGTERM, cancelled)
    executable, database, address = sys.argv[1:]
    password = sys.stdin.buffer.readline(16386).rstrip(b"\n")
    proxy_password = sys.stdin.buffer.readline(1026).rstrip(b"\n")
    if not password or len(password) > 16384 or not proxy_password or len(proxy_password) > 1024:
        raise RuntimeError("invalid synthetic terminal input")
    prefix = ["tmux", "-L", "ssjack-proxy-" + uuid.uuid4().hex, "-f", "/dev/null"]
    environment = dict(os.environ, TERM="xterm-256color", SSJACK_OWNER_TUI_CHILD="1")
    deadline = time.monotonic() + 120
    control, output, pid = None, None, None
    pending, transcript = bytearray(), bytearray()

    def remaining():
        seconds = deadline - time.monotonic()
        if seconds <= 0:
            raise RuntimeError("synthetic proxy terminal timed out")
        return seconds

    def tmux(*args, data=None):
        return subprocess.run(prefix + list(args), input=data, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, env=environment, check=True,
                              timeout=remaining()).stdout

    def private(content):
        if password in content or proxy_password in content or b"PRIVATE KEY" in content:
            raise RuntimeError("synthetic proxy terminal exposed private input")

    def screen():
        content = tmux("capture-pane", "-p", "-t", "owner")
        private(content)
        return content

    def pump():
        output.next(remaining(), "proxy terminal output")
        consume(output.take())

    def consume(chunk):
        for offset in range(0, len(chunk), 32768):
            parse(chunk[offset:offset + 32768])

    def parse(chunk):
        pending.extend(chunk)
        if len(pending) > 1 << 20 or len(transcript) > 2 << 20:
            raise RuntimeError("synthetic proxy terminal output exceeded its bound")
        while b"\n" in pending:
            line, _, rest = pending.partition(b"\n")
            pending[:] = rest
            line = line.rstrip(b"\r")
            if line.startswith(b"%output "):
                fields = line.split(b" ", 2)
                if len(fields) == 3:
                    transcript.extend(re.sub(rb"\\([0-7]{3})", lambda m: bytes([int(m.group(1), 8)]), fields[2]))
        private(transcript)

    def close_control():
        if control is None:
            return
        if not control.stdin.closed:
            control.stdin.close()
        control.terminate()
        try:
            control.wait(timeout=5)
        except subprocess.TimeoutExpired:
            control.kill()
            control.wait(timeout=5)
        if output is not None:
            output.finish()
            consume(output.take())
        control.stdout.close()

    def expect(text):
        while text not in screen():
            pump()

    def keys(*values):
        tmux("send-keys", "-t", "owner", *values)

    def paste(value):
        tmux("load-buffer", "-", data=value)
        tmux("paste-buffer", "-d", "-t", "owner")

    try:
        tmux("new-session", "-d", "-s", "owner", "-x", "160", "-y", "40", "sh", "-c",
             'stty -echo; tmux wait-for ready; exec "$@"', "owner-cli", executable,
             "-test.run=^TestOwnerInteractivePTYChild$", "--", "--interactive", "--vault", database,
             "--server", "pty-renamed")
        pid = int(tmux("display-message", "-p", "-t", "owner", "#{pid}").strip())
        if pid <= 1:
            raise RuntimeError("invalid owned terminal identity")
        identity = shared.server_identity(pid)
        tmux("set-option", "-w", "-t", "owner", "remain-on-exit", "on")
        tmux("set-hook", "-g", "pane-died", "wait-for -S finished")
        control = subprocess.Popen(prefix + ["-C", "attach-session", "-t", "owner"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, env=environment)
        output = shared.TerminalOutput(control.stdout, limit=2 * 1024 * 1024)
        pump()
        tmux("wait-for", "-S", "ready")
        expect(b"Vault secret:")
        paste(password + b"\n")
        expect(b"[Rename server]")
        for _ in range(32):
            if b"> [Edit SSH proxy]" in screen():
                break
            before = screen()
            keys("Down")
            while screen() == before:
                pump()
        else:
            raise RuntimeError("server proxy action is not reachable")
        keys("Enter")
        expect(b"Proxy type:")
        expect(b"not encrypted")
        keys(*(["BSpace"] * len("direct")))
        expect(b'Proxy type: ""')
        paste(b"socks5")
        keys("Tab")
        paste(address.encode())
        keys("Tab")
        paste(b"proxy-operator")
        keys("Tab")
        paste(proxy_password)
        expect(b"<hidden; entered>")
        keys("Tab", "Enter")
        expect(b"Change applied.")
        keys("Escape")
        expect(b"[Add server]")
        keys("Escape")
        expect(b"Global secrets")
        keys("Up")
        expect(b"> Exit")
        keys("Enter")
        shared.wait_for_exit(prefix, identity, remaining(), environment)
        status = tmux("display-message", "-p", "-t", "owner", "#{pane_dead_status}").strip()
        if status != b"0" or b"PASS" not in screen():
            raise RuntimeError("synthetic proxy terminal child failed")
        close_control()
        private(transcript)
        print("Synthetic server proxy terminal configuration accepted.")
    finally:
        try:
            close_control()
        finally:
            if pid is not None:
                try:
                    result = subprocess.run(prefix + ["display-message", "-p", "-t", "owner", "#{pane_dead}:#{pane_pid}"],
                                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5)
                    dead, pane = result.stdout.strip().split(b":")
                    if dead == b"0" and int(pane) > 1:
                        os.kill(int(pane), signal.SIGKILL)
                except (OSError, ValueError, subprocess.SubprocessError):
                    pass
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        sys.exit(str(error))

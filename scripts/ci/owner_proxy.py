"""Configure a synthetic per-server proxy through the real Bubble Tea terminal."""
import os
import re
import select
import signal
import subprocess
import sys
import time
import uuid


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
    control, pid = None, None
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
        if not select.select([control.stdout], [], [], remaining())[0]:
            raise RuntimeError("synthetic proxy terminal output timed out")
        chunk = os.read(control.stdout.fileno(), 32768)
        if not chunk:
            raise RuntimeError("synthetic proxy terminal ended early")
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
        tmux("set-option", "-w", "-t", "owner", "remain-on-exit", "on")
        tmux("set-hook", "-g", "pane-died", "wait-for -S finished")
        control = subprocess.Popen(prefix + ["-C", "attach-session", "-t", "owner"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=environment)
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
        tmux("wait-for", "finished")
        status = tmux("display-message", "-p", "-t", "owner", "#{pane_dead_status}").strip()
        if status != b"0" or b"PASS" not in screen():
            raise RuntimeError("synthetic proxy terminal child failed")
        private(transcript)
        print("Synthetic server proxy terminal configuration accepted.")
    finally:
        if control is not None:
            control.terminate()
            try:
                control.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                control.kill()
                control.communicate()
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

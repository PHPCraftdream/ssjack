"""Drive the owner connection picker through a real terminal against a loopback SSH server.

Usage: owner_connect.py single|multi EXECUTABLE DATABASE MARKER; stdin carries
the database secret on line one and the synthetic SSH password on line two
(leak checks only). Root order (servers, then accounts, sorted by name):
  multi:  0 main/first (key)  1 second (password)  2 wrong-pin/intruder  3 Servers
          4 Global secrets  5 Export  6 Import  7 Link  8 Pending  9 Exit
  single: 0 main/first  1 Servers  2 Global secrets  3 Export  4 Import  5 Link
          6 Pending  7 Exit (the Go side made every other account agent-only)
The agent-only account "agentonly" is never listed. No sleeps: screen polling
plus barrier(), which orders a control-mode response after earlier output.
"""
import os
import re
import select
import signal
import subprocess
import sys
import time
import uuid

OCTAL = re.compile(rb"\\([0-7]{3})")


def cancelled(_signal, _frame):
    raise RuntimeError("synthetic terminal parent cancelled")


def connect_line(server, login, account, authentication):
    pattern = '^> Connect: "%s" / "127\\.0\\.0\\.1:\\d+" / login "%s" / account "%s" / "%s"' % (
        server, login, account, authentication)
    return pattern.encode()


def process_gone(pid):
    try:
        os.kill(pid, 0)
        with open("/proc/%d/stat" % pid, "rb") as handle:
            return handle.read().rsplit(b")", 1)[1].split()[0] == b"Z"  # unreaped zombie
    except (OSError, IndexError):
        return True


def stop_server(prefix, pid):
    # Cleanup only: bounded short-sleep polls verify the tmux server exited and
    # its socket answers no more; they are never a test barrier.
    for sig, seconds in ((signal.SIGTERM, 5), (signal.SIGKILL, 3)):
        if not process_gone(pid):
            os.kill(pid, sig)
        end = time.monotonic() + seconds
        while not process_gone(pid) and time.monotonic() < end:
            time.sleep(0.05)
    if not process_gone(pid):
        return "the terminal server did not exit"
    listing = subprocess.run(prefix + ["list-sessions"], stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, timeout=5)
    return "the terminal server is still reachable" if listing.returncode == 0 else None


def main():
    signal.signal(signal.SIGTERM, cancelled)
    mode, executable, database, marker = sys.argv[1:]
    if mode not in ("single", "multi"):
        raise RuntimeError("unknown driver mode")
    exit_index = 9 if mode == "multi" else 7
    password = sys.stdin.buffer.readline(16386).rstrip(b"\n")
    ssh_password = sys.stdin.buffer.readline(4098).rstrip(b"\n")
    if not password or len(password) > 16384 or not ssh_password or not re.fullmatch(r"[0-9a-z]{1,64}", marker):
        raise RuntimeError("invalid synthetic fixture input")
    socket = "ssjack-connect-" + uuid.uuid4().hex
    prefix = ["tmux", "-L", socket, "-f", "/dev/null"]
    environment = dict(os.environ, TERM="xterm-256color", SSJACK_OWNER_TUI_CHILD="1")
    deadline = time.monotonic() + 150
    control = None
    server_pid = None
    # Control-mode input is split into lines; "%output %pane data" lines are
    # decoded into one byte stream (the session has a single pane), so chunk and
    # record framing cannot split a prompt or a secret. tmux escapes bytes <32
    # and backslash as \ooo in data; decoding is exact for that rule only.
    inbuf = bytearray()
    stream = bytearray()
    block = []
    state = {"open": False}
    done = set()
    position = 0

    def remaining():
        seconds = deadline - time.monotonic()
        if seconds <= 0:
            raise RuntimeError("synthetic terminal interaction timed out")
        return seconds

    def tmux(*arguments, data=None):
        return subprocess.run(prefix + list(arguments), input=data, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, env=environment,
                              check=True, timeout=remaining()).stdout

    def check_private(content):
        if password in content or ssh_password in content or b"PRIVATE KEY" in content:
            raise RuntimeError("synthetic terminal exposed private input")

    def screen():
        content = tmux("capture-pane", "-p", "-t", "owner")
        check_private(content)
        return content

    def parse():
        while True:
            end = inbuf.find(b"\n")
            if end < 0:
                return
            line = bytes(inbuf[:end]).rstrip(b"\r")
            del inbuf[:end + 1]
            if line.startswith(b"%output "):
                fields = line.split(b" ", 2)
                if len(fields) == 3:
                    stream.extend(OCTAL.sub(lambda m: bytes([int(m.group(1), 8) & 255]), fields[2]))
            elif line.startswith(b"%begin "):
                block.clear()
                state["open"] = True
            elif line.startswith((b"%end ", b"%error ")):
                if line.startswith(b"%end "):
                    done.update(block)  # tokens of completed command blocks
                state["open"] = False
            elif state["open"]:
                block.append(line)

    def read_control(seconds):
        if not select.select([control.stdout], [], [], seconds)[0]:
            return False
        chunk = os.read(control.stdout.fileno(), 32768)
        if not chunk:
            raise RuntimeError("synthetic terminal ended unexpectedly")
        inbuf.extend(chunk)
        parse()
        if len(stream) > 4 * 1024 * 1024 or len(inbuf) > 1024 * 1024:
            raise RuntimeError("synthetic terminal output exceeded its bound")
        return True

    def barrier():
        # tmux answers control commands in order: once this command's complete
        # %begin/%end block arrives, every %output record tmux had already
        # queued before executing it is in the decoded stream. It does not prove
        # the child consumed input; that is what the Down/Up probes are for.
        token = ("barrier-" + uuid.uuid4().hex).encode()
        control.stdin.write(b"display-message -p " + token + b"\n")
        control.stdin.flush()
        end = time.monotonic() + 30
        while token not in done:
            left = min(remaining(), end - time.monotonic())
            if left <= 0 or not read_control(left):
                raise RuntimeError("synthetic terminal barrier timed out")
        done.discard(token)

    def expect(pattern, wait=30):
        if isinstance(pattern, str):
            pattern = re.escape(pattern.encode())
        compiled = re.compile(pattern, re.M)
        end = time.monotonic() + wait
        while not compiled.search(screen()):
            left = min(remaining(), end - time.monotonic())
            if left <= 0 or not read_control(left):
                raise RuntimeError("synthetic terminal timed out at phase: " + pattern.decode(errors="replace"))

    def probe_input(down_line, up_line):
        # Input barrier: the cursor only moves if the program is alive, has
        # rendered the list and handles keys; no sleep is needed.
        keys("Down")
        expect(down_line, wait=10)
        keys("Up")
        expect(up_line, wait=10)

    def paste(value):
        tmux("load-buffer", "-", data=value)
        tmux("paste-buffer", "-d", "-t", "owner")

    def keys(*values):
        tmux("send-keys", "-t", "owner", *values)

    def move_to(index, line):
        nonlocal position
        delta = index - position
        if delta:
            keys(*(["Down"] * delta if delta > 0 else ["Up"] * -delta))
        position = index
        expect(line, wait=10)

    def session(index, line, login):
        move_to(index, line)
        keys("Enter")
        expect("SYNTHETIC-SSH-READY user=%s marker=%s" % (login, marker))
        # The raw client terminal does not echo locally; only the server answers.
        tmux("send-keys", "-t", "owner", "-l", "hello")
        keys("Enter")
        expect("ECHO:hello")
        tmux("send-keys", "-t", "owner", "-l", "exit")
        keys("Enter")
        # Strict: returning to the picker must not need an extra keystroke.
        expect("SSH session ended (exit code 0).", wait=20)
        expect(line, wait=10)

    try:
        tmux("new-session", "-d", "-s", "owner", "-x", "120", "-y", "40",
             "sh", "-c", 'stty -echo; tmux wait-for ready; exec "$@"', "owner-cli", executable,
             "-test.run=^TestOwnerInteractivePTYChild$", "--", "--interactive", "--vault", database)
        server_pid = int(tmux("display-message", "-p", "-t", "owner", "#{pid}").strip())
        if server_pid <= 1:
            raise RuntimeError("invalid owned terminal server identity")
        tmux("set-option", "-w", "-t", "owner", "remain-on-exit", "on")
        tmux("set-hook", "-g", "pane-died", "wait-for -S finished")
        control = subprocess.Popen(prefix + ["-C", "attach-session", "-t", "owner"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=environment)
        # Attach must be live before the child prints its prompt, so the
        # stream sees every "Vault secret:" prompt of the whole run.
        if not read_control(remaining()):
            raise RuntimeError("synthetic terminal control client did not attach")
        tmux("wait-for", "-S", "ready")
        expect("Vault secret:")
        # Screen-side proof, independent of the decoder: one prompt was visible.
        if screen().count(b"Vault secret:") != 1:
            raise RuntimeError("the vault prompt was not shown exactly once")
        paste(password + b"\n")

        first = connect_line("pty-renamed", "first", "main", "key")
        second = connect_line("pty-renamed", "second", "second", "password")
        intruder = connect_line("wrong-pin", "intruder", "intruder", "key")
        listed = (first, second, intruder) if mode == "multi" else (first,)
        for line in listed:
            expect(line.replace(b"^> ", b"^(> |  )"), wait=60)
        # Everything tmux queued for the listing is processed: no late render.
        barrier()
        shown = screen()
        if b"agentonly" in shown:
            raise RuntimeError("picker listed an agent-only account")
        if len(re.findall(rb"^(?:> |  )Connect:", shown, re.M)) != len(listed):
            raise RuntimeError("picker listed an unexpected number of connection points")
        if mode == "single" and (b'login "second"' in shown or b'login "intruder"' in shown):
            raise RuntimeError("the singleton picker listed another account")
        if b"SYNTHETIC-SSH-READY" in shown or b"SYNTHETIC-SSH-READY" in stream:
            raise RuntimeError("picker connected without an explicit Enter")
        expect(first, wait=10)
        probe_input(second if mode == "multi" else rb"^> Servers", first)
        barrier()
        if b"SYNTHETIC-SSH-READY" in stream or b"SYNTHETIC-SSH-READY" in screen():
            raise RuntimeError("moving the cursor connected without an explicit Enter")
        if mode == "multi":
            session(0, first, "first")
            session(1, second, "second")
            move_to(2, intruder)
            keys("Enter")
            expect("SSH connection failed or ended with an error")
            if b"user=intruder" in screen():
                raise RuntimeError("a wrong host pin still reached the SSH shell")

        move_to(exit_index, rb"^> Exit")
        keys("Enter")
        tmux("wait-for", "finished")
        status = tmux("display-message", "-p", "-t", "owner", "#{pane_dead_status}").strip()
        if status != b"0" or b"PASS" not in screen():
            raise RuntimeError("synthetic terminal child failed")
        barrier()
        check_private(bytes(stream))
        if stream.count(b"Vault secret:") != 1:
            raise RuntimeError("the vault secret was requested more than once")
        forbidden = [b"agentonly"] + ([b"user=intruder"] if mode == "multi" else [b"SYNTHETIC-SSH-READY"])
        if any(item in stream for item in forbidden):
            raise RuntimeError("synthetic terminal showed a forbidden connection")
        if mode == "multi" and not all(b"SYNTHETIC-SSH-READY user=" + l in stream for l in (b"first", b"second")):
            raise RuntimeError("synthetic terminal transcript lacks a connection")
        print("Synthetic owner connection interaction accepted (%s)." % mode)
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
            problem = stop_server(prefix, server_pid)
            if problem and sys.exc_info()[0] is None:
                raise RuntimeError(problem)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        sys.exit(str(error))

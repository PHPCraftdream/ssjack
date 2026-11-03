"""Drive only a synthetic owner database through the actual terminal CLI."""
import errno
import fcntl
import os
import pty
import select
import signal
import struct
import sys
import termios
import time


def cancelled(_signal, _frame):
    raise RuntimeError("synthetic terminal parent cancelled")


def main():
    signal.signal(signal.SIGTERM, cancelled)
    executable, database = sys.argv[1:]
    password = sys.stdin.buffer.readline(16386).rstrip(b"\n")
    if not password or len(password) > 16384:
        raise RuntimeError("invalid synthetic fixture input")
    pid, terminal = pty.fork()
    if pid == 0:
        fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
        attributes = termios.tcgetattr(0)
        attributes[3] &= ~termios.ECHO
        termios.tcsetattr(0, termios.TCSANOW, attributes)
        env = dict(os.environ, TERM="xterm-256color", SSJACK_OWNER_TUI_CHILD="1")
        os.execve(executable, [executable, "-test.run=^TestOwnerInteractivePTYChild$",
                              "--", "--interactive", "--vault", database], env)
    deadline = time.monotonic() + 90
    pending, transcript = bytearray(), bytearray()
    reaped = False

    def receive():
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([terminal], [], [], remaining)[0]:
            raise RuntimeError("synthetic terminal interaction timed out")
        try:
            chunk = os.read(terminal, 32768)
        except OSError as error:
            if error.errno != errno.EIO:
                raise
            chunk = b""
        pending.extend(chunk)
        transcript.extend(chunk)
        if len(transcript) > 1024 * 1024:
            raise RuntimeError("synthetic terminal output exceeded its bound")
        return bool(chunk)

    def expect(text):
        needle = text.encode()
        while needle not in pending:
            try:
                available = receive()
            except RuntimeError as error:
                raise RuntimeError("synthetic terminal phase " + text + ": " + str(error)) from None
            if not available:
                raise RuntimeError("synthetic terminal ended at phase: " + text)
        del pending[:pending.index(needle) + len(needle)]

    def send(data):
        view = memoryview(data)
        while view:
            written = os.write(terminal, view)
            if written <= 0:
                raise RuntimeError("synthetic terminal input stalled")
            view = view[written:]

    try:
        expect("Vault secret:")
        send(password + b"\n")
        expect("owner database")
        send(b"\r")
        expect("[Add server]")
        send(b"\x1b[B\r")
        expect("[Rename server]")
        send(b"\r")
        expect("Server name:")
        send(b"pty-renamed\t\r")
        expect("Change applied.")
        expect('Server "pty-renamed"')
        send(b"\x1b[B\x1b[B\r")
        expect("Account name:")
        send(b"cancelled\tcancelled-login\t\tsynthetic-cancelled-private")
        expect("<hidden; entered>")
        send(b"\x1b")
        expect("[Add SSH account]")
        send(b"\x1b")
        expect("[Add server]")
        send(b"\x1b")
        expect("Global secrets")
        send(b"\x1b[B" * 4 + b"\r")
        while receive():
            pass
        _, status = os.waitpid(pid, 0)
        reaped = True
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            raise RuntimeError("synthetic terminal child failed")
        if password in transcript or b"synthetic-cancelled-private" in transcript:
            raise RuntimeError("synthetic terminal exposed private input")
        print("Synthetic owner terminal interaction accepted.")
    finally:
        os.close(terminal)
        if not reaped:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError) as error:
        sys.exit(str(error))

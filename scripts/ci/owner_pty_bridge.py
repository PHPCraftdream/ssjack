#!/usr/bin/env python3
"""Bridge a real Unix PTY for the native owner process acceptance fixture."""
import errno
import fcntl
import os
import pty
import signal
import struct
import subprocess
import sys
import termios
import threading


def main():
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 60, 200, 0, 0))

    def terminal_session():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    child, stopping, terminating = None, False, False

    def terminate_child():
        nonlocal terminating
        if child is None or terminating:
            return
        terminating = True
        child.terminate()
        force = threading.Timer(3, child.kill)
        force.daemon = True
        force.start()

    def stop(_signum, _frame):
        nonlocal stopping
        stopping = True
        terminate_child()

    signal.signal(signal.SIGTERM, stop)
    child = subprocess.Popen(sys.argv[1:], stdin=slave, stdout=slave, stderr=slave,
                             close_fds=True, preexec_fn=terminal_session)
    os.close(slave)
    if stopping:
        terminate_child()

    def input_copy():
        while True:
            data = os.read(0, 4096)
            if not data:
                return
            offset = 0
            while offset < len(data):
                offset += os.write(master, data[offset:])

    threading.Thread(target=input_copy, daemon=True).start()
    try:
        while True:
            try:
                data = os.read(master, 4096)
            except OSError as error:
                if error.errno == errno.EIO:
                    break
                raise
            if not data:
                break
            offset = 0
            while offset < len(data):
                offset += os.write(1, data[offset:])
        return child.wait()
    finally:
        os.close(master)
        if child.poll() is None:
            child.kill()
            child.wait()


if __name__ == "__main__":
    raise SystemExit(main())

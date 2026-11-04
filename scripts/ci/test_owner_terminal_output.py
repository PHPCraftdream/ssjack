"""Regression: a driver waiting for exit must not block its control producer."""
import importlib.util
import os
from pathlib import Path
import threading
import unittest


PATH = Path(__file__).with_name("owner_import.py")
SPEC = importlib.util.spec_from_file_location("owner_import_terminal", PATH)
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)


class TerminalOutputTests(unittest.TestCase):
    def capture_while_waiting_for_exit(self, payload, limit):
        read_fd, write_fd = os.pipe()
        finished = threading.Event()
        failures = []

        def producer():
            try:
                remaining = memoryview(payload)
                while remaining:
                    size = os.write(write_fd, remaining)
                    remaining = remaining[size:]
            except OSError as error:
                failures.append(error)
            finally:
                os.close(write_fd)
                finished.set()

        with os.fdopen(read_fd, "rb", buffering=0) as stream:
            output = DRIVER.TerminalOutput(stream, limit=limit)
            writer = threading.Thread(target=producer)
            writer.start()
            try:
                # No output.next()/pump call: this models wait-for finished.
                self.assertTrue(finished.wait(timeout=5), "control output blocked process completion")
                writer.join(timeout=5)
                self.assertFalse(writer.is_alive())
                self.assertFalse(failures)
                return output.finish()
            finally:
                stream.close()
                writer.join(timeout=5)
                output.thread.join(timeout=5)
                self.assertFalse(writer.is_alive())
                self.assertFalse(output.thread.is_alive())

    def test_exit_wait_drains_more_than_pipe_capacity(self):
        payload = b"synthetic-terminal-frame\n" * 65536
        self.assertTrue(self.capture_while_waiting_for_exit(payload, 2 << 20) == payload,
                        "bounded terminal capture changed the produced bytes")

    def test_overflow_still_drains_and_joins_without_retaining_more_bytes(self):
        with self.assertRaisesRegex(RuntimeError, "output exceeded its bound"):
            self.capture_while_waiting_for_exit(b"x" * 65536, 128)


if __name__ == "__main__":
    unittest.main()

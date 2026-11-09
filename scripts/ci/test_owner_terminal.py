import contextlib
import io
import os
import select
import signal
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import owner_terminal as terminal


class ProcessIdentityTests(unittest.TestCase):
    def test_kernel_record_exposes_only_state_parent_and_start_time(self):
        fields = [b"Z", b"7"] + [b"0"] * 17 + [b"123"]
        raw = b"321 (synthetic ) command) " + b" ".join(fields) + b"\n"
        with patch.object(terminal.Path, "open", return_value=io.BytesIO(raw)):
            self.assertEqual(terminal.process_identity(321), (b"Z", 7, 123))

    def test_invalid_pid_cannot_select_an_arbitrary_file(self):
        with patch.object(terminal.Path, "open") as opened:
            for pid in (0, 1, -1, b"../secret", b"", "321"):
                self.assertIsNone(terminal.process_identity(pid))
            opened.assert_not_called()

    def test_unavailable_or_oversized_record_refuses(self):
        for raw in (b"", b"malformed", b"x" * 4097):
            with patch.object(terminal.Path, "open", return_value=io.BytesIO(raw)):
                self.assertIsNone(terminal.process_identity(321))


class ReaperSignalStateTests(unittest.TestCase):
    def test_only_signal_mask_bits_are_returned(self):
        raw = b"Name:\tsynthetic\nSigBlk:\t0000000000010000\nSigCgt:\t0000000000000000\n"
        with patch.object(terminal, "process_identity", return_value=(b"S", 1, 100)):
            with patch.object(terminal.signal, "SIGCHLD", 17, create=True):
                with patch.object(terminal.Path, "open", return_value=io.BytesIO(raw)):
                    self.assertEqual(terminal.reaper_signal_state((7, 100)), (True, False))

    def test_reused_owner_does_not_read_the_new_process(self):
        with patch.object(terminal, "process_identity", return_value=(b"S", 1, 101)):
            with patch.object(terminal.Path, "open") as opened:
                self.assertEqual(terminal.reaper_signal_state((7, 100)), (None, None))
                opened.assert_not_called()


class OwnedZombieWakeTests(unittest.TestCase):
    def system(self, states):
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(terminal, "process_identity", side_effect=states))
        opened = stack.enter_context(patch.object(terminal.os, "pidfd_open", return_value=99, create=True))
        sent = stack.enter_context(patch.object(terminal.signal, "pidfd_send_signal", create=True))
        closed = stack.enter_context(patch.object(terminal.os, "close"))
        stack.enter_context(patch.object(terminal.signal, "SIGCHLD", 17, create=True))
        stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        return opened, sent, closed

    def test_only_owned_zombie_is_woken_through_a_pinned_process_handle(self):
        child, parent = (b"Z", 7, 50), (b"S", 1, 100)
        opened, sent, closed = self.system([child, parent, child, parent])
        self.assertTrue(terminal.wake_owned_zombie((7, 100), b"321"))
        opened.assert_called_once_with(7)
        sent.assert_called_once_with(99, 17, None, 0)
        closed.assert_called_once_with(99)

    def test_live_foreign_reused_or_missing_processes_are_never_signalled(self):
        cases = [
            [(b"S", 7, 50), (b"S", 1, 100)],
            [(b"Z", 8, 50), (b"S", 1, 100)],
            [(b"Z", 7, 50), (b"S", 1, 101)],
            [(b"Z", 7, 50), (b"Z", 1, 100)],
            [None, (b"S", 1, 100)],
        ]
        for states in cases:
            with self.subTest(states=states):
                opened, sent, closed = self.system(states)
                self.assertFalse(terminal.wake_owned_zombie((7, 100), b"321"))
                opened.assert_not_called()
                sent.assert_not_called()
                closed.assert_not_called()

    def test_ownership_is_rechecked_after_opening_the_handle(self):
        child, parent = (b"Z", 7, 50), (b"S", 1, 100)
        opened, sent, closed = self.system([child, parent, (b"Z", 1, 50), parent])
        self.assertFalse(terminal.wake_owned_zombie((7, 100), b"321"))
        opened.assert_called_once_with(7)
        sent.assert_not_called()
        closed.assert_called_once_with(99)

    def test_reused_parent_epoch_after_open_never_receives_a_signal(self):
        child, parent = (b"Z", 7, 50), (b"S", 1, 100)
        _, sent, closed = self.system([child, parent, child, (b"S", 1, 101)])
        self.assertFalse(terminal.wake_owned_zombie((7, 100), b"321"))
        sent.assert_not_called()
        closed.assert_called_once_with(99)

    def test_unavailable_process_handle_never_falls_back_to_numeric_signalling(self):
        child, parent = (b"Z", 7, 50), (b"S", 1, 100)
        opened, sent, closed = self.system([child, parent])
        opened.side_effect = ProcessLookupError()
        with patch.object(terminal.os, "kill") as numeric_signal:
            self.assertFalse(terminal.wake_owned_zombie((7, 100), b"321"))
            numeric_signal.assert_not_called()
        sent.assert_not_called()
        closed.assert_not_called()

    def test_failed_signal_closes_the_owned_handle(self):
        child, parent = (b"Z", 7, 50), (b"S", 1, 100)
        _, sent, closed = self.system([child, parent, child, parent])
        sent.side_effect = ProcessLookupError()
        with self.assertRaisesRegex(RuntimeError, "wakeup failed; no retry"):
            terminal.wake_owned_zombie((7, 100), b"321")
        closed.assert_called_once_with(99)


class ExitCoordinationTests(unittest.TestCase):
    def test_already_reaped_status_does_not_signal_or_wait(self):
        with patch.object(terminal.subprocess, "run", return_value=SimpleNamespace(stdout=b"0:\n")) as run:
            with patch.object(terminal, "wake_owned_zombie") as wake:
                self.assertFalse(terminal.wait_for_exit(["tmux"], (7, 100), 75, {}))
                self.assertEqual(run.call_count, 1)
                wake.assert_not_called()

    def test_owned_wakeup_never_replays_an_owner_command(self):
        results = [SimpleNamespace(stdout=value) for value in (b":", b"321", b"", b"0:")]
        with patch.object(terminal.subprocess, "run", side_effect=results) as run:
            with patch.object(terminal, "wake_owned_zombie", return_value=True) as wake:
                self.assertTrue(terminal.wait_for_exit(["tmux"], (7, 100), 75, {}))
                wake.assert_called_once_with((7, 100), b"321")
                operations = [call.args[0][1] for call in run.call_args_list]
                self.assertEqual(operations, ["display-message", "display-message", "wait-for", "display-message"])

    def test_empty_status_after_notification_still_refuses(self):
        results = [SimpleNamespace(stdout=value) for value in (b":", b"321", b"", b":")]
        with patch.object(terminal.subprocess, "run", side_effect=results):
            with patch.object(terminal, "wake_owned_zombie", return_value=False):
                with self.assertRaisesRegex(RuntimeError, "no reaped status"):
                    terminal.wait_for_exit(["tmux"], (7, 100), 75, {})

    def test_late_zombie_wakeup_keeps_the_original_deadline(self):
        clock = [0]
        replies = iter([b":", b"321", b":", b"", b"0:"])
        waits = []

        def command(arguments, **options):
            if arguments[1] == "wait-for":
                waits.append(options["timeout"])
                if len(waits) == 1:
                    clock[0] = 70
                    raise subprocess.TimeoutExpired(arguments, options["timeout"])
            return SimpleNamespace(stdout=next(replies))

        with patch.object(terminal.time, "monotonic", side_effect=lambda: clock[0]):
            with patch.object(terminal.subprocess, "run", side_effect=command):
                with patch.object(terminal, "wake_owned_zombie", side_effect=[False, True]):
                    self.assertTrue(terminal.wait_for_exit(["tmux"], (7, 100), 75, {}))
        self.assertEqual(waits, [70, 5])


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "pidfd_open")
                     and hasattr(signal, "pidfd_send_signal"), "Linux process-handle acceptance")
class NativeZombieReapingTests(unittest.TestCase):
    def test_one_owned_notification_reaps_a_real_zombie_without_replaying_it(self):
        script = """
import os, signal, subprocess, sys
signal.signal(signal.SIGCHLD, signal.SIG_DFL)
signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGCHLD})
child = subprocess.Popen([sys.executable, '-I', '-c', 'pass'], stdout=subprocess.DEVNULL)
signal.sigwait({signal.SIGCHLD})
print(child.pid, flush=True)
signal.sigwait({signal.SIGCHLD})
pid, status = os.waitpid(child.pid, 0)
print('reaped=%d' % os.waitstatus_to_exitcode(status), flush=True)
"""
        parent = subprocess.Popen([sys.executable, "-I", "-c", script], stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            self.assertTrue(select.select([parent.stdout], [], [], 10)[0], "native parent did not become ready")
            line = parent.stdout.readline(32).strip()
            self.assertTrue(line.isdigit(), "native parent did not identify its child")
            child_pid = int(line)
            identity = terminal.server_identity(parent.pid)
            self.assertEqual(terminal.process_identity(child_pid)[:2], (b"Z", parent.pid))
            self.assertTrue(terminal.wake_owned_zombie(identity, child_pid))
            output, _ = parent.communicate(timeout=10)
            self.assertEqual(parent.returncode, 0)
            self.assertEqual(output.strip(), b"reaped=0")
            print("Native owned zombie reaping accepted.")
        finally:
            if parent.poll() is None:
                parent.send_signal(signal.SIGCHLD)
                try:
                    parent.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    parent.terminate()
                    try:
                        parent.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        parent.kill()
                        parent.communicate(timeout=5)
            parent.stdout.close()


if __name__ == "__main__":
    unittest.main()

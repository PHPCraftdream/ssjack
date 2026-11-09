import unittest
from unittest.mock import Mock, patch

import owner_import


class OwnerImportExitReadinessTests(unittest.TestCase):
    def test_pty_eof_without_reaped_status_is_not_ready(self):
        # pane_dead may already be 1 while both status formats are empty.
        for value in (b":", b":\n", b" : \n"):
            self.assertFalse(owner_import.exit_status_ready(value))

    def test_normal_and_signal_results_are_ready_not_necessarily_successful(self):
        for value in (b"0:", b"1:", b"255:\n", b":TERM", b":KILL\n"):
            self.assertTrue(owner_import.exit_status_ready(value))

    def test_reaping_transition_requires_waiting_past_pty_eof(self):
        observed = [owner_import.exit_status_ready(value) for value in (b":", b":", b"0:")]
        self.assertEqual(observed, [False, False, True])

    def test_missing_format_separator_cannot_prove_readiness(self):
        for value in (b"", b"0", b"TERM"):
            self.assertFalse(owner_import.exit_status_ready(value))


class TerminalOutputDrainTests(unittest.TestCase):
    def test_reader_drains_without_consumer_pumping_and_take_is_incremental(self):
        stream = Mock()
        stream.fileno.return_value = 12345
        with patch.object(owner_import.os, "read", side_effect=[b"first", b"second", b""]) as read:
            output = owner_import.TerminalOutput(stream)
            self.assertEqual(output.finish(), b"firstsecond")
            self.assertEqual(read.call_count, 3)
            self.assertEqual(output.take(), b"firstsecond")
            self.assertEqual(output.take(), b"")
            self.assertEqual(output.finish(), b"firstsecond")

    def test_continuous_drain_keeps_the_output_bound(self):
        stream = Mock()
        stream.fileno.return_value = 12345
        with patch.object(owner_import.os, "read", side_effect=[b"oversized", b""]):
            output = owner_import.TerminalOutput(stream, limit=4)
            with self.assertRaisesRegex(RuntimeError, "output exceeded its bound"):
                output.finish()
            self.assertEqual(output.take(), b"")


if __name__ == "__main__":
    unittest.main()

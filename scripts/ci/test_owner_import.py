import unittest

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


if __name__ == "__main__":
    unittest.main()

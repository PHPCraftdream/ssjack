import unittest

import owner_connect


class OwnerMenuSelectionTests(unittest.TestCase):
    def test_exit_follows_displayed_management_rows(self):
        for connections in (1, 3):
            for remote_mcp in (False, True):
                with self.subTest(connections=connections, remote_mcp=remote_mcp):
                    rows = [b"Connect: synthetic-%d" % i for i in range(connections)]
                    rows += [b"Servers", b"Global secrets"]
                    if remote_mcp:
                        rows.append(b"Remote MCP servers")
                    rows += [b"Export", b"Import", b"Link", b"Pending", b"Exit"]
                    content = b"ssjack owner\nDatabase / Global scope\n"
                    content += b"\n".join((b"> " if i == 0 else b"  ") + row
                                          for i, row in enumerate(rows))
                    content += b"\nPersistence: saved\nExit\n"
                    self.assertEqual(owner_connect.menu_index(content, b"Exit"), len(rows) - 1)

    def test_current_focus_does_not_change_row_index(self):
        content = b"  Connect: first\n> Connect: second\n  Remote MCP servers\n  Exit\n"
        self.assertEqual(owner_connect.menu_index(content, b"Exit"), 3)

    def test_missing_or_unrendered_exit_refuses(self):
        for content in (b"", b"Exit\nPersistence: saved\n", b"> Servers\n"):
            with self.assertRaisesRegex(RuntimeError, "menu item is not visible"):
                owner_connect.menu_index(content, b"Exit")


if __name__ == "__main__":
    unittest.main()

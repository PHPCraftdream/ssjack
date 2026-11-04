# Explicit owner terminal editor and connection picker

Start the Bubble Tea picker with `ssjack --interactive --vault DATABASE`.
Use `ssjack --interactive --server production --account deploy --vault DATABASE`
to open a particular account directly. With only `--server`, the server page
lists its accounts for explicit navigation. Unknown selectors refuse, and legacy
`--profile`/`-p` cannot be combined with named server selectors.
No command, omitted selectors, and terminal detection never enable the editor implicitly.
Interactive mode requires terminal input and output and refuses command/mode
combinations before requesting the database password. Named selector syntax and
conflicts are also checked before unlock; actual directory names are resolved only
after authentication. Legacy databases require
an explicit `vault migrate-directory NEW_FILE` first; opening this editor does
not silently migrate or rewrite them.

The database password is requested once. The existing owner coordinator retains
its authenticated session in RAM and serializes encrypted persistence. The root
screen is a connection picker: first one entry per named SSH account whose usage
permits human use (`both` or `human`), labelled with the escaped server name,
address, login, account name and authentication kind; agent-only accounts are not
listed. With no such account (including an empty database) a non-actionable
`(no SSH connections available)` entry is shown and only reports a message. The
management items follow unchanged: servers, global secrets, export, store linking,
pending change and exit. The management screens cover their named SSH accounts,
server-scoped secrets and explicit pending-operation controls. Names and public metadata
are visible; passwords, private-key paths entered as credentials, store unlock
material, and secret values are masked. Terminal-control characters in metadata
are quoted. Raw backend error strings are not rendered.

## Human SSH connection

A connection starts only when the owner presses Enter on a connection entry, or on
the `Connect via SSH` item at the top of an account screen (shown only when that
account permits human use). Other keys, a single available entry, and
`--server`/`--account` startup selection never connect; the selectors only focus
the server or account screen. Selection ends the Bubble Tea program without
closing the database session. The command then asks the already unlocked session
for a client configuration for that one server/account (`HumanSSH`; a second
unlock is never requested and no credential bytes are returned). The session
refuses closed state, unknown server or account, and accounts that do not permit
human usage. The configuration uses only the verified host-key pins stored in the
encrypted database, built from a copy of the credential, so later edits or close
cannot alter it. The shared terminal handoff (size query, `TERM`, resize
watcher, raw mode, built-in SSH client, no external `ssh`) then runs on the real
terminal, which the exited program has restored and no longer uses. The same model
resumes in a fresh program on the root screen position it had; its metadata is
refreshed and a fixed message reports `SSH session ended (exit code N)` or a
generic failure that made no database change. Raw error text is never displayed.
Terminal input is owned by an explicit pump that starts only after the SSH shell
is established and is cancelled and joined when the session ends; the whole
cancel and join is bounded by one 2 second timer, and a cancel call that blocks
counts as not released. On Linux, macOS and BSD the cancellable reader cancels
the blocked read via epoll or select, allowing the picker to resume. Input already
read for a closing SSH session is not replayed into the picker. On
Windows consoles in VT-input mode the library cannot cancel the read, so a
connection there normally ends in the fail-closed exit rather than a resumed
picker; resuming is not claimed to work on Windows. On failure to release, the
reader's handles are not closed (a read or cancel may still use them), the
terminal mode captured before the reader was created is restored, the picker
does not resume, and the command exits through the bounded database close and
reports that terminal input could not be released. If the owner cancels the whole
command meanwhile, the final bounded close below still runs.

Use arrows to navigate, Enter to select, Tab/Shift+Tab to focus fields or buttons,
and Escape to cancel or go back. Apply transfers owned input to a Bubble Tea
command; Cancel clears it without calling the backend. Editing an account with a
blank credential keeps its current credential only when the selected authentication
kind matches. New key authentication imports a bounded existing private-key file;
it does not create plaintext staging. Server creation requires independently
verified bare OpenSSH host keys separated by `|`. No scan or SSH connection is
performed by these forms. Server connection edits update every account together;
blank replacement host keys retain the verified pins, and public fingerprints
are displayed in the server view. Duplicate account creation refuses rather than replacing
an existing account. Existing account names are not renamed through this form.

Secret scope is selected through the tree, not inferred through fallback. Removal
requires the explicit `REMOVE` confirmation. Linked value operations retain the
coordinator's durable encrypted intent and exact versioned-reference semantics.
Pending controls accept `retry-db`, `reconcile`, `resume-draft`, and `cancel-draft`;
opening the editor never automatically replays an interrupted operation.

Persistence status distinguishes saving, saved, errors, and pending owner decisions.
Exit waits for the coordinator; a failed close leaves the picker running. Terminal
failure, external cancellation or a connection-free exit attempts a bounded final
close (one minute) and returns an
error if unresolved state remains. This is not a process-crash durability guarantee
for unsaved input. There is no implicit discard action. The owner leaves through
the Exit item or Ctrl+C; ending an SSH session returns to the picker.

## Verification paths

Fast CI drives Bubble Tea messages and the actual framework event loop/renderer
with synthetic input. Full-profile Linux acceptance additionally drives the CLI
through a real pseudo-terminal and a production-encrypted synthetic database:
unlock, rename, cancel a credential form, exit, and reopen to verify persistence
and preservation of both SSH accounts. The driver never prints its terminal
transcript or places password bytes in arguments, environment variables or files.
The same full-profile run then reuses that database for a real-terminal connection
acceptance (`scripts/ci/owner_connect.py`): a synthetic SSH server listens on
`127.0.0.1` inside the test process with a fresh host key, and the fixture accounts
are retargeted to it with matching host pins. Through tmux the driver unlocks once
(the `Vault secret:` prompt must appear exactly once in the whole run, including
after each connection; it is counted in the tmux control-mode `%output` records
decoded into one byte stream, so record framing cannot split it, and once on the
screen before the secret is pasted), verifies that the picker lists the key
account, the password account and an account on a server with a deliberately
wrong host pin but not an agent-only account, and that showing the picker does
not connect. Waiting uses no sleeps: screen expectations plus a control-mode
barrier (a unique `display-message -p` command whose complete `%begin`/`%end`
response must arrive, so earlier output is already in the stream), and a Down/Up
cursor probe proves the program processes input before any Enter. The driver
then connects the key account and the password account in turn, types a line
and sees the server's echo, exits, and returns to the picker with the fixed
exit-code message. Selecting the wrong-pin account must show the fixed failure
message and never reach the remote shell. The Go side asserts that the server
recorded exactly one public-key authentication and one password authentication
and none for the wrong-pin account. A second `single` run then marks every other
account agent-only so the picker has exactly one connection point; the driver
shows it, probes Down to `Servers` and back, asserts that nothing connected,
and exits, while the Go side asserts the loopback server accepted zero new TCP
connections (so no handshake). Afterwards the loopback server is joined with a
bounded wait and the database must have no pending owner state and unchanged
credentials. The driver also verifies its tmux server has exited. These tests do not exercise real operator
databases or servers. The picker, selection rules and `HumanSSH` also have source
tests (`internal/ownertui`, `internal/vault`, `internal/ownerdb`).

## Current boundaries

The Export menu captures a visible server/account/global scope and defaults to
encrypted output. Plaintext requires a separate format choice and the exact
`EXPORT PLAINTEXT` confirmation after its disclosure warning. Output is exclusive;
Cancel does not queue export. See [owner export format](OWNER-EXPORT-FORMAT.md).
Windows credential export uses a protected owner-only ACL checked before writing.
Linked value collection retains the Linux-only backend boundary; selected values
are never silently omitted on other platforms.

This implementation does not yet include
multiline secret input or interactive
secret rename without a value replacement. The picker offers no connection
search or filtering and no agent connections. Existing command paths remain available
for their documented operations. Connected terminal/process-fault acceptance is a
separate gate; pure message tests do not establish it. Linked app-store value
operations retain the existing Linux-only runtime boundary. Existing v1 text
transport limits and cryptographic profiles are unchanged.

Bubble Tea is pinned to v2.0.10. Its dependency resolution and six-target linked
inventory were collected in public CI without raising existing module selections.
Exact license filenames/texts are retained in the release policy, including
`uniseg`'s `LICENSE.txt` and the Go `x/sync` patent grant. Factual source matching
is not legal approval.

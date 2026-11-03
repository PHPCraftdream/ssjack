# Explicit owner terminal editor

Start the Bubble Tea editor with `ssjack --interactive --vault DATABASE`.
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
its authenticated session in RAM and serializes encrypted persistence. The menu
contains servers, their named SSH accounts, global secrets, server-scoped secrets,
store linking, and explicit pending-operation controls. Names and public metadata
are visible; passwords, private-key paths entered as credentials, store unlock
material, and secret values are masked. Terminal-control characters in metadata
are quoted. Raw backend error strings are not rendered.

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
Exit waits for the coordinator; a failed close leaves the editor running. Terminal
failure or external cancellation attempts a bounded final close and returns an
error if unresolved state remains. This is not a process-crash durability guarantee
for unsaved input. There is no implicit discard action.

## Verification paths

Fast CI drives Bubble Tea messages and the actual framework event loop/renderer
with synthetic input. Full-profile Linux acceptance additionally drives the CLI
through a real pseudo-terminal and a production-encrypted synthetic database:
unlock, rename, cancel a credential form, exit, and reopen to verify persistence
and preservation of both SSH accounts. The driver never prints its terminal
transcript or places password bytes in arguments, environment variables or files.
These tests do not exercise real operator databases or servers.

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
secret rename without a value replacement. Existing command paths remain available
for their documented operations. Connected terminal/process-fault acceptance is a
separate gate; pure message tests do not establish it. Linked app-store value
operations retain the existing Linux-only runtime boundary. Existing v1 text
transport limits and cryptographic profiles are unchanged.

Bubble Tea is pinned to v2.0.10. Its dependency resolution and six-target linked
inventory were collected in public CI without raising existing module selections.
Exact license filenames/texts are retained in the release policy, including
`uniseg`'s `LICENSE.txt` and the Go `x/sync` patent grant. Factual source matching
is not legal approval.

# Explicit remote MCP checkbox model

This package is a metadata-only Bubble Tea model, not itself startup integration,
persistence, authentication, a session grant or a remote bridge. No credential
values enter its input or result. The caller supplies the selected stable SSH
profile, exact displayed database revision and an authenticated metadata snapshot.

First use starts unchecked, including a singleton. Remembered checks survive only
when the current enabled server/account IDs and both revisions exactly match the
saved binding for that SSH profile. Display-only renames preserve that identity;
changed/disabled/deleted bindings do not become newly approved choices.

Space or Enter on an account toggles it. Continue and Cancel are separate focus
positions; only Enter on Continue returns a choice. Empty confirmation is valid.
Esc, Ctrl-C, q and Cancel return no choice, and the model never writes preferences.
At most 16 accounts may be checked. Input counts and display lengths are bounded;
structural errors and bound violations refuse rather than truncate. Display strings are quoted and the
visible account window follows the cursor. Zero models cannot manufacture approval.

A confirmed result owns its bindings and captures the original profile/revision.
Later input cannot change it, and caller mutations cannot change the model's
captured metadata. The caller must still revalidate the exact SSH context and
bindings against confirmed owner state before saving preferences or minting any
fresh bounded capability. A stale choice must not silently adopt newer endpoints,
credentials or policy. This package itself never performs network requests.
The selector is wired into full-mode startup after stable SSH profile selection.
Remembered exact bindings are suggestions only; explicit Continue is required for
empty and singleton choices. Cancellation/refusal stops before persistence,
capture, private launch issuance, and child launch. Following confirmation, startup
saves and verifies the preference receipt; only a non-empty choice prepares a
bounded launch and guard. No remote bridge consumes that launch. The Linux/amd64
selector/startup PTY acceptance source is authored but has not been run and is not
Windows/macOS acceptance. Task #357 is supervised bridge/harness integration;
#318 native bridge acceptance remains pending, #358 covers MCP archive
export/import, and #359 is the final gate. Task #317 remains incomplete.

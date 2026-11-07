# Explicit remote MCP checkbox model

This is a metadata-only Bubble Tea model, not startup integration, persistence,
authentication, a session grant or a remote bridge. No credential values enter
its input or result. The caller supplies the selected stable SSH profile, exact
displayed database revision and an authenticated metadata snapshot.

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
credentials or policy. This package itself never performs network requests. That
revalidation path now exists as the pre-adoption `vault.Vault.RemoteMCPCapture`
production entry, the post-adoption `vault.Session.RemoteMCPCaptureAt` seam
and `mcpgrant` issuance from an explicitly confirmed choice; startup wiring
remains pending.

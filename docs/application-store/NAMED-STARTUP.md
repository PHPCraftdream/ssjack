# Explicit named startup selection

Examples:

```sh
ssjack --vault DATABASE --server production --account deploy ssh
ssjack --vault DATABASE --server production --account agent run claude
ssjack --vault DATABASE --server production --account deploy check
ssjack --vault DATABASE --interactive --server production
ssjack --vault DATABASE --interactive --server production --account deploy
```

`--server` selects an exact, case-sensitive directory name. `--account` selects
one account on that server. An omitted account is inferred only when the selected
server has exactly one account. Multiple accounts without an explicit selection
refuse with guidance; neither `main` nor another account is silently substituted.
Unknown names refuse. Legacy databases require explicit directory migration.

`--profile`/`-p` remain legacy credential-record selectors and cannot be combined
with `--server`. `--account` without `--server`, empty explicit names and malformed
names refuse before unlock. Named selectors support SSH, check, key rotation,
text-adapter and full-mode harness startup. Database maintenance continues to use
its existing explicit legacy selectors; use the owner editor for directory edits.
Declarative enrollment and key-container creation are not named-server operations.

No missing command, missing selector or detected terminal starts a menu. Only
`--interactive` opens the owner editor; there the selected server/account is opened
directly, or the tree supplies explicit navigation when no server was selected.
Back navigation preserves the server/account hierarchy.

Resolution happens inside the already authenticated database load and returns the
existing stable credential-record identity. It does not run a second unlock and
it does not grant SSH/delivery permission. Existing usage restrictions, selected
key/password evidence, verified pins and human/root delivery grants still apply.
Registered Clawwright application options receive that resolved identity, never a
server label or an ambiguous account set. Literal secret references and explicit
server-local/global scopes are unchanged; there is no secret-name fallback.

The command implementation uses a reserved private string representation to bridge
existing string-based loaders. It is not accepted through `--profile`, persisted
in the database, exposed as a protocol, or treated as authorization.

# Parameterized owner commands

`ssjack owner ACTION [OPTIONS]` runs one owner-menu operation without navigating
the full menu. It requires a trusted input/output terminal and directory payload
schema v2. It requests the database password once, opens the same Bubble Tea form
as the menu, then waits for encrypted persistence and exits. It does not enter the
connection picker afterward. Use `--interactive` for a retained multi-action session.

Only metadata belongs in parameters. Passwords, application values, raw private
keys, store unlock secrets and exact confirmations have no argv or environment
option. A private-key **file path** is metadata, not inline private-key content.
Missing fields remain editable in the form; supplied fields are read-only and
skipped by Tab/Shift+Tab. Apply is still explicit. Escape, Ctrl+C and Cancel abandon
an unsubmitted form. A failure after submission may follow effects: inspect
persistence and pending recovery rather than automatically retrying.

## Syntax and selectors

```sh
ssjack --vault DATABASE owner ACTION --option VALUE
ssjack --vault DATABASE --server production --account operator owner edit-account --login operator
```

Global options precede `owner`; action options follow `ACTION`. Global
`--vault`, `--server`, `--account` are the only supported global options here.
Do not combine with `--interactive`, `--profile`, keeper modes or a harness.
Duplicate options, conflicting selectors, unknown options and secret/confirmation
options refuse before unlock. Names are exact and case-sensitive.

Existing server/account selectors are required where indicated. For new accounts,
`--account` names the account to create, not an existing login to select. Secret
scope is always explicit: `--scope global`, or `--scope server --server NAME`.
There is no global fallback or ambiguous account inference in owner commands.

## Actions and metadata options

| Action | Selection | Optional form parameters |
| --- | --- | --- |
| `add-server` | New database entry | `--name`, `--address`, `--account`, `--login`, `--auth key\|password`, `--key-file`, `--usage both\|human\|agent`, `--host-keys` |
| `rename-server` | `--server NAME` | `--name` |
| `edit-server` | `--server NAME` | `--address`, `--host-keys` |
| `add-account` | `--server NAME` | `--account`, `--login`, `--auth`, `--key-file`, `--usage` |
| `edit-account` | `--server NAME --account NAME` | `--login`, `--auth`, `--key-file`, `--usage` |
| `edit-proxy` | `--server NAME` | `--type direct\|socks5\|http`, `--address`, `--login` |
| `add-secret` | Explicit secret scope | `--name` |
| `edit-secret` | Explicit secret scope and `--secret NAME` | Value entered only in the form |
| `remove-secret` | Explicit secret scope and `--secret NAME` | Exact `REMOVE` entered only in the form |
| `export` | `--scope all\|global\|server\|account` (default `all`) | `--destination`, `--format encrypted\|plaintext` |
| `import` | Whole archive | `--file` |
| `link` | Database | `--directory` |
| `pending` | Database | `--action retry-db\|reconcile\|resume-draft\|cancel-draft\|resume-import\|abort-import` |

Server/account export scopes require `--server`; account scope also requires
`--account`. They include the selected server's local values but not global
values. Global scope exports only global values. Default export is encrypted.
Plaintext still requires the disclosure warning and exact `EXPORT PLAINTEXT`
in the form; a flag never substitutes for that human confirmation.

`--host-keys` contains independently verified bare OpenSSH public keys separated
by `|`. It is not discovery or trust-on-first-use. `--key-file` explicitly selects
key authentication and conflicts with `--auth password`. Blank credentials on
edit retain the existing matching credential kind, as in the menu. Proxy-password
retention likewise requires unchanged type/address/login. See [proxy limits](PROXY.md).

## Examples

```sh
ssjack owner add-server --name production --address host.example:22 --account operator --login deploy --auth password --usage human
ssjack owner edit-account --server production --account operator --key-file ./approved-key.pem
ssjack owner edit-proxy --server production --type socks5 --address proxy.example:1080 --login operator
ssjack owner add-secret --scope global --name api-token
ssjack owner edit-secret --scope server --server production --secret api-token
ssjack owner export --scope account --server production --account operator --destination owner.zip
ssjack owner import --file owner.zip
ssjack owner pending --action reconcile
ssjack help owner edit-account
```

For the first example, the form asks for the SSH password and verified host keys
not supplied by parameters. Supplying all metadata never supplies a password or
removes Apply. Secret operations require the already linked/provisioned private
application store and remain Linux-only. There is no secret getter or JSON
plaintext output.

## Import and recovery

Import still authenticates the archive in RAM, shows metadata/conflicts and
requires exact `IMPORT`. It never silently merges or overwrites. The command
waits for complete application; a partial import returns failure, not success.
Per-secret encrypted intents remain recoverable. The remaining import plan lives
only in that process's memory; a later command cannot reconstruct it after exit.
For an import where in-process resume/abort matters, use the retained
`--interactive` session. Abort does not roll back entries already applied.

SSH connection is already available through `--server NAME --account NAME ssh`;
commands do not connect just because metadata was displayed or a form was opened.
Root provisioning/grants, harness/internal endpoints and standalone key-container
operations retain their separate interfaces and authority. They are not silently
added to this database-owner menu.

## Parity acceptance

Registry/navigation tests enumerate the actual owner-menu management forms and
require a command for each, then require a shared form for every registered owner
command. Effect tests drive the menu and parameterized path and compare changes,
export scope and recovery dispatch. Bubble Tea Program tests exercise secret
masking in raw renderer output, immutable metadata, cancellation, persistence
failure and import confirmation. Production CI additionally drives the real CLI
in tmux against a synthetic full-profile database, checks cancellation preserves
ciphertext and reopens the result to verify metadata and hidden credentials.
These tests are acceptance checks, not a claim that an unrun candidate passed.

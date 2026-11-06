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

Forms pin the database revision from the same snapshot as their displayed metadata.
A stale Apply refuses before changing the directory or publishing queued owner work.
Directory edits also refuse while the owner worker is busy, preserving the scope of
an admitted export/import/link operation. Explicit import cancellation remains
revision-checked and does not roll back effects already committed.

If a keeper owns this database, the helper attaches through authenticated native
IPC after its own single unlock. Only a proven absent endpoint permits exclusive
standalone control. Unsafe, busy, unauthenticated or uncertain endpoints never
trigger standalone fallback. Successful helper exit flushes and detaches its peer,
not the keeper. Human SSH from the interactive picker captures the exact displayed
saved revision; later owner edits do not change that captured connection.

## Syntax and selectors

```sh
ssjack --vault DATABASE owner ACTION --option VALUE
ssjack --vault DATABASE --server production --account operator owner edit-account --login operator
```

Global options precede `owner`; action options follow `ACTION`. Global
`--vault`, `--server`, `--account` and `--vault-password` are supported here.
The database unlock password alone can also come from `SSJACK_VAULT_PASSWORD`;
see [startup password risks and precedence](STARTUP-PASSWORD.md). This does not
supply form credentials or confirmations and does not remove the TTY requirement.
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

## Remote MCP management

MCP actions use the same owner form and persistence path. Their `--server` and
`--account` selectors name remote MCP records, **not SSH records**. Merely opening
these pages or commands does not connect to the endpoint.

| Action | Selection | Optional metadata parameters |
| --- | --- | --- |
| `add-mcp-server` | New MCP server | `--name`, `--url` (HTTPS only) |
| `edit-mcp-server` | `--server NAME` | `--name`, `--url`, `--enabled true\|false` |
| `remove-mcp-server` | `--server NAME` | Exact `REMOVE` in the form; also removes its accounts |
| `add-mcp-account` | `--server NAME` | `--account`, `--auth none\|bearer\|basic`, `--login`, `--enabled`, `--credential-action` |
| `edit-mcp-account` | `--server NAME --account NAME` | `--auth`, `--login`, `--enabled`, `--credential-action` |
| `rename-mcp-account` | `--server NAME --account NAME` | `--name` |
| `remove-mcp-account` | `--server NAME --account NAME` | Exact `REMOVE` in the form |
| `edit-mcp-header` | `--server NAME --account NAME` | `--header`, `--header-action replace\|clear` |

Primary `--credential-action` accepts `keep`, `replace` or `clear`. `keep` requires
an existing account with unchanged authentication kind and username. `replace`
requires a hidden token/password. `clear` requires `--auth none`, an empty username
and an empty credential field. New public accounts default to `none`/`clear`.
Hidden input never appears in argv, display metadata or help output. Header edits
replace or clear one canonical custom credential header; at most four are allowed.
Reserved Authorization, routing, framing and MCP headers cannot be overridden.

Display-only renames preserve remembered choices. Endpoint/policy/credential edits
invalidate prior preselection; active sessions do not silently adopt edits. The
launch checkbox selector, actual remote bridge and MCP-specific ZIP export/import
remain separate integration work. Existing exports/imports do **not** include MCP
credentials or remembered choices.

```sh
ssjack owner add-mcp-server --name docs --url https://docs.example/mcp
ssjack owner add-mcp-account --server docs --account work --auth bearer --credential-action replace
ssjack owner edit-mcp-header --server docs --account work --header X-Api-Key --header-action replace
ssjack owner rename-mcp-account --server docs --account work --name personal
```

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
application store. Protected owner storage/editing supports Windows, Linux and
macOS; Linux amd64 text adapters retain their narrower platform boundary. There
is no secret getter or JSON plaintext output.

## Import and recovery

Import still authenticates the archive in RAM, shows metadata/conflicts and
requires exact `IMPORT`. It never silently merges or overwrites. The command
waits for complete application; a partial import returns failure, not success.
Per-secret encrypted intents remain recoverable. The remaining import plan lives
only in the coordinator's RAM and is lost when that coordinator exits. An attached
helper owns its inspected plan; another helper cannot act merely by knowing its
PlanID. Disconnect cleans up no-effect state only. A retained effectful/partial plan
requires an explicit recovery decision against freshly displayed revision/PlanID;
attachment never resumes it automatically. Use a retained keeper or `--interactive`
session when in-process recovery matters. Abort does not roll back entries already
applied.

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

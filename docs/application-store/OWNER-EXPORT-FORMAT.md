# Explicit owner export archives

The archive is connected to the explicit trusted-terminal owner editor.
It has no MCP registration and no secret/master getter. No real operator export
is performed by its development or tests.

## Representation and bounds

The outer file is a standard ZIP archive using stored entries. The encrypted path
seals each payload through the existing authenticated `keyfile.Unlocked.Seal`
capability, with its existing encryption profile and fresh nonce. This is data
encryption, not key wrapping. The ZIP file itself is not passed directly to the
ordinary keyfile decoder; each `.ktav` entry is an existing keyfile container.

- `database.ssjack.ktav`: selected validated v2 Ktav directory records and settings.
- `secrets/ALIAS_ID.bin.ktav`: byte `0x01` followed by the exact selected value
  bytes, including empty values. This versioned nonempty frame preserves the
  existing keyfile sealer's rejection of zero-length payloads.
- `manifest.json.ktav`: `ssjack-owner-export-v1`, the database record and one
  secret-file record per selected alias. Each record binds its exact ZIP name,
  encoded length and SHA-256 digest of the **ciphertext** entry bytes.

The selected directory already contains secret names, scopes and exact references;
the manifest does not duplicate these. Consequently the manifest fits the existing
64 KiB keyfile bound while supporting 128 selected values of up to 16 KiB each.
The database entry retains the same 64 KiB bound. Outer ZIP metadata reveals opaque
alias identities, entry count and encoded lengths, not secret names or values.
Linked installation unlock material (`owner_store`) is refused rather than copied
into this portable credential/value export. It is not needed to decode the actual
exported values.

When `remote_mcp` is absent, the manifest remains `ssjack-owner-export-v1` and the
archive is compatible with legacy readers. A selected MCP directory is represented
in the same validated version-2 database record; its manifest is
`ssjack-owner-export-v2`. Readers bind this capability version to actual directory
presence, and a legacy reader refuses v2 rather than dropping MCP metadata. Vault
schema remains version 2; this archive distinction is not a database migration.

The builder requires an exact reference match for every value and refuses missing,
extra, duplicate or oversized inputs. It owns copies of its inputs and clears
owned buffers on close, best-effort within the trusted Go runtime. No claim of
complete application RAM erasure is made.

## Reader

`ownerarchive.ReadFile` (and `Read` for bytes already in memory) is the only
reader. It authenticates before it trusts and never extracts or stages files:

- The path is opened exactly once: with a no-follow, nonblocking descriptor on
  Unix, or a reparse-point-aware, disk-file-only handle on Windows. The type is
  checked on that open handle, so a FIFO, device, symlink, directory or a file
  replaced after any earlier check is refused without blocking. It must be a
  regular file of at most 40 MiB, read fully into one exact-size RAM buffer.
  `Read` enforces the same 40 MiB bound for data already in memory.
- At most 130 ZIP entries (128 values plus database and manifest), `Store`
  method only, no duplicates, no encrypted-ZIP flags. Names are a whitelist:
  the manifest, the database and `secrets/ALIAS_ID.bin` (plus `.ktav` when
  sealed); a plaintext and a sealed manifest together are refused. Each entry's
  declared size is bounded before it is opened.
- The manifest is parsed strictly (no unknown or duplicate keys) and must
  re-encode to exactly the same bytes. Every listed record's name, length and
  SHA-256 digest is verified over the stored entry bytes **before** that entry is
  decrypted. The database entry must list exactly the manifest's aliases, and
  every alias value must be present.
- Encrypted archives cost one unlock (four sequential Argon2id derivations): the manifest is unlocked with
  `keyfile.Unlock`, and the returned `Unlocked.Open` opens every other entry
  under that same key. A plaintext archive ignores any password.
- An archived database containing `owner_store` is refused. Archived secret
  references are parsed only to check the inventory.

Errors are classified. `ErrAuthentication` means a wrong password, modified
ciphertext or a digest/length mismatch of an encrypted entry. `ErrArchive` means a
structurally invalid, unsupported or over-bound archive (including a plaintext
digest mismatch). Neither carries archive content. `Opened` owns authenticated
copies until `Close`, which clears them.

Owner import builds on this reader; see
[owner coordinator](OWNER-COORDINATOR.md#owner-import) and
[owner terminal editor](OWNER-TUI.md#owner-import).

## Deliberate plaintext artifact

The separate plaintext operation requires the exact local confirmation
`EXPORT PLAINTEXT`. It uses the same final ZIP representation without `.ktav`
suffixes (the database entry is `database.ktav`); these are actual plaintext
credential and value files inside the explicit final artifact. This is not the
default operation. The trusted owner form shows the selected scope and a disclosure
warning before accepting that confirmation. It must never accept this approval
through a model-facing call.

## Publication boundary

The bounded archive is assembled in RAM, then written only to the explicitly
selected new final file with exclusive creation and `0600` permissions on Unix.
Windows creates the file with a protected owner-only DACL, then verifies the actual
file-handle owner, inheritance protection and sole allow entry before writing. There is
no plaintext temporary/staging file or implicit overwrite. Failed publication
attempts remove only the same file identity created by that operation; callers
must inspect the destination after errors and must not report success. File sync
is performed; directory crash durability is not claimed. Unsupported private-file
runtimes refuse before publication. Linked application-store collection still
requires its existing supported Linux runtime; unsupported platforms never omit
selected values to produce a credential-only artifact silently.

The session API prepares an opaque export plan from explicit server/account IDs,
an explicit global-secret selection and revision-bound MCP account bindings. MCP
selection is opt-in; legacy scopes do not select remote MCP implicitly. MCP-only
selection is valid without SSH accounts or global values. The plan includes only
selected MCP servers and accounts, and retains a remembered `Last` binding only
when it is selected, enabled and still matches its captured revisions for an
exported SSH profile. An MCP-only archive has no SSH profile context and therefore
no `Last` bindings. The plan returns reference metadata only; selected credential
buffers and the cached sealing key have no getter. It refuses pending/unsaved
database state and publication after the captured revision changes or the session
closes. Encrypted publication reuses the retained authenticated key; it does not run
another unlock during export.

The owner coordinator queues export through its existing single worker and waits
for a saved, unchanged database snapshot. Selected values are copied privately
from a clean authenticated owner editor into the concrete opaque plan; no generic
value sink or getter is exposed. Exact version/snapshot references and signed
anchor/history state are checked before and after collection. Collection failure
closes the plan, so partial or stale copies cannot later be published.

The explicit owner menu offers all contents, one server, one account plus that
server's secrets, global values only or explicitly selected MCP accounts (including
MCP-only). The shared form lists stable MCP account IDs, names, authentication
types, endpoints and enabled flags from the captured metadata snapshot; its MCP
account field is blank by default. `owner export --mcp-accounts ID[,ID…]` uses that
same form and validates the IDs against the snapshot; `--scope mcp` requires at
least one explicit MCP account. Existing all/server/account/global scopes and
selection behavior remain unchanged, with optional MCP accounts. The scope is
captured before Apply, encrypted format is the default, and plaintext requires a
visible warning and `EXPORT PLAINTEXT`. Cancel never queues export. Completion
waits for the worker; errors require inspection of the selected destination, not an
automatic replay. Exports do not rewrite the source database or create a new
application-store snapshot. They describe the authenticated captured selection,
not a claim of future latest-state freshness.

Import preview includes MCP server/account metadata only: names, endpoints,
authentication kinds and enabled state, never credentials or custom-header values.
Imports assign fresh MCP server and account IDs at revision 1 and remap only
selected, current, enabled `Last` bindings whose SSH profile is also selected.
MCP-only imports do not create an SSH context. Existing SSH identities preserve
their legacy imported IDs. Name, endpoint, ID and limit conflicts refuse the whole
import; the importer does not merge or overwrite. No grants or runtime sessions are
created by archive import.

Full CI helpers cover actual sealed credentials, wrong-password rejection and
private app-store value collection, plus plaintext export and overwrite refusal.
Production-profile acceptance also imports encrypted and plaintext archives into
fresh databases (see the coordinator document). The selected native archive
acceptance exercises the command/form path with explicit MCP account IDs, encrypted
MCP round-trip, unselected-record exclusion, credential/header custody, fresh IDs,
revision-1 imports, selected `Last` closure, MCP-only archives and metadata-only
preview. Its test name remains selected by the existing dedicated public full-KDF
CI command.

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

The builder requires an exact reference match for every value and refuses missing,
extra, duplicate or oversized inputs. It owns copies of its inputs and clears
owned buffers on close, best-effort within the trusted Go runtime. No claim of
complete application RAM erasure is made.

A future reader must authenticate the manifest first, reject duplicate/unlisted ZIP
entries, verify each exact name/length/digest and authenticate each individual
container with the selected database password. It must enforce the same bounds
and require all selected values; extracting files is not authenticated import or
restoration. Reader/import integration and wrong-password production acceptance
are not yet implemented by this core.

## Deliberate plaintext artifact

The separate plaintext operation requires the exact local confirmation
`EXPORT PLAINTEXT`. It uses the same final ZIP representation without `.ktav`
suffixes (the database entry is `database.ktav`); these are actual plaintext credential and value files inside the
explicit final artifact. This is not the default operation. The eventual CLI must
show selected scope and a disclosure warning before accepting that confirmation.
It must never accept this approval through a model-facing call.

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

The session API prepares an opaque export plan from explicit server/account IDs
and an explicit global-secret selection. It returns reference metadata only;
selected credential buffers and the cached sealing key have no getter. The plan
refuses pending/unsaved database state and refuses publication after the captured
revision changes or the session closes. Encrypted publication reuses the retained
authenticated key; it does not run another unlock during export.

The owner coordinator queues export through its existing single worker and waits
for a saved, unchanged database snapshot. Selected values are copied privately
from a clean authenticated owner editor into the concrete opaque plan; no generic
value sink or getter is exposed. Exact version/snapshot references and signed
anchor/history state are checked before and after collection. Collection failure
closes the plan, so partial or stale copies cannot later be published.

The explicit owner menu offers all contents, one server, one account plus that
server's secrets, or global values only. The scope is captured before Apply,
encrypted format is the default, and plaintext requires a visible warning and
`EXPORT PLAINTEXT`. Cancel never queues export. Completion waits for the worker;
errors require inspection of the selected destination, not an automatic replay.
Exports do not rewrite the source database or create a new application-store
snapshot. They describe the authenticated captured selection, not a claim of
future latest-state freshness.

Full CI helpers cover actual sealed credentials, wrong-password rejection and
private app-store value collection, plus plaintext export and overwrite refusal.
The reader/import interface remains unfinished. Existing keyfile tools can decode each authenticated container; the
actual Ktav directory entry retains the ordinary v2 database shape.

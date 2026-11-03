# Owner export archive core (not yet wired to a command)

The archive core is an internal building block, not a delivered owner export CLI.
It has no MCP registration and no secret/master getter. No real operator export
is performed by its development or tests.

## Representation and bounds

The outer file is a standard ZIP archive using stored entries. The encrypted path
seals each payload through the existing authenticated `keyfile.Unlocked.Seal`
capability, with its existing encryption profile and fresh nonce. This is data
encryption, not key wrapping. The ZIP file itself is not passed directly to the
ordinary keyfile decoder; each `.ktav` entry is an existing keyfile container.

- `database.json.ktav`: selected validated v2 directory records and settings.
- `secrets/ALIAS_ID.bin.ktav`: exact selected value bytes, including empty values.
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
suffixes; these are actual plaintext credential and value files inside the
explicit final artifact. This is not the default operation. The eventual CLI must
show selected scope and a disclosure warning before accepting that confirmation.
It must never accept this approval through a model-facing call.

## Publication boundary

The bounded archive is assembled in RAM, then written only to the explicitly
selected new final file with exclusive creation and `0600` permissions. There is
no plaintext temporary/staging file or implicit overwrite. Failed publication
attempts remove only the same file identity created by that operation; callers
must inspect the destination after errors and must not report success. File sync
is performed; directory crash durability is not claimed. Windows is refused
before publication until a verified restrictive ACL path is implemented.

The core is not yet connected to the owner coordinator, cached session sealing,
exact private value collection, scope-selection UI or export commands. Plaintext
archive unit tests do not prove the encrypted production path.

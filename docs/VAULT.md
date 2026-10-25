# Encrypted credentials and interactive SSH

Manual SSH sessions and coding-agent sessions use one encrypted database of named credentials. `ssh <name>` uses a record directly; `run <name> <harness> [arguments...]` makes the keeper expose only that record through its authenticated MCP connection. Neither mode exports the private key to an external SSH executable or SSH agent, and vault editing does not start a plaintext editor.

## Commands

Use an executable built from the updated source. The default vault path is `.ssh/credentials.ssjack.ktav`, relative to the current working directory. The parent directory must exist.

```text
ssjack vault init
ssjack vault add storage
ssjack vault list
ssjack vault show storage
ssjack vault edit storage
ssjack vault remove storage
ssjack vault passwd
ssjack vault import storage existing-key.pem
ssjack vault export storage exported-key
ssjack vault public storage
ssjack ssh storage
ssjack run storage claude -c
```

To select another vault, put the option before the command:

```text
ssjack --vault .ssh/other.ssjack.ktav vault list
ssjack --vault .ssh/other.ssjack.ktav ssh storage
```

**Every invocation that accesses the vault asks for its secret interactively.** There is no unlocked daemon, remembered password, environment override, pipe input, or cross-command password cache. Initialization asks for a new secret twice. `vault passwd` asks for the current secret and confirms the new secret. Invalid syntax or unavailable terminal input fails without opening credentials.

After `ssh` opens an authenticated SSH session, that session works like a normal interactive terminal; it does not ask for a vault secret before each remote shell command. The next ssjack invocation asks again. This is the selected per-CLI-invocation boundary, not per-keystroke or per-remote-command authorization.

## What is encrypted

Each vault target contains:

- SSH address and port;
- SSH username;
- private SSH key bytes;
- explicitly trusted server public keys.

All these fields and the target labels are inside the encrypted payload. Only the container's public cryptographic parameters and ciphertext are stored outside encryption. The vault uses the same four sequential 1 GiB Argon2id calls and **1000 nested AES-256-GCM data encryptions** documented in [KEYS.md](KEYS.md). An empty vault is encrypted too.

Private key bytes are unencrypted only inside the decrypted in-memory vault, never in a staging file. The file replacement stage is already ciphertext. The vault does not store source key paths, host-key file paths, or plaintext target settings beside itself. Unix mode `0600` is used for private files; Windows users must also restrict the directory ACL.

The current vault supports SSH public-key authentication. It does not add SSH password authentication, agent forwarding, host-key auto-acceptance, CA-based host certificates, port forwarding, or file transfer.

## Add and edit targets

`vault add <name>` prompts without echo for:

1. Address in `host:port` form, including brackets for IPv6.
2. SSH username.
3. Path of a supported standard OpenSSH/PEM private key or ssjack key container.
4. That source key's passphrase, only if encrypted.
5. Path of one verified, bare server public key file in OpenSSH `.pub` format.

A public host-key file must come from an already trusted channel. Supply the server's host public key, not the client's login public key. A `known_hosts` line is not a bare `.pub` key and is rejected. Do not obtain trust merely by accepting an unverified network scan.

`vault edit <name>` uses the same hidden prompts. Enter keeps the existing field. A new private key is imported only when a new key path is entered; a new server pin replaces the previous pin only when a new server public-key file is entered. The current record is not written if validation fails.

The imported source remains unchanged. Importing does not delete older, potentially weaker private-key copies. Decide separately whether to retain or retire them. A key can first be created with:

```text
ssjack --generate-key .ssh/derived-key.ssjack.ktav
```

Then import that encrypted file through `vault add`. The vault secret and the source key's secret may differ. After import, only the vault secret is required to access that copy.

`vault import <name> <file>` replaces only the key in an existing record, preserving address, user, and server pins. New records are created with `vault add`. Both plaintext and encrypted standard sources can be imported explicitly; plaintext sources remain plaintext on disk because the importer never modifies them. Only the encrypted database receives the imported copy.

`vault export <name> <file>` writes a new encrypted OpenSSH private-key file after a separate passphrase confirmation. It never overwrites a destination or writes an unencrypted private-key export. Standard OpenSSH protection replaces the custom container profile for that exported copy; do not count it as four Argon2id plus 1000 layers. Use a different export passphrase from the vault secret so that this weaker copy does not become a cheaper oracle for the vault secret. `vault public <name>` prints only the OpenSSH public key, suitable for redirecting to a `.pub` file. A changed private key may require updating `authorized_keys` through a trusted connection; no command does that remotely on its own.

`vault list` prints target labels only. `vault show <name>` intentionally displays its address, username, and host-key fingerprints, but never its private key. Terminal output, terminal recording, and screenshots remain disclosure paths when explicitly displaying credentials. `vault remove` requires typing the target label again before saving.

Target labels use 1 to 64 ASCII letters, digits, dots, underscores, or hyphens, starting with a letter or digit. The vault supports up to 64 targets, subject to the container's 64 KiB plaintext size limit.

## Interactive shell

`ssh <name>` reads only the encrypted vault. It does not read the legacy plaintext target configuration or `known_hosts` files. The SSH authentication signer and pinned server public keys are prepared in memory.

The built-in Go SSH client verifies that the server presents one of the public keys stored for that target. It requests a PTY and a remote login shell, passes stdin/stdout/stderr, and forwards terminal size changes. The local terminal enters raw mode only after server authentication and PTY acceptance. Normal exit, cancellation, shell startup failure, and other ordinary error paths restore the terminal. An uncatchable process kill or crash can still require manual terminal recovery.

The remote account's shell and permissions determine what the user can do. This mode is not a sandbox and does not grant sudo. Raw interactive output is controlled by the remote system, as in a normal SSH terminal. It is not rendered through the MCP command-card sanitizer.

Remote exit status is preserved. Missing terminal input/output, mismatched server keys, refused PTY requests, and refused shell requests fail rather than falling back to an external client or skipping trust checks.

## Writes and concurrency

New vaults are created exclusively without overwriting an existing path. Updates use a same-directory encrypted staging file, flush it, and replace the old file through the OS rename operation. The implementation never deletes the current vault first to make replacement succeed. Filesystem/OS rename semantics, especially on Windows, remain relevant; this is not a guarantee against power loss on every filesystem.

An exclusive `.lock` file serializes cooperating writers. A hash of the encrypted revision is checked before replacement to avoid silently overwriting another CLI invocation's changes. A stale revision fails and must be reloaded; updates are not merged automatically. A crash can leave a stale lock, which is not removed automatically. Never remove one without first confirming that its writer is no longer active. These mechanisms do not isolate against a targeted process running as the same OS user and ignoring the lock protocol.

Changing the secret re-encrypts with fresh public salts and nonce parameters. Other backups retain their prior secret and protection. Removing a target is not guaranteed secure erasure of old filesystem blocks, snapshots, or backups.

Read-only commands and shell startup perform four Argon2id invocations. An update first unlocks the old vault and then protects a fresh container, so it performs eight, excluding the source key's own KDF when importing a key. No fixed wall-clock latency is promised; the full profile can take seconds or longer, and requires substantial available RAM. No local benchmark is implicit.

## Coding agents and MCP

```text
ssjack run storage claude -c
ssjack --vault .ssh/other.ssjack.ktav run work claude -c
```

The keeper asks for the vault secret once per launcher invocation, opens the named record, and prepares an in-memory SSH client configuration. Only that record name is given to the job manager, and its runner rejects any other target name. `remote_targets` therefore lists only the selected credentials, not the other records in the vault.

When using the shorthand `ssjack <harness> [arguments...]`, the launcher still uses the encrypted vault: it selects a single available record automatically or asks for a name from a sorted list after unlocking. An empty vault, unknown name, wrong secret, or cancelled selection fails before launching the harness. There is no automatic fallback to plaintext configuration.

The child harness starts `ssjack mcp` as before. That stdio bridge does not independently open the vault, accept a credentials flag, or receive the vault secret/private key. It connects to the keeper using the existing single-use environment/file capability pair. Selecting credentials does not bypass project MCP trust or authentication.

For explicit legacy compatibility only:

```text
ssjack --config .ssh/ssjack.ktav claude -c
```

This opt-in path uses the legacy plaintext target metadata and encrypted key files, and may expose all targets configured in that file. It cannot be combined with an explicit `run <name>` command. Existing files are not silently imported, deleted, or rewritten. Import their keys and verified server pins into named vault records to use the default encrypted-database path.

## Verification

Tests cover vault schema validation, private-byte cleanup, host-key pinning, output conflicts, revision conflicts, lock ownership, command validation, terminal restoration, PTY and resize requests, SSH stream forwarding, exit status, host mismatch, and cancellation. Network tests use local ephemeral SSH servers, not real accounts.

Key-container tests exercise 1000 actual AES-GCM data layers with an unexported low-memory Argon2id test implementation. Filesystem vault tests operate on opaque fixture bytes and do not claim to benchmark the production KDF. There is no public cheaper-profile flag. A dedicated GitHub CI job exercises the real 1 GiB profile through vault creation, loading, modification, and reloading; normal unit jobs skip that heavy integration test explicitly. This is functional validation, not a RAM/latency benchmark or confirmation of a real user terminal session. Defining these jobs does not imply they have passed.

Test and build execution belongs in GitHub CI, not local development commands. The Go CI matrix covers Linux, Windows, and macOS; the race job runs on Linux.

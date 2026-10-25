# Named credentials and recovery

ssjack uses one encrypted database for human SSH sessions and coding-agent sessions. Addresses, users, private keys, server pins, record names, and intended usage are inside the encrypted payload. The default file is `.ssh/credentials.ssjack.ktav`, relative to the working directory. Its parent directory must exist.

## Discover commands

```text
ssjack --version
ssjack help
ssjack help vault restore
ssjack key export --help
```

Every command has a usage description, safety notes, and examples in built-in help. Global options such as `--vault FILE` precede the command. Arguments after the harness name belong to that harness, including `--help`:

```text
ssjack -p home run claude --help
```

This launches the harness after vault authorization; it does not show ssjack help.

## Create and edit records

```text
ssjack vault init
ssjack -p home add
ssjack list
ssjack -p home show
ssjack -p home edit
ssjack -p home remove
ssjack vault passwd
```

Each invocation that accesses credentials requests the secret interactively. No secret is accepted from arguments, environment variables, stdin pipes, or a persistent password cache. Initialization and secret changes require confirmation. Invalid syntax, help, and build-version output do not unlock the database.

`add` prompts without echo for SSH address (`host:port`, numeric port 1–65535), user, private-key source, verified server public-key file, and intended usage. Standard OpenSSH/PEM private keys and ssjack containers can be imported. Encrypted sources require their own passphrase. Plaintext sources are accepted only as explicitly selected inputs; the source remains plaintext until separately retired. The database copy is encrypted, never written through a plaintext editor or staging file.

`edit` uses the same hidden prompts; Enter preserves existing values. `show` intentionally displays connection metadata, usage, and server fingerprints, never private bytes. `list` prints sorted labels only. `remove` requires typing the record name again and does not remove remote authorized keys or old backups.

Labels use 1–64 ASCII letters, digits, dots, underscores, or hyphens, beginning with a letter or digit. The database supports up to 64 records within a 64 KiB plaintext payload limit. Private files use Unix mode `0600`; Windows users must protect the directory/file DACL separately.

## Human and agent usage

```text
ssjack -p home ssh
ssjack -p home run claude -c
ssjack --vault .ssh/work.ssjack.ktav run work claude -c
```

The usage field is `both`, `human`, or `agent`. Human SSH rejects agent-only records; coding-agent launch rejects human-only records before connection or harness startup. Administrative CLI operations can inspect and maintain either kind after vault authorization.

This is an accident-prevention policy, **not a server-side sandbox or readonly shell**. Separate remote SSH accounts, key restrictions, and container/VM isolation enforce actual privileges. A record named `readonly` does not make arbitrary shell commands safe. ssjack does not create remote accounts, grant sudo, or configure Incus on its own.

Older records without a usage field mean `both`. The reader accepts the original four fields and the known optional usage field, rejecting unknown fields. Writes preserve the old four-field representation when no explicit usage exists. An older strict reader rejects policy-bearing five-field records instead of silently ignoring the policy. Keep an encrypted backup before adopting new metadata; the key-container encryption profile is unchanged.

The keeper unlocks once per launcher invocation and exposes only the selected profile through MCP. The bridge receives neither the private key nor the vault secret. Global `-p NAME` defaults to `main`; an unknown profile never selects another record. Plaintext target metadata is accepted only by explicit migration, never by normal startup.

## Keys and interoperability

```text
ssjack --generate-key .ssh/derived.ssjack.ktav
ssjack --protect-key existing-key --key-output .ssh/protected.ssjack.ktav
ssjack -p home key import existing-key.pem
ssjack -p home key export exported-key
ssjack -p home key public > home.pub
```

`key import` replaces only a key in an existing record and preserves address, user, usage, and server pins. For a new record, use `add`. Inputs are never rewritten or deleted. Unsupported key formats fail explicitly.

`key export` creates a new encrypted OpenSSH private-key file and never prints the private key. A confirmed nonempty export passphrase **must differ from the vault secret**. Standard OpenSSH protection is not the custom four-Argon2id/1000-layer profile. Reusing the vault secret would let the weaker export act as a cheaper password oracle for the whole database, so the CLI refuses it. Existing output paths are not overwritten. Public output is deliberately unencrypted and may be redirected.

Generation derives Ed25519 bytes from the typed secret plus fresh public parameters, not a random replacement seed. The secret alone does not recover lost parameters; back up the container/database. See [KEYS.md](KEYS.md).

## Diagnostics

```text
ssjack doctor
ssjack -p home check
```

`doctor` reports build version/commit/platform, vault integrity, private-file permissions, MCP registration, binary resolution, and managed UI asset consistency. It does not fix settings, install plugins, execute a PATH-resolved binary, connect to SSH, or launch a harness. Missing first-run registration/assets are warnings because normal launcher startup installs them. Windows DACL privacy and actual harness render support are explicitly not falsely certified by a Unix-mode check or asset hash.

`check` verifies the saved server pin, SSH authentication, and session opening without a remote command or PTY. Unknown/changed host keys fail. The native client never starts an external SSH executable or agent.

## Explicit container format upgrade

```text
ssjack vault upgrade
ssjack --vault .ssh/work.ssjack.ktav vault upgrade
```

New databases use opaque v2. Existing v1 databases remain readable and retain v1 during ordinary edits and password changes. Upgrade requests the vault secret, authenticates/schema-validates the original, generates a fresh v2 container, and decrypts it again to verify exact payload equality. Only after typing `UPGRADE` does it preserve the exact v1 ciphertext in an encrypted `before-upgrade` recovery file and perform revision-checked replacement. The secret, SSH keys, and records stay unchanged. Already-v2 invocations authenticate and check the revision without rewriting or creating another copy.

The one-field v2 outer envelope removes readable algorithm/cost metadata, not algorithms from public source or observable network/file metadata. Backup/restore copy exact ciphertext and do not silently upgrade it. Keep the recovery copy for rollback; an old binary cannot read v2 and may also reject newer record fields. Other backups/exports retain their prior protection. No real database is upgraded merely by installing new source. See [the format specification](OPAQUE-FORMAT-PROPOSAL.md).

## Backup, verification, and restore

```text
ssjack vault backup backups/home.ssjack.ktav
ssjack vault check backups/home.ssjack.ktav
ssjack vault restore backups/home.ssjack.ktav
```

Create the backup directory yourself. Backup authenticates and validates the database, then copies exactly the verified ciphertext to an exclusive new file and flushes it. No private payload is staged as plaintext. `vault check` requests the backup secret and verifies the profile, authentication, schema, and keys without modifying files or making network connections.

Restore validates the source and, when present, the current database with their respective secrets **before** asking for exact `RESTORE` confirmation. It preserves a uniquely named encrypted previous copy before a same-directory revision-checked replacement. Source backups and recovery copies are retained. A conflict or failure does not delete the current file to make replacement succeed. A missing destination is created exclusively. Source and destination cannot be the same file.

The restored database uses the **backup's secret**, not necessarily the previous current secret. Old copies keep their old protection. Deletion is not guaranteed secure erasure from storage, snapshots, or external backups.

Writers cooperate through an exclusive `.lock` and a ciphertext revision hash. An abandoned lock is not removed automatically. These mechanisms do not isolate against a targeted same-user process ignoring the protocol. Filesystem power-loss and rename semantics remain OS-dependent, especially on Windows. Cancellation is checked after expensive KDF work and before publication; an Argon2id invocation itself is not interruptible.

## Server identity pins

```text
ssjack -p home hostkey show
ssjack -p home hostkey replace verified-server-key.pub
```

These commands concern **server** keys, not client login keys. Replacement reads one bare OpenSSH public key already verified through an independent trusted channel, shows old/new fingerprints, and requires typing the new fingerprint. It replaces all existing pins for the record while preserving other fields. It does not scan the network, accept a mismatch automatically, or enable certificate/CA trust implicitly.

## Two-phase key rotation

```text
ssjack -p home rotate
```

Automatic rotation is intentionally narrow: a POSIX account using an existing regular `~/.ssh/authorized_keys` with an unrestricted bare old key. Per-key options such as `command=`, `from=`, or `restrict`, symlinks, and nonstandard key sources require manual rotation; they are refused instead of being silently stripped.

1. Verify current SSH login using the saved server pins, without a remote command.
2. Ask for a confirmed new key-recovery secret and derive a new Ed25519 identity with the unchanged heavy scheme.
3. Preserve an encrypted database snapshot and an encrypted new-key recovery container before any remote mutation.
4. Show old/new client fingerprints and require typing the record name.
5. Through the pinned native client, run a fixed installation script with only public keys on stdin. The script cooperatively locks the key file, preserves old bytes, safely adds a newline when needed, and is idempotent for the same public key. It never removes the old key.
6. Verify new SSH authentication and session opening without an exec/PTY request.
7. Only then switch the encrypted record using the original revision and atomic writer.

If addition, verification, cancellation, or local commit fails, old access is retained and recovery files remain. A new public key may already be installed even if the local switch fails; the diagnostic states that recovery path. Concurrent local edits cause a conflict rather than a lost update. Recovery filenames are printed, and the new-key container uses the separately entered recovery secret.

Even after success, **old remote keys are not retired automatically**. Verify every intended client and remove obsolete authorized keys explicitly through a trusted session. Rotation does not grant privileges or bypass forced-command restrictions.

## Trust and verification boundaries

Stored data uses four sequential Argon2id operations at 1 GiB each, followed by 1000 nested AES-256-GCM **data encryptions**. This custom composition is not independently audited and does not imply 1000-fold password resistance: the outer GCM tag supplies a candidate-secret check. Go/OS memory copies, swap, dumps, debuggers, and same-user process inspection remain outside strong isolation guarantees.

Keeper IPC listens only on `127.0.0.1`/`tcp4`; the bridge rejects DNS names, aliases, other IPs, and invalid ports before TLS/dial. TCP peers must be loopback before authentication. TLS pinning and single-use two-part capabilities remain mandatory. This does not block keeper SSH to approved servers and is not an OS firewall.

Unit tests, synthetic SSH servers, transaction failure fixtures, POSIX script tests, installer tests, race checks, and the dedicated real-1-GiB profile run belong in GitHub CI. Defining or writing a test is not a passed result. See [AUDIT.md](AUDIT.md) for the external-review boundary.

## Default profile selection

Every profile-scoped command uses global `-p NAME` / `--profile NAME`, defaulting to `main`. Profile names are not ambiguous positional arguments: use `ssjack ssh`, `ssjack run claude -c`, `ssjack edit`, or select another with `ssjack -p work run claude -c`. An absent `main` is an error even when another profile is the only available record; no fallback occurs.

First `vault init` asks for complete connection credentials and stores the selected profile (`main` by default) only after successful validation. Existing databases are not silently renamed or populated. Vault-wide backup/list/check operations do not reveal profile values without authorization. Named profiles remain encrypted at rest; a name explicitly supplied through argv can still be visible in process listings and shell history.

## Legacy metadata migration boundary

Normal startup accepts profiles only from the encrypted database. `--config` is not a supported startup option. An old plaintext metadata file can be consumed only by explicit `ssjack [-p PROFILE] vault migrate LEGACY_FILE`, defaulting to destination profile `main`.

Migration asks for database authorization (or a confirmed new database secret), source key authorization when needed, and explicit destination-profile confirmation. It imports address/user/private key bytes and only raw server keys already trusted for the exact legacy address/port, including supported hashed known_hosts entries; revoked, unrelated, CA-only, or missing trust is not accepted. No network scan or connection supplies migration trust. Existing destination profiles are never overwritten. Existing databases receive encrypted recovery snapshots before the new profile is committed.

Source metadata, source private-key files, and old copies are never silently deleted. They can still expose metadata until the user separately retires them after verifying the encrypted profile. The assistant cannot perform real migration without the user's terminal-only secrets and does not read real private keys through tools.

## Encrypted SSH policy

`ssjack [-p PROFILE] policy show` displays this profile's preferences only after database authorization. `policy edit` uses hidden interactive input for host-key algorithms, key exchanges, ciphers, and MACs. Empty values preserve existing settings; `default` resets a list. Values are stored only in the authenticated encrypted record, never in a new plaintext configuration file or command-line options.

The pinned SSH library's `SupportedAlgorithms()` lists define accepted algorithms; unknown, duplicate, and insecure choices are rejected rather than silently ignored by ssh.Config. Default connections use those supported lists explicitly. Host-key pinning remains mandatory and independent of the chosen negotiation algorithms. This changes SSH negotiation preferences, not the four-Argon2id/1000-data-layer storage profile.

The optional known `ssh_policy` object is a payload extension. Older strict readers reject it rather than ignoring it. Original records without usage/policy fields retain safe compiled defaults. Always preserve an encrypted backup before saving extended metadata. Supported algorithm names are not secrets cryptographically; traffic observers can see parts of SSH negotiation, and hiding a filename cannot hide the destination IP from the OS/network.

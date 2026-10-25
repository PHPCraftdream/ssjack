# ssjack

A cross-platform Go SSH client, encrypted credential manager, key utility, and scoped MCP bridge for coding agents. SSH runs inside the keeper; private keys and vault secrets are not exported to an external SSH executable, agent, harness, or MCP bridge.

## Main workflows

Using an executable built from the current source, from your application directory:

```text
ssjack --version
ssjack vault init
ssjack add home
ssjack ssh home
ssjack run home claude -c
```

The same named record is used for human and agent sessions. Every credential-management invocation asks for its secret again. A coding-agent launcher unlocks once for that session and exposes only its selected record through a pinned loopback connection with a single-use two-part capability. Human SSH behaves like a normal PTY session after login.

Help is deliberately detailed:

```text
ssjack help
ssjack help key export
ssjack vault restore --help
```

Each command explains its arguments, trust boundaries, and examples. Global flags precede the command. Everything after the harness name belongs to the harness, including `--help`.

## Records, keys, and diagnosis

```text
ssjack list
ssjack show home
ssjack edit home
ssjack remove home
ssjack key public home
ssjack key import home existing-key.pem
ssjack key export home home.openssh
ssjack doctor
ssjack check home
```

Records contain encrypted addresses, users, private keys, server pins, and optional `both`/`human`/`agent` usage. Usage gates prevent selecting the wrong record accidentally; real readonly/admin privileges require separate server accounts and isolation, not string filtering of shell commands.

`doctor` is read-only and checks local readiness after vault authorization. `check` verifies server trust and SSH authentication without running a remote command or opening a PTY. OpenSSH private exports are encrypted, exclusive new files and require a passphrase different from the vault secret. Source keys are never overwritten or deleted by import.

## Recovery and rotation

```text
ssjack vault backup backups/home.ssjack.ktav
ssjack vault check backups/home.ssjack.ktav
ssjack vault restore backups/home.ssjack.ktav
ssjack hostkey show home
ssjack hostkey replace home verified-server-key.pub
ssjack rotate home
```

Create backup parent directories yourself. Backups stay encrypted; restore validates before confirmation, retains the previous encrypted copy, and refuses revision conflicts. Server pin replacement requires independent verification and exact fingerprint confirmation, never automatic acceptance of a mismatch.

Rotation preserves recovery files, explicitly confirms remote addition, retains the old authorized key, verifies the new login, and only then switches the vault record. Option-bearing keys and nonstandard authorized-key locations require manual handling rather than silently losing restrictions. Old remote keys are never removed automatically.

## Protected key generation

```text
ssjack --generate-key .ssh/derived.ssjack.ktav
ssjack --protect-key existing-key --key-output .ssh/protected.ssjack.ktav
```

Stored data uses four sequential Argon2id operations at 1 GiB each and **1000 nested AES-256-GCM data encryptions**. Derived Ed25519 bytes depend on the typed secret and fresh public parameters; retain the encrypted container/database because the secret alone does not recover lost parameters.

This custom composition is **not independently audited**. The outermost GCM tag is a candidate-secret oracle, so 1000 layers do not imply 1000-fold password resistance. Strong secret entropy remains essential. See [the audit review package](docs/AUDIT.md).

## Installation and compatibility

[Global installers and the release contract](docs/RELEASES.md) are provided as source. They require a real published GitHub Release; writing a workflow does not publish one. No binary release or installed executable update is implied by source changes.

CI builds the CLI with the Go version in `go.mod` and embeds build identity. From a compiled checkout, `./ssjack.sh` or `.\ssjack.cmd` locates the local `build/ssjack` executable without building automatically. The launcher installs its embedded project-local UI plugin for compatible Claude Code builds and preserves unrelated settings/hooks/plugins.

The default database is `.ssh/credentials.ssjack.ktav`; `--vault FILE` selects another. Legacy plaintext target metadata requires explicit `--config FILE`; no automatic fallback occurs. Older OpenSSH wrappers are removed. Existing keys/configuration are not silently migrated.

## Security boundaries

This is not isolation from a targeted process running as the same OS user. Administrators, debuggers, memory dumps, swap, and internal Go copies remain relevant. Accessible buffers are cleared best-effort; unlocked signers remain in keeper memory for the session. A process stealing both bootstrap secrets before attachment can race the bridge.

IPC is restricted to canonical `127.0.0.1`/`tcp4`, with numeric-port and loopback-peer checks before authentication, pinned TLS 1.3, and atomic single-use capabilities. SSH outbound is performed only by the keeper for the selected approved credentials. These controls are not an OS firewall.

Commands run with the remote account's permissions. Use least-privilege users and VM/container boundaries. Do not expose administrative Incus sockets to service agents. Closing SSH does not necessarily terminate detached processes. Remote output and deliberately displayed metadata can contain sensitive information; cards are not an immutable audit log.

## Verification and documentation

All test and build execution belongs in GitHub CI, not local development. The matrix covers Linux/macOS/Windows, Linux race detection, native CLI/installer fixtures, a dedicated production-1-GiB encrypted-vault integration path, command/help regression tests, and synthetic SSH servers. Writing tests is not evidence of a passing run. UI tests require a compatible authoring environment and are not replaced by fake checks.

- [Credential commands, recovery, and rotation](docs/VAULT.md)
- [Key format and derivation details](docs/KEYS.md)
- [Cryptographic audit scope and known limitations](docs/AUDIT.md)
- [Architecture, MCP bootstrap, and updates](SSJACK.md)
- [SSH interoperability and server trust](SSH.md)
- [Release assets and installers](docs/RELEASES.md)
- [UI plugin development](plugins/ssjack-ui/README.md)

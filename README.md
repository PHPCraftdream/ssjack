# ssjack

[![CI](https://github.com/PHPCraftdream/ssjack/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/PHPCraftdream/ssjack/actions/workflows/ci.yml)
[![Go](https://img.shields.io/github/go-mod/go-version/PHPCraftdream/ssjack?logo=go)](go.mod)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](docs/INSTALL.md)
[![Status](https://img.shields.io/badge/status-experimental-orange)](#security-boundaries)

**Native SSH for humans and coding agents, with encrypted profiles and explicit trust boundaries.**

ssjack is a cross-platform Go SSH client, encrypted credential manager, key utility, and scoped MCP bridge. SSH runs inside the keeper; private keys and vault secrets are not exported to an external SSH executable, agent, harness, or MCP bridge.

> **Experimental, security-sensitive software.** The custom encrypted container is not independently cryptographically audited. A green CI badge is regression evidence, not a security certification or a promise of production readiness.

## Features

- One encrypted profile database for native interactive SSH and coding-agent sessions.
- Memory-only bootstrap with a single-use capability over pinned loopback TLS; no runtime credential files.
- Local Ed25519 generation directly into a profile, plus public-key installation instructions with PTY enabled.
- Verified backups, explicit restore/rotation, server pins, and human/agent usage guards.
- Command/result cards for compatible Claude Code builds, with ordinary MCP support for other harnesses.
- Windows, Linux, and macOS installers that replace running images without stopping processes.

[Installation](docs/INSTALL.md) · [CLI guide](docs/VAULT.md) · [Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md)

## Quick start

Using an executable built from the current source, from your application directory:

```text
ssjack --version
ssjack vault init --generate-key
ssjack -p home add --generate-key
ssjack -p home check
ssjack -p home ssh
ssjack -p home run claude -c
```

Create the database's parent directory first. The wizard needs an existing remote account and an independently verified server public-key file; it does not automatically create a remote user or trust a scanned key. Generated private keys stay in the database. After save, copy the printed public-key installation command to the intended remote account through an already trusted connection. Omit `--generate-key` to import an existing key instead.

The same named record is used for human and agent sessions. Every credential-management invocation asks for its secret again. A coding-agent launcher unlocks once for that session and exposes only its selected record through a pinned loopback connection with a single-use environment capability without bootstrap files. Human SSH behaves like a normal PTY session after login.

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
ssjack -p home show
ssjack -p home edit
ssjack -p home remove
ssjack -p home key public
ssjack -p home key import existing-key.pem
ssjack -p home key export home.openssh
ssjack doctor
ssjack -p home check
```

Records contain encrypted addresses, users, private keys, server pins, and optional `both`/`human`/`agent` usage. Usage gates prevent selecting the wrong record accidentally; real readonly/admin privileges require separate server accounts and isolation, not string filtering of shell commands.

`doctor` is read-only and checks local readiness after vault authorization. `check` verifies server trust and SSH authentication without running a remote command or opening a PTY. OpenSSH private exports are encrypted, exclusive new files and require a passphrase different from the vault secret. Source keys are never overwritten or deleted by import.

## Recovery and rotation

```text
ssjack vault backup backups/home.ssjack.ktav
ssjack vault check backups/home.ssjack.ktav
ssjack vault restore backups/home.ssjack.ktav
ssjack -p home hostkey show
ssjack -p home hostkey replace verified-server-key.pub
ssjack -p home rotate
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

[Global installers](docs/INSTALL.md) accept a real published GitHub Release or a verified local CI artifact with an explicit SHA-256. Writing a workflow does not publish a release, and source changes alone do not update an installed executable. See the [release contract](docs/RELEASES.md) for asset naming and publisher trust.

The canonical Go module is `github.com/PHPCraftdream/ssjack`; `go.mod` declares the minimum Go version and CI selects that declared toolchain. No stable binary release is implied by this development snapshot.

If you explicitly prefer source installation, the following compiles locally using the declared Go toolchain:

```sh
go install github.com/PHPCraftdream/ssjack/cmd/ssjack@latest
```

`@latest` currently selects a development snapshot, not a stability promise; use a reviewed commit when you need a fixed source revision. CI artifacts embed the exact checkout SHA. Builds without those linker flags can identify themselves as `dev`/`unknown`.

CI builds the CLI with the Go version in `go.mod` and embeds build identity. Run the globally installed `ssjack` from the desired application working directory; source checkout launchers and local-build update wrappers are no longer needed. The launcher installs its embedded project-local UI plugin for compatible Claude Code builds and preserves unrelated settings/hooks/plugins.

The default database is `.ssh/credentials.ssjack.ktav`; `--vault FILE` selects another. Normal startup never reads plaintext target metadata; explicit `vault migrate FILE` is the only legacy import path. Older OpenSSH wrappers are removed. Existing keys/configuration are not silently migrated.

## Security boundaries

This is not isolation from a targeted process running as the same OS user. Administrators, debuggers, memory dumps, swap, and internal Go copies remain relevant. Accessible buffers are cleared best-effort; unlocked signers remain in keeper memory for the session. A process stealing the full child bootstrap environment before attachment can race the bridge; bootstrap now uses one environment capability, not separate environment/file channels.

IPC is restricted to canonical `127.0.0.1`/`tcp4`, with numeric-port and loopback-peer checks before authentication, pinned TLS 1.3, and atomic single-use capabilities. SSH outbound is performed only by the keeper for the selected approved credentials. These controls are not an OS firewall.

The current full MCP `remote_*` tools execute commands with the configured remote SSH principal's authority. A name such as `mcp-agent` does not establish that principal as non-admin: the operator controls server-side sudo rules, groups, socket access and backend memberships, which may permit host-root or equivalent access. For optional Incus routing, the selected host principal must be authorized for the fixed `sudo -n incus exec` operation, and the configured guest user has its guest privileges. Application registration fixes program selection against model substitution in tool arguments, but the admitted Clawwright entry/package and host-side paths remain trusted mutable code, not a sandbox. Admitted `app_exec` commands, including secret-reporting commands, may perform general operations or expose values. Output capture masks only exact child bootstrap-token occurrences; it is not general secret redaction. Safe SSH-key custody and captured output are no guarantee of secret nondisclosure.

A Docker/Incus administrator socket or sudo rule, or an alternate SSH channel available to trusted code, may bypass a future restricted API. A future declarative MCP would be a separate authorization and dispatch surface; it is not a relabeling or restriction of `app_*` or current `remote_*`. Until then, enforce least privilege in the operator-controlled host, guest and backend configuration. Closing SSH does not necessarily terminate detached processes; output and metadata can contain sensitive information. See [scoped application transport](docs/APP-TRANSPORT.md).

## Verification and documentation

Project validation builds and tests run in GitHub CI, not automatically on a contributor's machine. Local work normally needs only formatting; source installation is an explicit operator choice, not permission for an assistant to run local builds without approval. The matrix covers Linux/macOS/Windows, Linux race detection, native CLI/installer fixtures, a dedicated production-1-GiB encrypted-vault integration path, command/help regression tests, and synthetic SSH servers. Writing tests is not evidence of a passing run. UI tests require a compatible authoring environment and are not replaced by fake checks.

- [Credential commands, recovery, and rotation](docs/VAULT.md)
- [Key format and derivation details](docs/KEYS.md)
- [Cryptographic audit scope and known limitations](docs/AUDIT.md)
- [Architecture, MCP bootstrap, and updates](SSJACK.md)
- [SSH interoperability and server trust](SSH.md)
- [Release assets and installers](docs/RELEASES.md)
- [UI plugin development](plugins/ssjack-ui/README.md)

## Legacy metadata migration boundary

Normal startup accepts profiles only from the encrypted database. `--config` is not a supported startup option. An old plaintext metadata file can be consumed only by explicit `ssjack [-p PROFILE] vault migrate LEGACY_FILE`, defaulting to destination profile `main`.

Migration asks for database authorization (or a confirmed new database secret), source key authorization when needed, and explicit destination-profile confirmation. It imports address/user/private key bytes and only raw server keys already trusted for the exact legacy address/port, including supported hashed known_hosts entries; revoked, unrelated, CA-only, or missing trust is not accepted. No network scan or connection supplies migration trust. Existing destination profiles are never overwritten. Existing databases receive encrypted recovery snapshots before the new profile is committed.

Source metadata, source private-key files, and old copies are never silently deleted. They can still expose metadata until the user separately retires them after verifying the encrypted profile. The assistant cannot perform real migration without the user's terminal-only secrets and does not read real private keys through tools.

## Community and support

Read [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md) before opening an issue or pull request. Use the issue templates for redacted synthetic reproductions and focused proposals. Report vulnerabilities privately through [SECURITY.md](SECURITY.md); never attach real vaults, private keys, tokens, or private host details to a public issue.

## License

Project-owned code and documentation are dual-licensed under **MIT OR Apache-2.0**, at your option. See [LICENSE](LICENSE), [LICENSE-MIT](LICENSE-MIT), and [LICENSE-APACHE](LICENSE-APACHE).

Dependencies retain their own terms in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). The notices are embedded in distributed executables and can be printed without unlocking credentials:

```text
ssjack --licenses
```

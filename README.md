# ssjack

[![CI](https://github.com/PHPCraftdream/ssjack/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/PHPCraftdream/ssjack/actions/workflows/ci.yml)
[![Go](https://img.shields.io/github/go-mod/go-version/PHPCraftdream/ssjack?logo=go)](go.mod)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](docs/INSTALL.md)
[![Status](https://img.shields.io/badge/status-experimental-orange)](#security-boundaries)

**Native SSH, an encrypted server/secret directory, and explicitly scoped access for coding agents.**

ssjack is a Go SSH client, credential manager, Bubble Tea terminal interface,
key utility, and MCP keeper. SSH runs inside ssjack: a harness receives neither
SSH private keys/passwords nor the database master. Application-secret delivery
has separate, finite authorization; unrestricted SSH output is **not** secret-safe.

> **Experimental, security-sensitive software.** The custom encryption composition
> is not independently audited. Passing CI is regression evidence, not security
> certification, a published release, or proof that an application adopted a config.

[Install](docs/INSTALL.md) · [All capabilities and documentation](docs/README.md) ·
[Credential guide](docs/VAULT.md) · [Security](SECURITY.md)

## Capabilities

| Area | Available behavior |
| --- | --- |
| Encrypted directory | Named servers with stable IDs; multiple named SSH accounts per server; key **or** login/password authentication; verified host-key pins and per-account usage/policy. |
| Interactive terminal | Explicit `--interactive` Bubble Tea connection picker, manual credential entry, server/account edits, global/server-local secrets, exports, imports, pending-change recovery. One database unlock per owner session. |
| Connection choice | No automatic connection, even for one point. Enter selects human SSH; management stays reachable in an empty database. Named startup selectors are also available. |
| Persistence | Validated RAM edits, ordered encrypted background saves, visible save/error state, explicit retry/recovery, fresh nonces and unchanged data-encryption layers. |
| Migration and recovery | Credential-preserving directory migration, independent container upgrade, encrypted backups, verified restore, password changes, and recovery copies. |
| Keys and trust | Derived Ed25519 generation, key import/encrypted OpenSSH export, public-key output/install instructions, explicit server-pin replacement, SSH policy and two-phase key rotation. |
| Native SSH | Human PTY shell with terminal resize; no external SSH client or forwarded SSH agent. `check` verifies pins/authentication without a remote command. |
| Coding-agent access | One selected credential, pinned loopback TLS, single-use bootstrap, bounded `remote_*` jobs, read/cancel, compatible project-local command/result cards. |
| Application operations | Opt-in Clawwright registration and finite `app_*` jobs; optional fixed Incus route. This remains trusted shell-capable application code, not a sandbox. |
| Application secrets | Separate encrypted versioned store, exact placeholder refs, private owner CRUD, global/server-local bindings and controlled value export/import. |
| Text deploy/backup | Separately granted hydration and reference-only reverse copy; v1 bounded text or opt-in v2 streaming up to 64 MiB. Real paired Clawwright CLI/keeper/SSH acceptance. |
| Declarative slice | Separate Linux/amd64 root-granted synthetic metadata and delivery paths. The general declarative driver/enrollment contract remains a proposal. |
| Distribution | Windows/Linux/macOS installers, verified release/local candidates, embedded build identity and third-party license notices. |

The database-password holder owns its contents. Multiple SSH accounts do **not**
create a multi-owner RBAC system. Credentials remain in the encrypted database;
named application-secret bindings point to values in the separate store.

## Start with the terminal menu

Run from the application working directory. The default database is
`.ssh/credentials.ssjack.ktav` **relative to that directory**, not automatically
relative to your home or the executable. `--vault FILE` selects another file.

For a new installation, create the parent directory, initialize a first legacy
profile with verified server pins, then explicitly migrate to the directory schema:

```sh
ssjack vault init --generate-key
ssjack vault migrate-directory .ssh/directory.ssjack.ktav
ssjack --vault .ssh/directory.ssjack.ktav --interactive
```

`vault init` prompts for an existing remote login and independently verified server
public-key file. It does not create users, grant sudo or discover trust. Omit
`--generate-key` to import an existing key. Generated private bytes stay encrypted;
only the public key and installation instructions are printed after save.

In the menu:

- Press **Enter** on a connection point to connect; showing or focusing one never connects.
- Open **Servers** to add/edit a server or add/edit its SSH accounts.
- For password authentication, enter the password in the hidden credential field.
  For key authentication, select an existing private-key file; direct multiline
  private-key paste is not implemented.
- Use **Global secrets** or a server's **Server secrets** for explicit scopes.
  Value operations require a linked, already provisioned application store.
- Use **Export all credentials and values** or scoped export from server/account/global pages.
- Use **Import credentials and values** for archive inspection, preview and exact `IMPORT` confirmation.
- Use arrows, Tab/Shift+Tab, Escape and the Apply/Cancel buttons. Exit waits for saves;
  unresolved persistence errors are not silently discarded.

Only `--interactive` opens the menu. Missing commands and terminal detection do not.
After a supported SSH handoff the menu resumes without another database unlock.
If terminal input cannot be released, ssjack closes safely rather than starting a
competing reader; Windows VT consoles may require restarting ssjack after SSH.

See [the menu guide](docs/application-store/OWNER-TUI.md) for exact fields and limits.

## Migrate an existing database and keep its usual path

Stop all processes that could write the database. Migration first creates a
**different** verified encrypted file; it never replaces the source automatically:

```sh
ssjack --vault .ssh/credentials.ssjack.ktav vault migrate-directory .ssh/directory-new.ssjack.ktav
```

Enter the existing database password and confirm `MIGRATE DIRECTORY`. Each old
profile becomes a separate server with one `main` account, even if addresses match.
The source ciphertext and credentials are preserved, and the password is unchanged.

To let existing launch commands find the result automatically, put the verified
replacement at the **old path**, keeping the old file as a rollback copy. Follow
[the guarded PowerShell/POSIX switching instructions](docs/VAULT.md#activate-the-new-database-at-the-old-path).
There is no automatic path switch or background migration. Old binaries must use
the original database; downgrading the new payload is not a rollback strategy.

`vault migrate LEGACY_FILE` imports old plaintext SSH metadata instead.
`vault upgrade` changes the encrypted **container** format. These are three
separate operations; installing a binary performs none of them.

## Select a connection without the menu

```sh
ssjack --server production --account operator ssh
ssjack --server production --account automation run claude -c
ssjack --server production --account operator check
ssjack --interactive --server production --account operator
```

Names are exact and case-sensitive. A server without `--account` is accepted by
non-menu connection commands only when it has exactly one account; ambiguity and
unknown names refuse. Menu selectors only focus a page, never connect automatically.
`-p NAME` / `--profile NAME` selects a credential-record ID and defaults to `main`;
it cannot be combined with `--server`. Use the menu for directory edits.

Global flags precede the command. After `run HARNESS`, all arguments belong to the
harness, including `--help`. A normal SSH or harness invocation unlocks its selected
credentials once; the separate owner menu retains one RAM session across edits.

## Export, import, backups and maintenance

Owner export is a ZIP containing the **selected credentials, settings and actual
secret values**, not just refs. It is encrypted by default. Plaintext export
requires exact `EXPORT PLAINTEXT`, uses exclusive protected output, and is an
intentional final artifact. Import accepts both formats, uses RAM-only inspection,
shows metadata/conflicts and requires exact `IMPORT`. No silent overwrite or
merge by endpoint/name occurs. Linked installation unlock material is not exported.

A partial import is not success. Resolve its pending owner intent, then explicitly
resume or abort. Abort keeps already applied entries. Remaining plan values are
RAM-only and cannot be resumed after process restart; individual queued owner
intents remain encrypted and recoverable. Linked-value operations are Linux-only.

For whole-database recovery and key maintenance:

```sh
ssjack vault backup backups/before-maintenance.ssjack.ktav
ssjack vault check backups/before-maintenance.ssjack.ktav
ssjack vault restore backups/before-maintenance.ssjack.ktav
ssjack vault passwd
ssjack -p main key public
ssjack -p main key import existing-key.pem
ssjack -p main key export new-encrypted.openssh
ssjack -p main hostkey show
ssjack -p main hostkey replace independently-verified-server.pub
ssjack -p main policy show
ssjack -p main policy edit
ssjack -p main rotate
ssjack doctor
```

Create destination directories first. Private-key OpenSSH exports need a distinct
passphrase and are not equivalent to the custom encrypted database backup.
Rotation is key-only, retains old remote keys and requires explicit approval before
remote addition. `doctor` is local/read-only; host-key replacement is never TOFU.
See [the full credential guide](docs/VAULT.md).

## Application secrets and selected-text delivery

The [application-store guide](docs/application-store/ENTRY.md) covers provisioning,
`appstore setup|put|inspect|unlock`, private owner changes and exact references.
Setup does not enroll a service; `put` is first-entry only. Owner editing links an
existing authenticated installation, not an automatically created backend.

The [text adapter](docs/application-store/TEXT-ADAPTER.md) has its own root-approved
grants. `text-adapter serve` serves v1; `serve-stream` serves separate forward or
reverse v2 grants. Metadata, CLI flags and a parsed reference are **not approval**.

For v2, Clawwright uses the single valued `--stream-references PATH` option on
`deploy-text` / `backup-text`; the file contains exact canonical refs, never values.
There is no v1 fallback. Streaming uses bounded 32 KiB frames with 64 MiB decoded
input/output caps, at most 16 refs and 1 MiB selected values. Backup publishes only
a validated reference-only copy, never modifies the remote source and never
replaces an existing local output. Restore reuses captured exact refs.

Hydration is literal, single-pass, leftmost-longest and nonrecursive; it is not a
JSON/YAML escaping engine or a secret-discovery service. The operator owns mapping
completeness, file selection, representation and consumer compatibility. Explicitly
approved consumer plaintext configuration is permitted. `withheld` means pre-run
refusal, `received` is delivery evidence, and `unknown` may follow effects: no blind
retry, adoption claim or crash-durability guarantee follows from a receipt.

[Streaming and HTTP](docs/application-store/TEXT-STREAM-HTTP.md) ·
[Clawwright paired acceptance](docs/application-store/CLAWWRIGHT-TEXT-PAIR.md) ·
[General application transport](docs/APP-TRANSPORT.md)

## Security boundaries

Stored credentials retain **four sequential Argon2id operations, each 1 GiB,
followed by 1000 nested AES-256-GCM data encryptions**. Retained session keys avoid
repeating the KDF on every edit, not the 1000 encryption layers. Fresh nonces are
used on saves. This composition is not independently audited; 1000 layers do not
imply 1000-fold password resistance because the outer GCM tag is a candidate-secret
oracle. Keep strong passwords and encrypted recovery copies.

Root, the same OS user, trusted application code, debuggers, swap and dumps are
not isolated by ssjack. Memory clearing is best-effort within Go and the OS.
The primary bridge uses numeric loopback, pinned TLS 1.3 and a single-use child
bootstrap capability; it is not an OS firewall. Full `remote_*` and registered
`app_*` operations can execute broad commands and expose remote values in output.
`human`/`agent` usage is accident prevention, not server-side privilege enforcement.
Only separate server accounts, permissions and isolation establish least privilege.

Application-store and root-granted text/declarative runtimes have additional
Linux/amd64 constraints. General driver enrollment, universal restricted execution,
OpenClaw/provider adoption, automatic server hardening and secret discovery are
not implemented by these narrow paths. See [SECURITY.md](SECURITY.md),
[the audit scope](docs/AUDIT.md) and [the capability map](docs/README.md).

## Installation, verification and support

The repository root includes build-and-install entry points for all supported OSes:

```sh
sh ./build.sh                         # Linux/macOS; default /usr/local/bin
```

```powershell
.\build.ps1                          # Windows; current-user global PATH installation
```

They build this checkout with the local Go toolchain required by `go.mod`, embed
its commit, hash the native candidate and delegate publication to the verified
installer. No automatic elevation, process termination or database migration.
Use `--install-dir` / `-InstallDir` for an explicit destination and see
[installation permissions and source trust](docs/INSTALL.md#build-this-checkout-and-install-globally).

The installers also accept published release assets or an explicit local CI
artifact plus SHA-256. Source/CI acceptance alone does not update binaries or
create a release. Running processes retain their old code. Use a reviewed source
revision; `@latest` is not a stability promise.

Tests, builds and application acceptance run in public GitHub CI; local formatting
alone does not prove behavior. The matrix includes Linux/macOS/Windows, race tests,
real production-KDF fixtures, real Bubble Tea terminals and synthetic SSH peers.
[Full CI 41796602948](https://github.com/PHPCraftdream/ssjack/actions/runs/41796602948)
accepted source `0576409` with all nine jobs, including owner import/recovery and
the paired Clawwright v1/v2 paths. This is a source-specific receipt, not a promise
that every installed or future revision behaves identically.

```sh
ssjack help
ssjack help --interactive
ssjack help text-adapter
ssjack help vault migrate-directory
ssjack --version
ssjack --licenses
```

[Architecture](SSJACK.md) · [SSH interoperability](SSH.md) · [Release contract](docs/RELEASES.md) ·
[Contributing](CONTRIBUTING.md) · [Code of Conduct](CODE_OF_CONDUCT.md) · [UI plugin](plugins/ssjack-ui/README.md)

Never attach real vaults, passwords, private keys or tokens to issues. Report
vulnerabilities through [SECURITY.md](SECURITY.md).

## License

Project-owned code and documentation: **MIT OR Apache-2.0**. See [LICENSE](LICENSE),
[LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE).
Dependencies retain their own terms in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md);
`ssjack --licenses` prints embedded notices without unlocking the database.

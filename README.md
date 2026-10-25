# ssjack

A cross-platform Go SSH keeper, MCP bridge, and native interactive SSH client with encrypted credentials and separate command/result cards in Claude Code.

The launcher prompts once for the encrypted vault secret, selects one named credential record, starts the chosen harness, and authenticates one MCP bridge using two independent bootstrap secrets: one in the child environment and one in a temporary file. The pair is consumed on first attachment. The bridge never receives the private SSH keys or vault secret, and can use only the selected record.

## Quick start

Build with the Go version declared in `go.mod`:

```sh
go build -mod=readonly -trimpath -o build/ssjack ./cmd/ssjack
```

On Windows, use `-o build/ssjack.exe` instead. Create an encrypted vault and add a named credential record as shown below, importing a private key and a verified server public key. Never commit real keys, vaults, host-specific settings, or bootstrap credentials. Legacy plaintext target configuration remains available only through explicit `--config <file>`.

Run the desired harness:

```text
ssjack run storage claude -c
```

From a checkout, use `./ssjack.sh run storage claude -c` or `.\ssjack.cmd run storage claude -c`. When using the shorthand `ssjack <harness> [arguments...]`, the launcher unlocks the vault and offers a record selection (a single record is selected automatically). The launcher automatically installs its embedded, project-local UI plugin for Claude Code; it does not require a separate plugin installation. That UI requires a Claude Code build supporting function-hook render plugins. Other harnesses can use the MCP bridge but may need their own MCP registration format.

## Encrypted credentials and interactive SSH

Using an executable built from the updated source:

```text
ssjack --generate-key .ssh/derived-key.ssjack.ktav
ssjack vault init
ssjack vault add storage
ssjack ssh storage
ssjack run storage claude -c
```

The generated Ed25519 key is derived from the typed secret and fresh public parameters, not a random replacement seed. Key containers use four sequential Argon2id operations at 1 GiB each and **1000 nested AES-256-GCM encryptions of the data**. Keep the container backed up: the secret alone does not recover its random public parameters. This custom construction is not independently audited, and 1000 layers do not imply 1000-fold password-guessing resistance.

The interactive vault encrypts addresses, usernames, private keys, and trusted server keys. Each vault command and each `ssh` invocation requests the secret again; after login, the shell behaves normally. The Go client handles SSH itself without exporting keys to `ssh.exe`. The same named credentials are used for manual shell sessions and coding-agent/MCP sessions; the latter is restricted to the selected record. Existing legacy files are not migrated automatically. See [protected keys](docs/KEYS.md) and [vault commands and shell](docs/VAULT.md).

## Features

- Encrypted private keys on disk; decrypted signers remain in the keeper process.
- Loopback TLS 1.3 with certificate pinning and single-use bootstrap authentication.
- Preconfigured SSH targets with mandatory host-key verification.
- Asynchronous command execution, bounded output, offsets, cancellation, and timeouts.
- Automatic command/result cards and cleanup of obsolete ssjack display hooks.
- Pure-Go Ktav 0.8.1 for owned configuration, bootstrap, and internal messages.
- JSON only at required external boundaries such as MCP and Claude Code metadata.
- Rename-based executable updates with retained backups and rollback attempts.

## Security boundaries

This is not isolation from a targeted process running as the same OS user. A process that steals both bootstrap secrets before attachment can race the intended bridge. Administrators, debuggers, memory dumps, swap, and inherited environment variables remain relevant threats. There is no guaranteed erasure of every in-memory copy of a key or passphrase.

Commands run with the configured SSH user's permissions. Use least-privilege accounts and VM/container isolation for independent services. Do not expose a host's administrative Incus socket to service agents. Closing SSH does not necessarily stop detached remote processes.

The UI shows submitted commands and received chunks; it is not an immutable audit log. Remote output can contain secrets. The plugin does not alter model inputs, stored tool results, permissions, or SSH authentication.

## Documentation

- [Setup, architecture, limits, and updates](SSJACK.md)
- [Protected keys and secret-derived Ed25519 generation](docs/KEYS.md)
- [Encrypted credentials CLI and interactive SSH](docs/VAULT.md)
- [SSH compatibility and host trust](SSH.md)
- [UI plugin development](plugins/ssjack-ui/README.md)

[Global installers and the release-asset contract](docs/RELEASES.md) are provided as source. They require an actual GitHub Release; writing these scripts does not publish binary releases.

## Verification

Test runs and builds belong in GitHub CI, not local development. The Go jobs run these test commands; UI tests require a compatible authoring environment and separate authorization:

```text
go test -mod=readonly -count=1 -timeout 120s ./cmd/ssjack ./internal/... ./plugins/ssjack-ui
go test -mod=readonly -race -count=1 -timeout 120s ./cmd/ssjack ./internal/... ./plugins/ssjack-ui
claude plugin validate ./plugins/ssjack-ui
claude plugin test ./plugins/ssjack-ui
```

Go tests use generated temporary keys and a local test SSH server. Plugin tests use Claude Code's testing API and do not connect to user SSH servers. The GitHub CI workflow runs Go tests on Linux, Windows, and macOS; UI tests require the compatible Claude Code authoring environment and are not silently substituted with fake CI checks.

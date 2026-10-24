# ssjack

A cross-platform Go SSH keeper and MCP bridge with session-scoped access and separate command/result cards in Claude Code.

The launcher prompts once for the passphrase of encrypted SSH keys, starts the selected harness, and authenticates one MCP bridge using two independent bootstrap secrets: one in the child environment and one in a temporary file. The pair is consumed on first attachment. The bridge never receives the private SSH keys.

## Quick start

Build with the Go version declared in `go.mod`:

```sh
go build -mod=readonly -trimpath -o build/ssjack ./cmd/ssjack
```

On Windows, use `-o build/ssjack.exe` instead. Copy `.ssh/ssjack.example.ktav` to `.ssh/ssjack.ktav`, configure the SSH target, and prepare an encrypted key plus a verified `known_hosts` file. Never commit real keys, host-specific settings, or bootstrap credentials.

Run the desired harness:

```text
ssjack claude -c
```

From a checkout, use `./ssjack.sh claude -c` or `.\ssjack.cmd claude -c`. The launcher automatically installs its embedded, project-local UI plugin for Claude Code; it does not require a separate plugin installation. That UI requires a Claude Code build supporting function-hook render plugins. Other harnesses can use the MCP bridge but may need their own MCP registration format.

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
- [Separate manual OpenSSH wrappers](SSH.md)
- [UI plugin development](plugins/ssjack-ui/README.md)

Global installers from GitHub Releases are planned separately; this source import does not publish binary releases.

## Verification

```text
go test -mod=readonly -count=1 -timeout 120s ./cmd/ssjack ./internal/... ./plugins/ssjack-ui
go test -mod=readonly -race -count=1 -timeout 120s ./cmd/ssjack ./internal/... ./plugins/ssjack-ui
claude plugin validate ./plugins/ssjack-ui
claude plugin test ./plugins/ssjack-ui
```

Go tests use generated temporary keys and a local test SSH server. Plugin tests use Claude Code's testing API and do not connect to user SSH servers. The GitHub CI workflow runs Go tests on Linux, Windows, and macOS; UI tests require the compatible Claude Code authoring environment and are not silently substituted with fake CI checks.

# ssjack

A cross-platform Go SSH client, encrypted credential manager, key utility, and MCP server. Agent access uses two roles in the same executable:

- `ssjack <harness> [arguments...]` prompts for a passphrase, keeps decrypted SSH keys in memory, and runs the selected harness.
- `ssjack mcp` is the stdio bridge started by that harness. Starting another bridge does not grant access by itself.

```text
ssjack claude -c
ssjack --config .ssh/ssjack.ktav --bootstrap-timeout 5m claude -c
```

Options belonging to ssjack precede the harness name. The remaining arguments belong to the harness. Native executables are launched without a shell. Windows batch launchers require `cmd.exe`; ambiguous quoting and shell expansion arguments are rejected rather than guessed.

## Build and launch

Use the Go version declared in `go.mod`. No automatic build occurs in the launch scripts.

Windows:

```text
go build -mod=readonly -trimpath -o build/ssjack.exe ./cmd/ssjack
.\ssjack.cmd claude -c
```

Linux/macOS:

```sh
go build -mod=readonly -trimpath -o build/ssjack ./cmd/ssjack
./ssjack.sh claude -c
```

Launch from the project directory: the encrypted credentials database and project MCP settings are relative to the current working directory. The wrapper finds the binary next to itself without changing that directory. The binary directory is prepended to PATH only for the child harness so it can start `ssjack mcp`.

Use an interactive terminal for the passphrase. On Windows, mintty may not provide a usable console handle; use CMD/PowerShell or a suitable `winpty`. Passphrases from environment variables, command arguments, pipes, or chat are not accepted.

Keep the launcher in the foreground. A harness that daemonizes and immediately exits its initial process is not supported: the keeper closes when that process exits.

## Named credentials and legacy configuration: Ktav 0.8.1, pure Go

ssjack uses `github.com/ktav-lang/golang/pure` pinned to `v0.8.1`. It does not import the Rust ABI-backed root package. The pure package works with `CGO_ENABLED=0` and requires no Rust shared library.

The following ssjack-owned formats use Ktav:

- SSH configuration: `.ssh/ssjack.ktav`;
- protected key containers and the encrypted interactive credentials vault;
- temporary bootstrap file: `bootstrap.ktav`;
- framed request/response bodies on the internal TLS connection.

JSON remains only at required external interfaces: MCP JSON-RPC, `.mcp.json`, Claude Code settings, and hook event input/output. Existing `json` struct tags are also used by the Ktav library to map Go field names; they do not make the stored documents JSON.

By default, shell and agent launches use the encrypted named-record vault. Use `ssjack run <name> <harness> [arguments...]` to select the agent's credentials explicitly. Without a name, select after vault unlock; one available record is selected automatically. See [vault commands](docs/VAULT.md) for initialization and editing.

The following target-file workflow is **legacy opt-in only**, selected by `--config .ssh/ssjack.ktav`. Copy `.ssh/ssjack.example.ktav` to `.ssh/ssjack.ktav` only if the destination does not already exist. Example:

```text
keys.storage: id_ed25519
targets.storagehost.address: CHANGE_ME:22
targets.storagehost.user: mcp-agent
targets.storagehost.key: storage
targets.storagehost.known_hosts: known_hosts
```

Relative paths resolve from the configuration file's directory. Only configured targets are available through MCP. Unknown configuration fields are rejected. All configured private keys must be encrypted and unlock with the supplied passphrase.

The migration does not delete an existing `.ssh/ssjack.json`; it is an unused rollback copy. New binaries read that legacy file only when explicitly selected with `--config`; the default credential database is `.ssh/credentials.ssjack.ktav`. The internal protocol changed, so restart both keeper and bridge together; do not mix old and new executables within one session.

## Keys and host verification

1. Generate a dedicated encrypted key with `ssjack --generate-key <new-file>`; see [protected keys](docs/KEYS.md). Legacy encrypted OpenSSH keys remain supported; see `SSH.md` for the separate manual workflow.
2. Install only its public key into the intended server account's `authorized_keys` through an existing trusted connection.
3. Verify server host keys through that trusted connection and populate `known_hosts` in advance. Unknown or changed host keys are never accepted automatically.
4. Configure the target address, SSH user, key reference, and `known_hosts` file.

The example account is `mcp-agent`, not the host administrator. This tool does not establish a sandbox or grant Incus privileges. Do not expose an administrative Incus socket to a service agent.

Private keys remain encrypted on disk. After unlocking, decrypted signer objects stay in the keeper's memory until it exits. They are not exported to the harness, bridge, remote server, or an external SSH client. SSH executes inside the keeper.

The passphrase buffer is cleared after unlocking, but Go and the OS cannot guarantee erasure of every copy, protection from swap, dumps, debuggers, administrators, or a targeted process running as the same user.

## Interactive shell and encrypted credentials

`ssjack ssh <name>` opens an interactive SSH session using the same encrypted database as `ssjack run <name> <harness> [arguments...]`. Every invocation asks for the vault secret. The vault stores the target address, user, private key, and pinned server public keys inside the encrypted payload. `ssjack vault init|passwd|backup|restore|check` manages it without a plaintext editor. The SSH client is built into ssjack and never starts an external `ssh` executable.

This is a full PTY shell, not a new MCP tool. Password authorization is per CLI invocation, not per remote shell command. The keeper exposes only the selected record to MCP, keeps the signer session-scoped, and preserves host-key verification. The bridge never receives the vault secret. See [vault commands and shell](docs/VAULT.md) for setup, terminal behavior, concurrency, and security limits.

## Bootstrap: two secrets, one connection

Each launch creates independent random 256-bit credentials:

- Token A is passed only in the child harness environment as `SSJACK_ENV_TOKEN`.
- Token B is written to `.ssh/runtime/session-*/bootstrap.ktav` with the public endpoint, session identifier, and certificate fingerprint.
- `SSJACK_BOOTSTRAP_FILE` tells the bridge where that file is located.

The parent shell's environment is not changed. Token A is not written into the bootstrap file, MCP configuration, or command arguments.

The bridge connects only to `127.0.0.1` using TLS 1.3, verifies the pinned certificate, and presents both tokens. The first successful authentication atomically consumes the pair and binds access to that live connection. The listening port then closes. After the acknowledgement, the bridge removes the bootstrap file. Failure to remove it closes the connection.

An acknowledgement lost in transit does not permit another authentication attempt. Reconnection requires a new launcher session and new credentials. The bridge removes bootstrap variables from its own environment, but cannot remove them from the parent harness environment; the old token is no longer valid after attachment.

The initial attachment deadline defaults to two minutes and can be increased up to ten minutes. Bootstrap data is cleaned up on expiry, normal exit, or launch failure. A hard crash can leave a file behind, but without its live keeper it grants no access. Deletion is not guaranteed secure erasure from disks or backups.

Someone who obtains only the file or only the environment token cannot authenticate. Someone who obtains both before consumption can race the legitimate bridge. Child programs of the selected harness can inherit its token. Processes sharing one harness MCP connection are not individually distinguished.

## MCP registration

If `.mcp.json` is absent, the launcher creates a secret-free entry from `.mcp.example.json`. Existing files are not overwritten: they must already contain an ssjack stdio entry with command `ssjack` and args `["mcp"]`; otherwise the launcher asks for manual configuration.

Claude Code project trust, MCP approvals, and permissions remain in force. Cached MCP connections may initialize lazily: open `/mcp` or use a tool before the bootstrap deadline.

Other harnesses may use a different registration format. Configure the same stdio command in their supported format and preserve inherited environment variables. ssjack does not modify global client settings.

## Automatic command and result cards in Claude Code

Launch normally:

```text
ssjack claude -c
```

The executable embeds the project-local `plugins/ssjack-ui` runtime assets. At startup it installs an immutable, content-addressed copy in `.claude/ssjack-ui/<hash>` and appends that directory to `CLAUDE_CODE_PLUGIN_DIRS` only in the child harness environment. Existing plugin directories are preserved. No manual `--plugin-dir`, global installation, or settings change is required to register the UI plugin. Claude Code's own project trust and plugin policies still apply.

The plugin expands grouped ssjack calls and renders separate bordered cards:

- cyan command cards show the target and submitted command;
- green/yellow/red result cards show job IDs, stdout/stderr, completion status, errors, and cancellation;
- stored tool inputs and results, execution, permissions, and authentication are unchanged.

This requires a Claude Code build supporting function-hook UI plugins and the `ToolGroup`, `ToolUse`, and `ToolResult` rendering APIs. The local authoring build is 2.1.304. Other harnesses can still use MCP, but this UI integration does not add cards to their interfaces.

At the same startup, ssjack removes only the obsolete classic display hooks it previously installed in project-local `settings.local.json`. Other hooks, such as clocks or status notifications, and unrelated settings are preserved. The legacy `install-hooks` command is not needed for this UI.

The module is display-only: it reads the tool row already held by the harness and never opens another SSH connection, reads key files, or receives bootstrap credentials. Terminal control sequences are escaped. Long display text is explicitly truncated without changing the stored tool result. Commands and output may contain secrets and are intentionally visible to the user.

These are actual UI cards, not assistant-authored messages or a tamper-proof audit trail. They show submitted commands and returned chunks, not every child command executed by a remote script. Updating the Go executable and restarting ssjack is required to activate a newly embedded plugin; an existing keeper/harness is not silently replaced.

## Tools and output

- `remote_targets`: approved logical target names, not credentials or addresses.
- `remote_exec`: noninteractive shell execution; returns `job_id`.
- `remote_read`: output chunks and operation state.
- `remote_cancel`: cancellation and SSH connection closure.

Pass returned stdout/stderr offsets into the next read. Offsets count original bytes. `done` means execution ended, not that all retained output was drained: continue reading while `stdout_more` or `stderr_more` is true.

Invalid UTF-8 is replaced in text output, with the original chunk additionally available as `stdout_base64` or `stderr_base64`. This also preserves bytes when a multibyte character spans chunks.

Limits:

- four concurrent operations;
- the latest 64 operations are retained, evicting older completed operations;
- 256 KiB retained per output stream per operation;
- up to 32 KiB of each stream per read;
- output eviction is reported by `stdout_lost` and `stderr_lost`;
- commands up to 16 KiB; timeout defaults to 600 seconds, at most 3600;
- no interactive PTY, conversational stdin, agent forwarding, or arbitrary target addresses through MCP.

Disconnecting the bridge cancels active operations and closes their SSH connections. Detached processes and system services may continue on the server. A shell command has the SSH user's permissions, so guest OS/Incus isolation remains necessary. Remote output can contain secrets and is delivered to the harness.

The old OpenSSH wrappers are retired and unused by the native client and MCP paths. Use `ssjack ssh <name>` for manual sessions; see [SSH compatibility and host trust](SSH.md).

## Updating an installed executable

Windows:

```text
.\update-ssjack.cmd
```

Git Bash, Linux, or macOS:

```sh
./update-ssjack.sh
```

The default candidate is `build/ui-next/ssjack.exe` on Windows and `build/ui-next/ssjack` on Linux/macOS. An optional candidate path may be supplied as the first argument. The target is always the main executable in this project's `build` directory.

The updater stages a copy, checks SHA-256 consistency, and runs the candidate's `--help` before changing the installed path. It renames the previous executable to a unique `ssjack.previous-*` backup and installs the staged version under the original name. It verifies the installed hash and help again. A failed installation attempts to restore the old name without stopping any process. Backups and failed candidates are retained rather than silently deleted.

Running processes keep their old executable image. Restart ssjack normally to use the installed version; the updater never kills processes or restarts the harness. If Windows refuses to rename a running image, the update fails rather than forcing termination.

A project-local lock serializes updater invocations. On POSIX, a hard crash can leave the lock directory behind; confirm no updater is running before removing a stale lock. Checksums verify copy consistency, not publisher identity: only use a trusted candidate, because its help command is executed.

## Tests

```text
go test -mod=readonly -count=1 -timeout 120s ./cmd/ssjack ./internal/...
go test -mod=readonly -race -count=1 -timeout 120s ./cmd/ssjack ./internal/...
```

Tests use temporary test keys and a local test SSH server. They do not connect to user servers or alter real SSH keys or global settings. Ktav round-trip tests cover commands, binary output, large integers, bootstrap consumption, and strict configuration validation.

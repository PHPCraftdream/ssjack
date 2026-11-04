# ssjack

A cross-platform Go SSH client, encrypted server/account directory, Bubble Tea owner console, key utility and MCP keeper. The current operator entry points and platform boundaries are indexed in [the capability map](docs/README.md). Agent access uses two roles in the same executable:

- `ssjack run <harness> [arguments...]` prompts for a passphrase, keeps decrypted SSH keys in memory, and runs the selected harness.
- `ssjack mcp` is the stdio bridge started by that harness. Starting another bridge does not grant access by itself.

```text
ssjack run claude -c
ssjack -p work --bootstrap-timeout 5m run claude -c
```

Options belonging to ssjack precede the harness name. The remaining arguments belong to the harness. Native executables are launched without a shell. Windows batch launchers require `cmd.exe`; ambiguous quoting and shell expansion arguments are rejected rather than guessed.

## Install and launch

Use the globally installed executable or a verified CI artifact. For a reviewed source checkout, root `build.sh` (Linux/macOS) and `build.ps1` (Windows) compile the native CLI and install it through the official verified installer, with commit identity and a SHA-256 check. They never self-elevate or stop processes. The same [installers](docs/INSTALL.md) handle release downloads/local candidates directly; there is no second replacement algorithm.

```text
ssjack run claude -c
ssjack -p work run claude -c
```

Launch from your application working directory: the encrypted database and MCP settings are relative to that directory. The executable directory is prepended to PATH only for the child harness so it starts the matching `ssjack mcp`. No automatic compilation occurs at launch.

Use an interactive terminal for the passphrase. On Windows, mintty may not provide a usable console handle; use CMD/PowerShell or a suitable `winpty`. Passphrases from environment variables, command arguments, pipes, or chat are not accepted.

Keep the launcher in the foreground. A harness that detaches into an angel (background process) and immediately exits its initial process is not supported: the keeper closes when that process exits.

## Named credentials and stored formats

ssjack uses `github.com/ktav-lang/golang/pure` pinned to `v0.8.1`. It does not import the Rust ABI-backed root package. The pure package works with `CGO_ENABLED=0` and requires no Rust shared library.

The following ssjack-owned formats use Ktav:

- The encrypted credential database and its directory payload; default `.ssh/credentials.ssjack.ktav`.
- Protected key containers and encrypted installation metadata.
- Framed request/response bodies on the primary internal TLS connection.

`.ssh/ssjack.ktav` is a legacy plaintext metadata input, never a normal startup configuration. JSON is used at MCP/configuration boundaries, archive manifests and separately versioned private HTTP text protocols (NDJSON for streaming). The application store has its own authenticated binary format. Existing `json` struct tags are also used by Ktav for field mapping; they do not make database payloads JSON.

Normal startup reads only the encrypted profile database. Select a profile with `-p NAME` / `--profile NAME`; absence means `main`, not a guessed single record. Use `ssjack ssh`, `ssjack run claude -c`, and `ssjack edit` for the selected profile.

An old plaintext target file is an explicit migration input only: `ssjack [-p NAME] vault migrate LEGACY_FILE`. The CLI authenticates interactively, imports actual key bytes and verified server pins into the encrypted database, preserves originals, and never enables plaintext startup fallback. See [profile migration](docs/VAULT.md).

## Owner session and named directory

`ssjack --interactive` unlocks once and runs the Bubble Tea connection picker and owner editor. Connection points are named server/account pairs; even a singleton requires Enter. Selectors can focus a server/account page without connecting. Server/account forms accept key-file or hidden-password authentication, shared verified host pins and per-account usage. Global and server-local secret values use the linked private app-store path; bindings carry exact refs and explicit stable-server-ID scopes, not a fallback hierarchy.

The owner coordinator retains authenticated RAM state, serializes encrypted saves and exposes explicit pending-intent recovery. Export scopes all/server/account/global include actual values; encrypted by default, exact `EXPORT PLAINTEXT` for the deliberate alternative. Import inspects existing ZIP archives in RAM, previews metadata and requires `IMPORT`; conflicts refuse without overwrite, and values receive fresh authenticated destination refs. Per-secret intents are durable; the remainder of a partial import plan is RAM-only, with no full-plan restart resume. These owner capabilities are not MCP getters or remote enrollment.

`vault migrate-directory NEW_FILE` explicitly converts the payload schema while preserving the original ciphertext and credentials. The operator must select the result or activate it at the old path; installation never switches files. `vault upgrade` is a different outer-container operation. See [the credential/migration guide](docs/VAULT.md) and [owner menu](docs/application-store/OWNER-TUI.md).

## Keys and host verification

1. Generate a key inside the database with `vault init --generate-key` / `add --generate-key`, select an existing key file, or choose password authentication in the owner menu. Standalone containers use `--generate-key FILE` / `--protect-key FILE`; see [keys](docs/KEYS.md).
2. For key authentication, install only the public key into the intended existing server account through a trusted connection.
3. Independently verify server public keys and enter/import the pins into the encrypted record. Unknown or changed keys are never accepted automatically.
4. Store endpoint, SSH login, exactly one key/password credential, pins and optional usage/policy in the database. A legacy `known_hosts` file is only an explicit metadata-migration input.

The example account is `mcp-agent`, not the host administrator. This tool does not establish a sandbox or grant Incus privileges. Do not expose an administrative Incus socket to a service agent.

Private keys remain encrypted on disk. After unlocking, decrypted signer objects stay in the keeper's memory until it exits. They are not exported to the harness, bridge, remote server, or an external SSH client. SSH executes inside the keeper.

The passphrase buffer is cleared after unlocking, but Go and the OS cannot guarantee erasure of every copy, protection from swap, dumps, debuggers, administrators, or a targeted process running as the same user.

## Interactive shell and encrypted credentials

`ssjack [-p NAME] ssh` opens a PTY using the same encrypted database as `run HARNESS [ARGS...]`; named-directory callers can instead use `--server NAME --account NAME`. Separate CLI invocations unlock individually, while the owner menu reuses one session. The vault stores address, user, key or password, verified server pins and settings. `vault init|passwd|backup|restore|check|upgrade|migrate-directory` manages storage without plaintext staging. Native SSH never starts an external `ssh` executable. Input is owned and joined before returning to the menu; Windows VT consoles can fail closed and require a restart rather than unsafe reader reuse.

This is a full PTY shell, not a new MCP tool. Password authorization is per CLI invocation, not per remote shell command. The keeper exposes only the selected record to MCP, keeps the signer session-scoped, and preserves host-key verification. The bridge never receives the vault secret. See [vault commands and shell](docs/VAULT.md) for setup, terminal behavior, concurrency, and security limits.

## Bootstrap: memory only, one connection

Each launch creates a random 256-bit capability and passes the endpoint, TLS certificate pin, session identifier, and token only through the child harness environment. No bootstrap file or `.ssh/runtime` directory is created. The parent shell's environment and persistent MCP settings do not receive credentials.

The bridge connects only to literal `127.0.0.1` using pinned TLS 1.3. Protocol-v2 authentication atomically consumes the token and binds access to the established connection; the listener then closes. Replay, expiry, disconnect, or a lost acknowledgement requires a new launcher session. The initial attachment deadline remains two minutes by default, at most ten minutes.

This intentionally replaces the former independent environment/file channels with one channel. Theft of the full child bootstrap environment before attachment can win the connection race. Same-user processes and children of the selected harness are not strongly isolated. Old and new bridge/keeper versions cannot attach to each other; restart the launcher after updating. See [the bootstrap and memory-key specification](docs/BOOTSTRAP.md).

## MCP registration

If `.mcp.json` is absent, the launcher creates a secret-free entry from `.mcp.example.json`. Existing files are not overwritten: they must already contain an ssjack stdio entry with command `ssjack` and args `["mcp"]`; otherwise the launcher asks for manual configuration.

Claude Code project trust, MCP approvals, and permissions remain in force. Cached MCP connections may initialize lazily: open `/mcp` or use a tool before the bootstrap deadline.

Other harnesses may use a different registration format. Configure the same stdio command in their supported format and preserve inherited environment variables. ssjack does not modify global client settings.

## Automatic command and result cards in Claude Code

Launch normally:

```text
ssjack run claude -c
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

The old OpenSSH wrappers are retired and unused by the native client and MCP paths. Use `ssjack [-p NAME] ssh` for manual sessions; see [SSH compatibility and host trust](SSH.md).

## Updating an installed executable

Use `install.ps1` on Windows or `install.sh` on Linux/macOS, with a reviewed release or an explicit local candidate and independently verified SHA-256. There is no separate project-local update path. See [INSTALL.md](docs/INSTALL.md) for commands and platform requirements.

The installer stages and verifies the candidate, renames the previous executable, publishes under the original name, and checks the installed hash/help. It attempts rollback on verification failure, never kills a process, and removes only safely identified unused installer-owned previous files after success. Busy or uncertain images are retained. Old inactive copies are not guaranteed to remain available for later rollback.

Running processes continue their old code until explicitly restarted. After an incompatible bootstrap change, restart the launcher and bridge together. Installers do not migrate the encrypted database or alter SSH credentials.

## Application secrets and separate text adapters

Application-secret values use a separate encrypted versioned store. The owner directory stores names/scopes/refs and its encrypted store link, not a second ordinary value database. `appstore setup|put|inspect|unlock` covers the explicit installation/first-entry/inspection/fixed-delivery path; owner CRUD and archive import/export extend that path without a public value getter. Setup does not enroll a service. See [store entry](docs/application-store/ENTRY.md) and [owner coordination](docs/application-store/OWNER-COORDINATOR.md).

The Linux/amd64 `text-adapter` CLI is separate from general `app_*` transport and synthetic delivery. Root registers/revokes exact finite grants; a non-root operator unlocks the selected account and installation and launches a direction-specific listener through `serve` (v1) or `serve-stream` (v2). Forward hydration never grants reverse reads. A v2 grant has its own namespace and no v1/raw fallback. Clawwright explicitly uses `--stream-references PATH` for large-text deploy/backup; the file is canonical reference metadata, not approval or values.

Private hydration and reverse-copy pipelines keep selected values out of model/tool responses. Reverse output is a validated reference-only copy, not a rewrite of the source. V2 uses bounded framing and up to 64 MiB decoded input/output, with status-only delivery outcomes. `received` does not establish adoption; uncertain effects must not be retried automatically. Literal replacement does not escape structured formats or discover unknown secrets. See [text adapter](docs/application-store/TEXT-ADAPTER.md), [stream HTTP](docs/application-store/TEXT-STREAM-HTTP.md) and [paired acceptance](docs/application-store/CLAWWRIGHT-TEXT-PAIR.md).

The separate `declarative setup|register|revoke|run` path implements only a synthetic Linux/amd64 metadata slice; general enrollment, restricted-driver execution and lifecycle specifications remain proposals. `--mode declarative` metadata descriptors do not enable that general runtime. See [declarative scope](docs/declarative/README.md).

## Tests

Run these only in the authorized GitHub CI environment, not as an implicit local startup step:

```text
go test -mod=readonly -count=1 -timeout 120s ./cmd/ssjack ./internal/...
go test -mod=readonly -race -count=1 -timeout 120s ./cmd/ssjack ./internal/...
```

Tests use temporary test keys and a local test SSH server. They do not connect to user servers or alter real SSH keys or global settings. Ktav round-trip tests cover commands, binary output, large integers, bootstrap consumption, and strict configuration validation.

## Legacy metadata migration boundary

Normal startup accepts profiles only from the encrypted database. `--config` is not a supported startup option. An old plaintext metadata file can be consumed only by explicit `ssjack [-p PROFILE] vault migrate LEGACY_FILE`, defaulting to destination profile `main`.

Migration asks for database authorization (or a confirmed new database secret), source key authorization when needed, and explicit destination-profile confirmation. It imports address/user/private key bytes and only raw server keys already trusted for the exact legacy address/port, including supported hashed known_hosts entries; revoked, unrelated, CA-only, or missing trust is not accepted. No network scan or connection supplies migration trust. Existing destination profiles are never overwritten. Existing databases receive encrypted recovery snapshots before the new profile is committed.

Source metadata, source private-key files, and old copies are never silently deleted. They can still expose metadata until the user separately retires them after verifying the encrypted profile. The assistant cannot perform real migration without the user's terminal-only secrets and does not read real private keys through tools.

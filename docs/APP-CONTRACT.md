# Registered application contract

Any application can be registered with ssjack if it ships a descriptor and, optionally, uses the child transport. ssjack knows nothing about a specific product: everything it needs is in the descriptor and in the environment contract below.

**Contract version:** descriptor format `ssjack-app-v1`; child transport protocol `1` (see [Protocol 1 tools](#protocol-1-tools)). A change that an older ssjack cannot honor gets a new descriptor format name or protocol number. It is never an unmarked change to v1.

## Integration status

The internal `apptransport` package implements the child transport described here. The main MCP surface supports opt-in application registration and finite application jobs. No application is enabled without human startup registration, and no child listener exists until an application operation starts. Registration of an application is not end-to-end readiness of that application: the application must itself implement the consumer side.

This is not the primary keeper bootstrap protocol. The primary bridge still uses its one-use protocol-v2 capability and framed Ktav over pinned loopback TLS. A child transport uses a different ephemeral TLS identity and a separate bearer lease, scoped to one selected profile and its application-operation lifetime.

## Registration

The owner registers applications at keeper startup, before the vault prompt:

```sh
ssjack -p lab --app ./deployment run claude -c
ssjack -p lab --app ./first --app ./second --app-route incus:lab-guest:operator run claude -c
```

- `--app DIR` is repeatable. `DIR` holds `ssjack-app.json`. Every descriptor is read, validated and resolved before any credential is unlocked; a failure ends startup. Two registrations with the same `name` are refused, and so is the same directory twice. At most 16 applications are registered.
- `--app-route incus:CONTAINER:USER` is optional and applies to every registered application. Without `--app` it is refused.
- `--app-route-for APP=incus:CONTAINER:USER` is repeatable for different applications and overrides the route of one application for this invocation only. Route precedence: `--app-route-for`, then the per-app route stored in the encrypted vault, then the global `--app-route`, then no route.
- Registration is available in full mode only. No application is enabled implicitly. Startup also scans the working folder and its immediate subfolders for candidate descriptors (default, see `docs/APP-DISCOVERY.md`): a candidate is reported, never enabled, until the owner approves it in `--interactive`; a changed descriptor needs re-approval. PATH is never scanned; only a bare `launch.executable` name is looked up on PATH, once, at startup.
- `--confirm-elicitation` enables the optional confirmation prompt for eligible MCP operations. It is OFF by default, available in full mode only, and set at keeper startup; agents cannot enable it through tool arguments, environment, or agent-writable files.

## Descriptor: `ssjack-app.json`

```json
{
  "format": "ssjack-app-v1",
  "name": "example",
  "launch": {
    "executable": "bin/example",
    "args": ["dist/entry.js"]
  },
  "workdir": ".",
  "commands": {
    "observational": ["status", "inspect", "version"],
    "refused": ["serve"]
  }
}
```

| Field | Required | Meaning |
| --- | --- | --- |
| `format` | yes | Exactly `ssjack-app-v1`. |
| `name` | yes | Application ID shown by `app_list` and passed as `application` to `app_exec`. Matches `^[a-z][a-z0-9-]{0,31}$`. |
| `launch.executable` | yes | A native regular executable file. See [Launch](#launch). |
| `launch.args` | no | Fixed leading arguments, for example an entry script. At most 16 entries, each at most 1024 bytes, 4096 bytes in total. |
| `workdir` | no | Working directory, relative to `DIR` and resolved inside it. Default `DIR`. |
| `commands.observational` | no | Command names that may run without `confirm=true`. |
| `commands.refused` | no | Command names that are always refused. |

Command names match `^[a-z][a-z0-9-]{0,63}$`, are unique within a list, and at most 64 are listed per list. A name in both lists is refused. A command is the first element of the `app_exec` `arguments`.

### Strict parsing

The file is read once as at most 16 KiB of valid UTF-8 and must be a single JSON object. Unknown fields at any level are refused, as are repeated fields, differently cased field names, trailing data, `null` values and values of the wrong type. Text values contain no control characters (including NUL). Nothing is guessed or defaulted beyond the optional fields above.

`DIR` and `ssjack-app.json` must not be symlinks or reparse points, and the descriptor must be a regular file. Parent components of `DIR` are resolved once and retained as absolute paths.

### Launch

- An absolute `launch.executable` is used as is. A relative path containing a separator is resolved against `DIR`. A bare name (no separator) is looked up once on `PATH` at startup, never in `DIR`.
- After symlink resolution the target must be a regular file. On Windows it must be a native `.exe`; elsewhere it must have an execute bit. Command shims (`.cmd`, `.bat`) are refused by name before and after resolution.
- The process is started directly with the executable, `launch.args` and then the `app_exec` arguments. There is never a shell, and the model cannot choose the program.
- The working directory is `workdir` after symlink resolution and must stay inside `DIR`.
- This is declared configuration, not provenance or isolation: an executable inside or outside `DIR` is trusted code run with the keeper user's authority.

### Commands and confirmation

- Interactive stdin is always refused by ssjack: an argument `--stdin` or `--stdin=...` is rejected for every application, and the process gets no stdin. The descriptor cannot change that.
- Commands in `commands.refused` are always refused, with or without `confirm=true`.
- Commands in `commands.observational` may run without `confirm=true`. List only commands that do not mutate state whatever their further arguments are.
- Every other command requires `confirm=true`. The flag records caller acknowledgment only; it does not prove human review or grant privileges. Harness permissions and the applicable operator authorization still apply.

Arguments passed to `app_exec` are bounded to 128 entries and 8 KiB before internal encoding, without NUL. The first argument must be a command name as above.

## MCP surface

The main MCP surface offers `app_list`, `app_exec`, `app_read` and `app_cancel`. `app_exec` accepts the application name, an argument vector, a finite timeout (default 600 seconds, at most 3600) and `confirm`. It returns a job ID rather than holding the primary broker request open. Read and cancel address only application jobs.

Design only, and not part of the first step: a task path for `app_exec` needs a truthful cancel result and a paged output contract from the application job manager first, so `app_exec` keeps returning a job ID and `app_read`/`app_cancel` stay as they are for every client. See [MCP-TASKS.md](MCP-TASKS.md) ("Later design: exec and application tools").

All four tools answer with plain text, never a raw JSON object: `app_list` lists `- <name> (profile <profile>)` lines (or says that no application is registered and repeats the hint), `app_exec` answers `Started job <job_id>` with the `app_read` step, `app_read` answers `Job <job_id>: running` or `Job <job_id>: done (exit code <n>)`, the output chunks verbatim between a `stdout (bytes A-B):` label and an `[end of stdout]` marker line (likewise for stderr, with a base64 line for bytes that are not valid UTF-8) and a `Next: stdout_offset=<n> stderr_offset=<n> · more: ... · lost: ...` line, and `app_cancel` answers `Cancelled job <job_id>` (a cancellation was requested while the job had not ended; if it finishes at the same moment, its own outcome is retained) or `Job <job_id> had already finished` (a job no longer running: done, failed, timed out or already cancelled). The format is specified in `REMOTE-MCP.md` ("Result text of the ssjack tools"). The text carries the same bytes as before: output capture, masking and the output guard are unchanged, so existing-output, exit-code and withheld-delivery rules of a consumer are not affected by the encoding of the result.

Application output uses the existing bounded captured-log manager: output eviction is explicit through `*_lost`; this surface is not an archive-download stream. Binary archives belong on the lossless child transport. Both output streams mask only exact occurrences of the known child bootstrap token, including matches split across writes. This is not general-purpose secret detection or redaction, and arguments and output may contain secrets. Application tools use the harness's normal tool presentation.

## Incus route

`--app-route incus:CONTAINER:USER` binds a fixed route through the selected SSH host: `sudo -n incus exec NAME -- runuser -u USER -- sh -c COMMAND`. `CONTAINER` matches `^[a-z0-9][a-z0-9-]{0,62}$` and `USER` matches `^[a-z_][a-z0-9_.-]{0,31}$`. The application supplies only the inner command; it cannot replace the profile, container or user. This authenticates the host and uses its trusted local Incus control plane, not an implicitly trusted guest SSH connection. Direct guest SSH would require separate enrollment and pins.

## Child transport environment

Each application operation launches the process with a fresh child transport and exactly three added environment values. This is the public contract an application relies on:

- `SSJACK_APP_ENDPOINT`: `https://127.0.0.1:<port>/mcp`;
- `SSJACK_APP_CERTIFICATE_SHA256`: the SHA-256 of this child's ephemeral DER certificate;
- `SSJACK_APP_TOKEN`: a random 256-bit bearer lease.

The environment builder removes inherited primary and child bootstrap names, case-insensitively, without changing the parent environment. No password, database master, SSH private key, or bootstrap file is provided. RAM-only transport credentials are still subject to same-user inspection, swap and dumps.

The child lease is reusable for requests during one application operation; it is not a second claim on the primary one-use capability. Possession of the whole child context permits access to that profile while the lease lives. It is not cryptographic proof of a process ID. The operation reuses the unlocked credential runner, not the primary bootstrap token. Closing the application scope (the application finishes, times out, is cancelled or loses its parent session) closes the listener and active HTTP connections and cancels its transport jobs. Applications must never persist this context in a deployment, MCP settings, lockfile, archive or log.

An application selects this transport for an automatic target only when the complete child context is present. Explicit standalone targets stay explicit. A supplied invalid, incomplete, incompatible or disconnected context fails closed and never falls back to ordinary SSH. Absence of a context preserves standalone operation and the application's existing transports.

The API is for finite CLI operations, not for starting a nested stdio MCP server.

## Trust and lifetime

The current full MCP `remote_*` tools execute commands with the configured remote SSH principal's authority. A name such as `mcp-agent` does not establish that principal as non-admin: the operator controls server-side sudo rules, groups, socket access and backend memberships, which may permit host-root or equivalent access. For optional Incus routing, the selected host principal must be authorized for the fixed `sudo -n incus exec` operation, and the configured guest user has its guest privileges. Registration fixes program selection against model substitution in tool arguments, but the registered executable, its package and host-side paths remain trusted mutable code, not a sandbox. Admitted `app_exec` commands, including secret-reporting commands, may perform general operations or expose values. Output capture masks only exact child bootstrap-token occurrences; it is not general secret redaction. Safe SSH-key custody and captured output are no guarantee of secret nondisclosure.

A Docker/Incus administrator socket or sudo rule, or an alternate SSH channel available to trusted code, may bypass a future restricted API. A future declarative MCP would be a separate authorization and dispatch surface; it is not a relabeling or restriction of `app_*` or current `remote_*`. Until then, enforce least privilege in the operator-controlled host, guest and backend configuration.

Second-hop deployment through `ssh`/`rsync`, persistent invocations and stdio protocol relays must refuse unsupported session-scoped routes before applying them. They must not fall back to an unrelated SSH executable or persist a temporary lease.

## HTTP boundary

This is the standard MCP Streamable HTTP transport, not another proprietary JSON wire format. The existing pinned Go MCP SDK serves stateless JSON responses. Internal keeper requests remain Ktav.

TLS requires 1.3 or newer. The server binds literal IPv4 loopback, bounds concurrent sockets, limits headers and request bodies, rejects browser origins, and accepts only authenticated POST requests at the exact `/mcp` endpoint and Host authority. Authentication is checked before entering MCP dispatch. There are no redirects or remote binding options.

A client must verify the certificate pin **before sending Authorization or request data**. In Node.js, merely combining `rejectUnauthorized: false` with `checkServerIdentity` is insufficient: the identity callback may not run. An agent connection factory must withhold the TLS socket from HTTP until it has compared the peer certificate's DER digest to the expected pin.

## Protocol 1 tools

`transport_info` returns:

- `protocol`: `1`;
- `profile`: the delegated profile name, not its address or key;
- `commit`: the serving keeper's source revision;
- `chunk_size`: `16384` raw bytes;
- `capabilities`: `exec`, `stdin`, `binary`, `backpressure`, `cancel`;
- `cancellation`: `connection-only`.

Check this actual keeper, not an unrelated executable found on PATH. No `stdioProtocol` or port-forwarding capability is advertised yet.

`transport_start` accepts `command` (a nonempty remote shell command, at most 64 KiB, without NUL) and optional `timeout_ms` (default 600000, maximum 3600000). It returns `job_id`. The profile is fixed by the server and cannot be selected by the request.

`transport_input` accepts `job_id` and either a base64 `data` chunk or `eof: true`. A request may not combine data and EOF. At most 16 KiB of raw input fits one chunk. `accepted: false` means backpressure: keep the same chunk and retry after allowing output to drain. `accepted: true` queues that chunk once. Repeated EOF is idempotent; data after EOF is refused.

`transport_read` accepts `job_id`. It consumes one base64 stdout/stderr chunk, returns `pending: true` while waiting, or returns `done: true` with `exit_code`, optional `error`, and `timed_out`. Drain until final status; a completed command can still have queued output. Stdout and stderr retain their own byte order, not a cross-stream chronological ordering guarantee.

`transport_cancel` accepts `job_id` and cancels the SSH operation. Closing the SSH connection does not prove that detached remote processes stopped. A consumer needing a target-side deadline must arrange one explicitly and must not claim confirmed remote cancellation.

## Flow control and failure

Each job has bounded queues: four stdin chunks and sixteen output chunks. Output producers wait rather than overwrite unread bytes. A client pumps input and drains output concurrently; writing all input before reading can deadlock any duplex program. At most four jobs run concurrently, and retained jobs are bounded. Only fully drained results are eligible for automatic retention eviction.

Frames carry bytes as base64, never lossy UTF-8 conversion. A consumer can decode textual command results after reassembling chunks, and must use a byte-safe path for archives or protocol streams.

The protocol deliberately has no replay or stream-resume contract. A lost response may have already consumed output or queued input. Do not automatically retry such a request: cancel/fail the operation instead of risking duplicate stdin or truncated output. Only an explicit `accepted: false` input reply permits retrying that chunk.

## Boundaries still owned by the application

A file transfer must preserve bytes and apply its own destination, symlink and atomic-publication rules. Scope is an SSH profile, not a filesystem jail.

Second-hop deployment, persistent schedules, port forwards, and externally launched MCP clients cannot borrow this temporary scope implicitly. Each must have an explicit supported route or refuse before mutation. A host profile does not automatically authenticate a guest or enroll its host key.

The current SSH runner authenticates a fresh connection for each command. The integration reuses the unlocked keeper session, not a promised single SSH TCP connection. All commands still pass the existing host-key and selected-signer checks.

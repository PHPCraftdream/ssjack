# Scoped application transport

## Integration status

The internal `apptransport` package implements the child transport described here. Registering and launching a local application through the main MCP surface is a separate integration step. The package alone does not enable an application, start a persistent listener, or add a new CLI command.

This is not the primary keeper bootstrap protocol. The primary bridge still uses its one-use protocol-v2 capability and framed Ktav over pinned loopback TLS. A child transport uses a different ephemeral TLS identity and a separate bearer lease, scoped to one selected profile and its application-operation lifetime.

## Trust and lifetime

Only a keeper-owned application launch may create the transport. The launching human chooses the executable and deployment directory; a model must not be able to substitute either in a tool call. Application code is trusted to issue commands with the selected SSH account's privileges. This is not a sandbox or a command allowlist.

The child gets three process-environment values:

- `SSJACK_APP_ENDPOINT`: `https://127.0.0.1:<port>/mcp`;
- `SSJACK_APP_CERTIFICATE_SHA256`: the SHA-256 of this child's ephemeral DER certificate;
- `SSJACK_APP_TOKEN`: a random 256-bit bearer lease.

The environment builder removes inherited primary and child bootstrap names, case-insensitively, without changing the parent environment. No password, database master, SSH private key, or bootstrap file is provided. RAM-only transport credentials are still subject to same-user inspection, swap and dumps.

The child lease is reusable for requests during one application operation; it is not a second claim on the primary one-use capability. Possession of the whole child context permits access to that profile while the lease lives. It is not cryptographic proof of a process ID. Closing the application scope closes the listener and active HTTP connections and cancels its transport jobs. Callers must never persist this context in a deployment, MCP settings, lockfile, archive or log.

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

An explicit child context that is incomplete, invalid, incompatible or disconnected fails closed. It must never trigger a fallback to ordinary SSH. Absence of a context preserves standalone operation and the consumer's existing transports. Explicitly selected other transports remain explicit choices.

## Boundaries still owned by the application

A file transfer must preserve bytes and apply its own destination, symlink and atomic-publication rules. Scope is an SSH profile, not a filesystem jail.

Second-hop deployment through `ssh`/`rsync`, persistent schedules, port forwards, and externally launched MCP clients cannot borrow this temporary scope implicitly. Each must have an explicit supported route or refuse before mutation. A host profile does not automatically authenticate a guest or enroll its host key.

The current SSH runner authenticates a fresh connection for each command. The integration reuses the unlocked keeper session, not a promised single SSH TCP connection. All commands still pass the existing host-key and selected-signer checks.

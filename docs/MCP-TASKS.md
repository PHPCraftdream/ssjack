# MCP tasks for the ssjack bridge tools

Status: implemented for `remote_upload` and `remote_download`. It specifies the MCP Tasks extension (`io.modelcontextprotocol/tasks`) for ssjack's MCP bridges, for the two transfer tools only; a task path for the exec tools is a separate design noted at the end. "Verification against the sources" and "What landed" below state what the sources confirmed and what the code and tests establish.

The tags below mark the source of every statement in this document.
`[client docs]` is taken from the Claude Code MCP documentation
(code.claude.com/docs/en/mcp, sections "MCP tasks that run on the server", "MCP
tasks for server authors" and "Automatic backgrounding of long tool calls"), or
from the extension text at modelcontextprotocol.io/extensions/tasks/overview and
modelcontextprotocol/ext-tasks. `[pinned SDK v1.8.0]` is observed in
github.com/modelcontextprotocol/go-sdk v1.8.0. `[ssjack code]` is observed in
this repository. `[assumption]` is our design assumption, not established by
either.

## Why

`remote_upload`, `remote_download`, `remote_exec` and `app_exec` answer
`Started job <job_id>` at once, and the model then polls `transfer_status`,
`remote_read` or `app_read`, optionally with `wait_seconds` up to 25
(FILE-TRANSFER.md, "Waiting calls (`wait_seconds`)", and REMOTE-MCP.md, "Result
text of the ssjack tools"). That model has three costs:

- `[ssjack code]` Every poll is printed into the model's chat, so a long job
  floods the conversation with status lines.
- `[ssjack code]` A waiting call occupies the single keeper request slot of its
  connection, so a concurrent `transfer_cancel` is served only after the wait
  ends, up to 25 s (FILE-TRANSFER.md, "Waiting calls").
- `[ssjack code]` Only the model can cancel, and it must decide to do so.

`[client docs]` The MCP Tasks extension lets a supporting client follow and
cancel the job itself.

This is implemented for the two transfer tools; the exec tools keep the polling path below.

The twelve decisions in this document, and the section that takes each one. The
table repeats the decisions; each section below carries the tags for its own
claims.

| Decision | Taken here | Section below |
| --- | --- | --- |
| Tool scope | `remote_upload` and `remote_download` only; the exec tools are a later design | Which tools carry a task |
| Identity and lifetime | The task id is the job id; records are RAM-only; `ttlMs` 7200000 is advisory | Identity, lifetime and bounds |
| Status content | One line of state names and counters the keeper already publishes, never content | Status message content |
| Final result | One text block, the same text the polling path produces | The final result |
| Cancel | `tasks/cancel` calls `transfer_cancel`; the reply only says whether a cancellation was requested, the next status record decides the state | Cancel |
| Advertisement and fallback | Advertise the extension in `server/discover`; a client without it keeps today's tools | Advertisement and fallback |
| Keeper connection | No cache: each `tasks/get` is one on-demand status read that queues on the shared connection until the task freezes | Keeper connection |
| input_required | Not used | input_required |
| Trust boundary | Nothing new reaches the model, another session or the wire | Trust boundary |
| Failure modes | A failed job stays a text result; a failed task status is machinery only | Failure modes |
| Acceptance tests | An in-process fake-keeper test for queueing and equality; one launched bridge per client kind | Acceptance tests |
| Implementation order and non-goals | Transfer task path only; exec tasks are a later design | Implementation order and non-goals |

## Client facts

- `[client docs]` Tasks need protocol revision 2026-07-28, and that revision is
  one of several conditions rather than the only one. Claude Code runs a
  second-generation MCP runtime that negotiates the revision: it uses that
  runtime on v2.1.232 or later in sessions that fetch feature flags, and by
  default on v2.1.274 or later in sessions that do not, unless
  `MCP_SDK_GENERATION=v1` or `MCP_PROTOCOL_NEGOTIATION=legacy` pins the earlier
  handshake. Tasks are an additional condition: the session must fetch feature
  flags, the call must come from the main conversation, and Anthropic must have
  enabled tasks for that session kind (public beta since v2.1.304). On such a
  connection every request carries the client's capabilities at
  `params._meta["io.modelcontextprotocol/clientCapabilities"]`, with
  `"io.modelcontextprotocol/tasks": {}` under `extensions` when the client
  supports tasks.
- `[client docs]` Revision 2026-07-28 moved Tasks out of the core protocol into
  the official extension `io.modelcontextprotocol/tasks`. The extension replaces
  the blocking `tasks/result` method with polling through `tasks/get`, adds
  `tasks/update` for client-to-server input, removes `tasks/list`, and lets a
  server return a task handle without a per-request opt-in flag.
- `[client docs]` A server may answer `tools/call` with a task only when the
  request carries that extension; otherwise the call fails with the tool error
  `Unsupported result type 'task' for tools/call`.
- `[client docs]` The task handle is the JSON-RPC result of the `tools/call`
  answer: `resultType: "task"`, `taskId` (at most 128 printable ASCII
  characters, no spaces), `status`, `createdAt`, `lastUpdatedAt`, `ttlMs` (may
  be `null`; the extension requires it, and recent versions tolerate its
  omission), optional `pollIntervalMs` (clamped to 250..30000, 2000 when absent
  or null, re-read from each `tasks/get` response) and optional
  `statusMessage`. The answer needs no `content` array.
- `[client docs]` Statuses are `working`, `input_required`, `completed`,
  `failed` and `cancelled`; the last three are terminal.
- `[client docs]` Right after the task answer Claude Code sends `tasks/get` with
  `{ "taskId": ... }`, then repeats it once per poll interval. Each `tasks/get`
  response must carry `resultType: "complete"` plus `taskId`, `status`,
  `createdAt`, `lastUpdatedAt` and `ttlMs`. On `completed` the normal
  `tools/call` result travels in the top-level `result` object; on `failed` the
  top-level `error` object `{ code, message, data }` carries the message Claude
  is told; on `cancelled` Claude is told `statusMessage`, or else
  `Task was cancelled by the server`.
- `[client docs]` Claude Code does not use `tasks/result`, `tasks/list` or
  `notifications/tasks`, so the outcome must be in the `tasks/get` responses. It
  sends `tasks/cancel` when Claude or the person stops the task while the server
  is connected, and not on exit. Cancellation is cooperative: the server
  acknowledges the intent and may still finish the work.
- `[client docs]` When a task settles, Claude learns the outcome from a task
  notification that the client raises; the server sends no notification of its
  own. A task that a person stopped is no longer followed, so its outcome is not
  delivered to Claude even if the server still had it.
- `[client docs]` A JSON-RPC error `-32602` is read as an unknown task id; for a
  background task Claude Code keeps asking for up to five minutes and then
  reports the outcome to Claude as unknown.
- `[client docs]` A task that needs input reports `input_required` with
  `inputRequests`, a map from a server-chosen key to `{ method, params }`.
  Claude Code answers each key once through `tasks/update` with
  `{ taskId, inputResponses }`, where `inputResponses` maps the same key to that
  request's result, and it ignores keys beyond 16 per task.
  `elicitation/create` is served only in interactive terminal sessions and
  `roots/list` everywhere; when the client cannot serve a request it asks the
  server to cancel the task.
- `[client docs]` `statusMessage` shown in `/tasks` comes from the latest
  `tasks/get` response, and a response that omits the field clears it.
- `[client docs]` Claude Code advises keeping a finished task's result for at
  least an hour, reporting `ttlMs` from creation (longest run plus retention),
  and sending `pollIntervalMs` 2000 for jobs shorter than a minute and
  10000..30000 for longer ones.
- `[client docs]` Tasks are not available in the VS Code extension, in local
  desktop sessions, in subagents, or in a one-shot `claude -p` run; they need the
  main conversation and feature-flag fetching.
- `[client docs]` Independently of tasks, a main-conversation tool call that is
  still running after two minutes is moved to a background task by Claude Code
  anyway, and the per-call wall-clock limit (`MCP_TOOL_TIMEOUT` or the
  per-server `timeout`) and the idle timeout (30 minutes for stdio servers)
  still apply until the server answers with the task; answered status checks
  count as activity for the idle timeout.
- `[client docs]` Protocol revision 2026-07-28 removes SSE stream resumability
  and message redelivery: a broken response stream loses the in-flight request
  and clients must re-issue it as a new request with a new request id. Every
  result carries a `resultType` field.
- `[client docs]` The extension text states that the server advertises the
  extension in its `server/discover` capabilities (`capabilities.extensions`),
  that a server must never return a task to a client that did not declare
  support, that the task should be durably created before the response is sent,
  and that `tasks/cancel` and `tasks/update` are acknowledged with an empty
  result.

## What the pinned SDK permits

The go.mod pin stays at v1.8.0; nothing here patches the SDK.

- `[pinned SDK v1.8.0]` The SDK has no tasks extension: no `tasks/get`, no
  `tasks/update`, no `tasks/cancel`, no task result type and no
  `CreateTaskResult`. It does have the plumbing the extension needs:
  `ServerCapabilities.Extensions` (and `AddExtension`), which the
  `server/discover` answer carries; `ClientCapabilities.Extensions`, and a
  per-request `ServerRequest.ClientCapabilities()` that reads `_meta` for the
  2026-07-28 revision; `mcp.AddReceivingCustomMethod`, which registers a
  non-standard method name with a `ParamsBase`/`ResultBase` parameter and result
  pair and refuses names that shadow standard methods; and
  `AddReceivingMiddleware`, which sees every request.
- `[pinned SDK v1.8.0]` Two limits matter. First, `checkRequest` rejects a
  method that is not registered before middleware runs, so `tasks/*` cannot be
  answered from middleware alone; each one must be registered as a custom
  method. Second, a tool handler must return `*mcp.CallToolResult`, whose
  `resultType` is unexported and admits only the empty value and
  `input_required`, so a task answer cannot come from a tool handler: it comes
  from a `tools/call` receiving middleware that returns its own `ResultBase`
  result, which the SDK serializes unchanged (its completion-type fix-up only
  matches the SDK's own result types).
- `[pinned SDK v1.8.0]` An SDK client can drive the whole task path.
  `ClientCapabilities.AddExtension` puts the extension into the per-request
  `_meta`; `AddSendingCustomMethod` and `CallCustomMethod` send `tasks/get`,
  `tasks/update` and `tasks/cancel` with `ParamsBase`/`ResultBase` types; and
  the `Transport` and `Connection` interfaces are public, so a decorator sees
  the raw JSON-RPC messages. The typed `CallToolResult` decodes a
  `resultType: "task"` answer into an empty result with no accessor for the
  handle, so the handle is read from the raw answer at the connection layer
  rather than through `CallTool`. The acceptance tests below use this shape for
  the task path and the fallback path alike.
- `[ssjack code]` The bridge builds its server with no options
  (`internal/bridge/internal/tooltext/registry.go`), so advertising the
  extension means passing `ServerOptions.Capabilities` with the current default
  (`Logging`) plus the `extensions` entry.
- `[pinned SDK v1.8.0]` A server has one capabilities set: `server/discover` and
  a legacy `initialize` answer both return it from the same options
  (`capabilities()` in `mcp/server.go`), so setting the entry exposes the
  extension in both answers; stripping it from one would take a receiving
  middleware that rewrites that result. `server/discover` is itself refused on a
  pre-2026-07-28 request, so the extension is only reachable through the modern
  path in any case.
- `[ssjack code]` The child bridge runs the SDK server over its own bounded
  stdio transport (`cmd/ssjack/internal/remotemcp/mcp_command.go`,
  `cmd/ssjack/internal/remotemcp/remote_mcp_connection.go`) whose allow-list
  admits exactly `initialize`, `notifications/initialized`,
  `notifications/cancelled`, `tools/list`, `tools/call`, `ping`,
  `server/discover` and `subscriptions/listen`, and answers every other method
  with method-not-found. The three `tasks/*` methods must be added to that list,
  and only for the 2026-07-28 revision.
- `[ssjack code]` The keeper is reached through one broker connection that
  serves one request at a time (`internal/broker/internal/brokercore/client.go`):
  `Call` applies its context to the connection and closes it when the context
  ends, while `CallWait` returns at once and reads and drops the reply the
  keeper still owes, keeping the client busy for at most the remaining wait.
  `jobwait` holds `MaxSeconds = 25` and four waiting slots per manager.
- `[ssjack code]` Job ids are 64 lowercase hex characters (`wire.RandomToken`);
  the transfer manager retains at most 64 records and evicts the oldest finished
  first, and the remote/application job manager has the same 64-record bound.
  Closing the keeper session cancels the running jobs (FILE-TRANSFER.md,
  "Cancellation and lifetime").

## Verification against the sources

Checked at implementation time against SEP-2663 (`seps/2663-tasks-extension.md` in modelcontextprotocol/modelcontextprotocol), the extension overview at modelcontextprotocol.io/extensions/tasks/overview, and the Claude Code page code.claude.com/docs/en/mcp ("MCP tasks that run on the server" and "MCP tasks for server authors").

Confirmed as this document assumed it, and implemented that way:

- A failed task is a successful `tasks/get` result whose `status` is `failed` and which carries the failure in a nested `error` object with `code` and `message`; the client reads that `message`. The envelope assumption in "Error behaviour" is settled this way.
- `tasks/get` answers carry `resultType: "complete"`; `taskId`, `status`, `createdAt`, `lastUpdatedAt` and `ttlMs` are required, `ttlMs` may be `null`, and this bridge always sends `7200000`.
- `pollIntervalMs` is optional, is re-read from every `tasks/get` answer, is clamped to 250..30000 and defaults to 2000 when absent, so 10000 is inside it.
- A `taskId` may be at most 128 printable ASCII characters without spaces, and a `CreateTaskResult` needs no `content` array but needs a `taskId` and a valid `status`.
- An invalid or nonexistent `taskId` is `-32602`: required for `tasks/get`, recommended for `tasks/update` and `tasks/cancel`. This bridge answers it for all three, as "Error behaviour" says.
- A tool result that ended with `isError: true` is `completed`; `failed` is reserved for a JSON-RPC error. The job mapping in "The final result" matches.

One requirement the first version of this document did not carry, now implemented:

- The extension makes it a MUST that a server answer `tasks/get`, `tasks/update` and `tasks/cancel` from a request that does not declare the extension with the JSON-RPC error `-32021` (Missing Required Client Capability) and the required extension in the error `data`. The bridge does that: on revision 2026-07-28 a task method whose request omits `io.modelcontextprotocol/tasks` under `_meta["io.modelcontextprotocol/clientCapabilities"].extensions` is refused with `-32021` and `{"requiredCapabilities":{"extensions":{"io.modelcontextprotocol/tasks":{}}}}` before any record or keeper call. `tools/call` is unaffected: it falls back to today's text instead.

Two advisory points on which this document stays stricter or quieter than the extension, because the client does not depend on them:

- The extension says a `tasks/get` answer for a `failed` task SHOULD carry a `statusMessage` with diagnostics; this bridge omits it and carries the fixed message in the nested `error` instead, so a status line is never repeated and a result never reappears as a message. The client reads the error message.
- The extension only recommends `-32602` for an unknown `taskId` on `tasks/update` and `tasks/cancel`; this bridge always answers it.

## Decisions

### Which tools carry a task

The first step gives a task path to `remote_upload` and `remote_download` only.
They run long, the model polls them most, and `[ssjack code]` the manager already
refuses a second job for the same destination, which bounds a duplicate start.

`remote_exec` and `app_exec` get no task path in this step: they keep
`Started job <job_id>` and the polling tools exactly as they are. Their task path
is a separate design with prerequisites the code does not meet yet ("Later
design: exec and application tools" below).

Never, in any step: `transfer_status`, `transfer_cancel`, `remote_read`,
`remote_cancel`, `app_read`, `app_cancel`, `remote_targets`, `app_list` and the
declarative `resource_plan`/`plan_apply`. They are short calls, and a task would
add a second way to do what the tool already does.

The task path replaces the polling path for a supporting client; it does not add
a parallel one.

### Identity, lifetime and bounds

- One task per job, and the task id is the job id, with no prefix: 64 lowercase
  hex characters are printable ASCII without spaces, well inside the
  128-character limit, already unique within the session and already printed to
  the model today, so no new identifier and no new information reach it. The
  record also stores that it came from the two transfer tools, which fixes the
  keeper operations it uses: `transfer_status` to read and `transfer_cancel` to
  cancel.
- A task exists only after the keeper returned a job id. A refused start has no
  job id and therefore no task: it answers today's error result unchanged (the
  tool error flag set) and never a task.
- A task belongs to the bridge session that created it. `tasks/get` and
  `tasks/cancel` for an id this session did not create, or never issued, answer
  JSON-RPC `-32602`, the same error for every unknown id, so a probe learns
  nothing about another session.
- `[assumption]` Records are RAM-only and die with the child bridge process.
  This is a deliberate divergence from the extension's durability rule: the
  transport is stdio, the bridge process is a child of the harness session, and
  jobs are already cancelled when that session closes. A client that resumes the
  conversation later and asks a bridge about the task, a live bridge answers
  `-32602` (a stopped bridge answers nothing, see failure modes);
  `[client docs]` the client reports the outcome as unknown.
- `ttlMs` is reported as `7200000` from creation and is an advisory hint, not a
  deadline: `[ssjack code]` the transfer path has no wall-clock limit (its bounds
  are the byte and entry limits), so a job may outlive any value this document
  could promise, and `[client docs]` the client does not drop a task because
  `ttlMs` passed.
- `[assumption]` A task freezes when the bridge first observes a terminal job
  status, or when a fatal read failure ends it ("Error behaviour" below); its
  state and result text are then fixed in the record and kept for one hour from
  that moment. Until it freezes, a record has no time limit and only the 64-record
  bound evicts it: the bound drops the oldest frozen record first and, when none is
  frozen, the oldest record at all. A dropped handle answers `-32602` (error
  behaviour below). A client that stops polling can therefore lose its handle to
  the bound, and the keeper may evict the job itself first (failure modes).
- Closing the keeper session or the bridge cancels the running jobs exactly as
  today (FILE-TRANSFER.md, "Cancellation and lifetime"); `[ssjack code]` the
  records vanish with the process.

### Status message content

`statusMessage` is built from the fields `transfer_status` already publishes and
follows the same rules the status record follows: no local or remote path, no
remote stderr, no file content, only state names, phase names, mode names,
counters and fixed messages. It is the status text's field lines - the `Phase`,
`Bytes`, `SHA-256`/`Manifest SHA-256` and `Failed`/`Cancelled` lines of
FILE-TRANSFER.md, "Result text" - joined with ` · `, without the headline and
without the hint line; it is omitted when no field line exists.

- A running chunked upload: `Phase: transfer · Mode: chunked · Chunks: 12/64 ·
  Attempts: 3 · Bytes: 52,428,800 · Files: 0 · Dirs: 0 · Speed: 1.3 MB/s`.
- `completed` and `failed` omit `statusMessage`, so it never repeats a result.
  Freezing drops the progress message of an earlier poll instead of carrying it
  into a terminal state. `cancelled` carries the fixed line `Cancelled job
  <job_id>`: a fixed message, not a result, because `result` is defined for a
  completed task only.
- `createdAt` and `lastUpdatedAt` are RFC 3339 in UTC with whole seconds;
  `lastUpdatedAt` changes while the task is not frozen, whenever a read returns
  a keeper record that differs from the previous one - not merely when the
  rendered text differs - and stops changing once the task freezes.

`[ssjack code]` The line reuses the transfer status renderer
(`internal/bridge/internal/tooltext/render.go`), so a field can never appear in a
status message that the transfer status text could not carry.

### The final result

Only a `completed` task carries `result`, with exactly one text content block, no
structured content and no output schema, the same shape the transfer tools answer
with today; it passes the same output guard and the same masking, and the
transport's write path bounds it.

- Transfers: byte-for-byte the terminal `transfer_status` text of the finished
  job, including the `link_unstable` resume hint when it applies, so the model
  sees exactly what it would see after polling to the end. The one exception is
  a terminal record the keeper already evicted (failure modes): that task ends
  `failed` instead of inventing text.
- `[assumption]` A job outcome never maps to the task status `failed`, because a
  failed job is a normal text result today (a failed transfer is text without the
  tool error flag). `failed` is reserved for the task machinery, with
  `error.code -32603` and the fixed message `the task could not be read`; it
  carries no job data and claims nothing about the job.
- No command or application output is part of a task result in this step,
  because those tools have no task path here.

### Cancel

- `[client docs]` The extension acknowledges a cancellation with an empty result.
  The bridge validates the task id against its own record first: an unknown id, a
  foreign id or an expired one answers JSON-RPC `-32602` with no keeper call. For
  a known id it issues the existing `transfer_cancel` operation on the same keeper
  connection as every other call and answers with an empty result when that call
  returns. The acknowledgement is therefore not "at once": it queues behind
  whatever holds the connection, exactly like the read in "Keeper connection".
- `[ssjack code]` The reply says only what the manager knew when it looked:
  `Cancelled: true` means the job was not finished and its cancellation was
  requested, and `Cancelled: false` means the job was already terminal, which
  includes a job that was already cancelled
  (`internal/transfer/internal/manager/manager.go`). After a `true` reply the job
  still reaches whatever terminal state its own run produces, so a transfer that
  had already finished successfully can end `done`.
- The task state therefore always comes from the following status record, never
  from the reply:
  - the reply records only that a cancellation was requested, for the owner's
    question 4 and for no other purpose;
  - each `tasks/get` reads the record; while the record reports `running` the task
    stays `working`;
  - the first read that returns a terminal record decides the task: `cancelled`
    with the fixed line `Cancelled job <job_id>` and no `result`; `done` as
    `completed` with the terminal status text; a failed job also as `completed`
    with its text, because a failed job is a normal text result today.
- Cancellation is therefore eventual and unconfirmed: the bridge cannot promise
  that the job stops, only that the request was passed on and what the record
  later says. `[ssjack code]` The operation signals the job's context; what
  happens to a chunked transfer's staged parts is the engine's separate cleanup,
  which keeps them for `link_unstable` and ignores removal errors
  (`internal/transferengine/internal/engine/chunkupload.go`,
  `internal/transferengine/internal/engine/chunkdownload.go`). Neither the
  acknowledgement nor the reply says anything about staged parts, and the task
  result is today's status text, which is the only place the client learns
  anything about them. Closing the connection still does not prove detached
  remote processes stopped (FILE-TRANSFER.md, "Cancellation and lifetime").
- A frozen record is never changed by `tasks/cancel`: the bridge makes no keeper
  call, answers with the empty result and leaves the record, so a client that
  cancels after it has already seen a terminal state cannot lose that state
  (the handle stays queryable until the hour or the 64-record bound ends it).
- For a record that is not frozen, a keeper that answers that the job is unknown
  (the keeper evicted it) leaves nothing to cancel: the record is dropped and the
  answer is the one "Error behaviour" gives for `tasks/cancel`. Any other failure answers with that
  table's code and leaves the record unchanged.
- `confirm` is not part of this path: `confirm=true` stays a start-call argument
  and is never requested through a task.

### Error behaviour

One table covers the three methods. "Handle unknown" means this bridge has no
record for the id: never issued, already dropped, or another session's. "Keeper
job evicted" means the record exists but the keeper no longer knows the job. A
"read error" is a well-formed error reply from the keeper; a lost attachment is an
exchange or connection failure, which closes the client.

| Method | Handle unknown | Keeper job evicted | Read error | Lost attachment |
| --- | --- | --- | --- | --- |
| `tasks/get` | `-32602`, no keeper call | successful result: task freezes `failed` with nested `error` `-32603`, `the task could not be read` | JSON-RPC error response `-32603` with the same fixed message; no state transition, the task stays `working` and the next poll tries again | successful result: task freezes `failed` with nested `error` `-32603`, `the task could not be read` |
| `tasks/cancel` | `-32602`, no keeper call | unfrozen record: `-32602`, the record is dropped; frozen record: empty result, no keeper call, record unchanged | `-32603`, `the cancellation could not be requested`; the record is unchanged | same as a read error; the record is unchanged |
| `tasks/update` | `-32602` | empty result, nothing changed | never calls the keeper | never calls the keeper |

- `[client docs]` `-32602` is the extension's unknown-task error; `-32603` is an
  internal error, and its fixed message travels as the error text.
- The extension also requires `-32021` (Missing Required Client Capability)
  for a task method from a request that does not declare the extension. The
  bridge answers that error with the required extension in `data` and touches
  no record; "Verification against the sources" records the requirement.
- Envelope: a frozen `failed` task is a successful `tasks/get` result whose task
  status is `failed` and which carries the failure in a nested `error` with
  `code` and `message`; a retryable read error is a JSON-RPC error response
  and changes nothing in the record. The two are never mixed: an error response
  never freezes a task, and a frozen task is never reported as an error
  response.
- Why the split: a well-formed error reply means the keeper is alive and the
  transport still works, so the next poll can succeed and the task is not ended; a
  lost attachment means no later read can succeed, so the task is frozen `failed`
  instead of staying `working` for ever.
- A frozen state is final: a `failed` task never becomes `completed` later, and a
  later keeper eviction cannot change a frozen record, because frozen reads no
  longer reach the keeper.

### Advertisement and fallback

- `[client docs]` The extension's negotiation mechanism is the `extensions`
  field: a server advertises it in `server/discover`, and a client declares it in
  the per-request `_meta`.
- `[pinned SDK v1.8.0]` The bridge sets one capability set
  (`ServerOptions.Capabilities`, the current default `Logging` plus
  `"io.modelcontextprotocol/tasks": {}`), and the SDK serves it from both
  `server/discover` and a legacy `initialize` answer (`capabilities()` in
  `mcp/server.go`). The rule is therefore: the entry is visible in both answers.
- What a legacy client can see, stated once: its `initialize` result carries the
  extension, and it can do nothing with it, because a task needs the 2026-07-28
  per-request declaration and the stdio transport refuses every `tasks/*` method
  on an earlier revision (`cmd/ssjack/internal/remotemcp/remote_mcp_connection.go`).
  Its tool results are unchanged. Nothing is stripped from the initialize result
  and no middleware rewrites it.
- A `tools/call` becomes a task only when all four hold: the request uses
  revision 2026-07-28; its
  `params._meta["io.modelcontextprotocol/clientCapabilities"].extensions`
  carries `io.modelcontextprotocol/tasks`; the tool has a task path (the two
  transfer tools, in this step); and the keeper returned a job id. The
  declaration is read from the request's own `_meta`: the revision and
  capabilities an earlier `server/discover` or `initialize` stored in the SDK
  session never make a later request eligible, and the same rule governs
  `tasks/get`, `tasks/update` and `tasks/cancel`. Anything else takes today's
  path and produces today's bytes.
- No new startup flag and no owner registration: the fallback is the existing
  behaviour, and the tool descriptions keep the polling step, gaining one
  sentence for the task case.
- Strict fallback: a task result is never returned without the extension in the
  request; a start call that fails for any reason answers today's error result
  with the tool error flag; a client on an earlier revision gets
  method-not-found for every `tasks/*` method.

### Keeper connection

The constraint: one keeper connection serves one request at a time.
`[ssjack code]` The keeper reads a request, runs the handler and writes the reply
in one loop, so a second request is read only after the first reply is written
(`internal/broker/internal/brokercore/server.go`; FILE-TRANSFER.md, "Waiting
calls").

- Mechanism: there is no follower and no cached status. Until it freezes, a
  `tasks/get` performs the existing status read (`transfer_status` with
  `wait_seconds` 0) on demand, on the ordinary call path, and reports what that
  read returns; the first terminal status it sees freezes the task (above), and
  every later `tasks/get` returns the frozen record without a keeper call.
- `[ssjack code]` The broker client serialises calls on one mutex
  (`internal/broker/internal/brokercore/client.go`). A caller waits for that mutex
  with no timer, so a queued call has no upper bound from the source: it takes as
  long as the callers ahead of it and the holder need. Once a call holds the mutex
  it arms its own exchange deadline, 30 s for an ordinary call and 35 s (the
  longest wait plus a margin) for a waiting call; those budgets bound one
  exchange, not a queue, and an abandoned waiting call keeps the mutex busy until
  the reply it still owes arrives under that same deadline.
- What a client can rely on: a `tasks/get` either returns the record of the read it
  made or an error. It may take as long as the connection is busy, including
  behind another tool's `wait_seconds` call, and the bridge neither truncates the
  wait nor fails it early. Nothing here is a freshness or latency guarantee: two
  polls can return the same record, a poll can return one that changed since the
  previous poll, and a poll can be delayed by the queue with no bound the bridge
  can state.
- While a task is not frozen, a read changes no keeper state but is not free of
  effect on the bridge: it updates `lastUpdatedAt`, and an error is handled by
  "Error behaviour". Two identical polls can therefore differ in what the client
  sees. Once the task is frozen, a poll returns the record and changes nothing.
- `pollIntervalMs` is 10000, inside the client's clamp: while the task is not
  frozen, every poll is one keeper round trip on the shared connection, so a
  shorter interval buys little and costs a call that other tools queue behind.
  `[client docs]` The client reads the value again from every `tasks/get`
  response.
- What does not change: a fallback client, and a model in a session without tasks,
  poll with waits exactly as today, and the four waiting slots per manager are
  untouched. A session that uses both a task and a model `wait_seconds` call sees
  them queue on one connection, as today.
- Deadline: the read's own exchange must finish inside its 30 s budget. An exchange
  that fails closes the attachment (the broker client closes the connection on a
  failed exchange), which "Error behaviour" treats as fatal.

### input_required

- Not used in the first step. The bridge never returns `input_required` and
  never populates `inputRequests`, so no job can pause for an answer. `confirm`
  stays a start-call argument that records caller acknowledgement only
  (FILE-TRANSFER.md; APP-CONTRACT.md, "Commands and confirmation").
- `tasks/update` is still implemented, because a client may send it: it
  acknowledges with an empty result and ignores unknown or already-satisfied
  keys, which `[client docs]` is what the extension asks for. It changes no
  state.
- Consequence for the owner: a job that would need an answer cannot ask for one,
  so the model must pass `confirm=true` up front or the call is refused.
  `[client docs]` A non-interactive session cancels a task that asks for input,
  which is a second reason not to ask.
- The elicitation and MRTR question, a server-initiated question a model could
  answer while a task runs, is task #475 and out of scope here.

### Trust boundary

What reaches the model through a task that does not reach it today: nothing new.
What the model gains is the same information in one place:

- the task id is the job id it would have received in the `Started job` line
  anyway;
- the status vocabulary, the counters, the mode and phase names and the fixed
  messages are the fields `transfer_status` already returns;
- `createdAt`, `lastUpdatedAt`, `ttlMs` and `pollIntervalMs` are new metadata,
  but they describe the task record only, never the job, the owner's file
  system, the remote host or the vault;
- the final result is byte-identical to the polling path's final text, except
  when the keeper had already evicted the record, which ends the task `failed`,
  and a cancellation reports today's `Cancelled job <job_id>`.

Not reachable, and each answered the same way:

- another session's jobs: an unknown or foreign handle answers `-32602` from
  `tasks/get` and `tasks/cancel` alike, so a probe cannot address another
  session's job; a known handle only ever reports its own record (see "Error
  behaviour" for what a known handle says when its keeper job is gone);
- a local or remote path, a file name inside a root, remote stderr, or command
  output outside the existing bounded read formats;
- any vault material, credential or bootstrap value; the client's extension
  declaration is neither logged nor stored.

Authority: a task grants no authority the tool did not already have.
`tasks/cancel` reaches the same cancel operation the cancel tools reach, with
the same authorization and the same best-effort remote semantics. Records are
content-free, bounded to 64 and RAM-only.

Masking and the output guard are unchanged: the status message and the final
text are built by the same renderers and pass the same guard, and a task result
is an ordinary tool result as far as the guard and the transport's write path are
concerned.

One asymmetry to keep in mind: the status message travels to the harness task
list (`/tasks`), not only into the model's context. It carries the same
content-free fields the status text carries, so this is not a new exposure, and
it is the reason the field list above is fixed rather than free text.

### Failure modes

- A failed status read. "Error behaviour" splits this: a well-formed error reply
  answers `-32603` and leaves the task `working`, because the next poll can
  succeed; a lost attachment freezes the task `failed` with the fixed message
  `the task could not be read`, because no later read can succeed. Either way the
  failure says nothing about the job: an IPC failure is not evidence that the job
  stopped or failed. The model can still poll by job id while the attachment is
  usable, because the task id is the job id.
- The keeper attachment ends. `[ssjack code]` When the bridge's serving loop
  returns it closes the keeper client
  (`cmd/ssjack/internal/remotemcp/mcp_command.go`), the keeper shuts the attached
  connection down (`internal/broker/internal/brokercore/server.go`), and the
  managers cancel their jobs with that session's context
  (`internal/transfer/internal/manager/handle.go`). The task records are RAM-only
  in the bridge process. A client whose bridge has exited gets a transport error,
  not `-32602`: only a live bridge can answer that, so what the client sees
  depends on whether a bridge is running in its session.
- Client restart or a resumed conversation. The bridge process is gone with the
  session and the records with it: a poll finds no bridge at all, or a live
  replacement bridge that answers `-32602`, and `[client docs]` Claude Code keeps
  asking for up to five minutes before it reports the outcome as unknown. Nothing
  claims the work survived.
- Lost message. This transport is stdio with one in-order stream. What the code
  establishes here is the shutdown above; the revision's rule that a lost
  response is re-issued as a new request belongs to Streamable HTTP and is not
  applied to this transport.
- Duplicate start. A re-issued start call is a new job attempt. While the first
  job runs, the destination lock refuses the second (`another transfer is using
  this destination`). After the first job ends the second call does what a
  repeated call does today: without `overwrite` it finds the destination present
  (`exists`) or resumes the staged parts, and with `overwrite` plus `confirm` it
  copies again; the bridge adds no de-duplication.
- The keeper evicts the finished job before the task freezes. `[ssjack code]` The
  transfer manager keeps 64 records and, on a start that finds the set full, evicts
  the oldest finished job (`internal/transfer/internal/manager/manager.go`). One
  start is enough when that record is the target and the set is full. The read then
  reports an unknown job and `tasks/get` freezes the task `failed` with the fixed
  message. After the task has frozen, a later eviction changes nothing: `tasks/get`
  no longer reads the keeper.
- Task record eviction or expiry. A frozen record is dropped one hour after it
  froze, or earlier when the 64-record bound needs room; an unfrozen record is
  dropped only by that bound, as above. A dropped handle answers `-32602` from a
  live bridge.
- Repeated `tasks/get`: before the task freezes, each one is a fresh read that
  changes no keeper state and costs one keeper round trip and one queue position,
  so two reads of one id can differ; after it freezes, each one returns the same
  frozen record and costs no keeper call.

### Acceptance tests

Every check runs on one attachment. `[ssjack code]` A keeper attachment is
single-use (`internal/broker/internal/brokercore/server.go`), so two clients never
share one keeper connection, and nothing below needs them to.

- In-process test, real broker client, fake keeper, one bridge. The bridge is
  built over a real `broker.Client` attached to a `broker.Listen` keeper whose
  handler the test controls (the fixture pattern of `internal/bridge/wait_test.go`),
  and the MCP side is an `mcp.IOTransport` session, so the client-side queueing and
  the keeper's serial dispatch are both real. It covers:
  - queueing: the keeper handler parks on a channel while it holds the first
    request; a fallback tool call takes the connection; a `tasks/get` is issued on
    the same connection. The test REQUIRES the broker-mutex observation before it
    releases anything: it probes a `flakediag.GoroutineDump` for the broker
    client's mutex wait through `flakediag.WaitForDesc` and fails the test when the
    probe reports `done` false, because `flakediag.WaitFor` neither fails on
    timeout nor returns its success flag (`internal/flakediag/poll.go`). Only after
    that requirement holds does it release the handler and assert that the
    `tasks/get` answered from a read that ran after the release. It does not infer
    queueing from the keeper handler alone: the keeper dispatches requests
    serially, so a handler that sees no second operation proves nothing about the
    client.
  - acknowledgement ordering: the keeper handler signals when it has entered the
    `transfer_cancel` operation and then parks; the test waits for that signal,
    asserts that no `tasks/cancel` reply has arrived, releases the handler and
    asserts the empty result. Requiring the entry signal is what makes the
    assertion meaningful: without it the test could pass merely because the
    request had not reached the keeper yet.
  - cancellation outcomes come from the record, tested as independent
    combinations of the reply and the following records: `true` then `running`
    then `cancelled` ends `cancelled`; `true` then `done` ends `completed`
    (success just before the cancel took effect); `false` then `cancelled` ends
    `cancelled` (already cancelled); `false` then `failed` ends `completed` with
    the failure text; `false` then `done` ends `completed`. The fake keeper must
    not pair `true` with `cancelled` and `false` with `completed` only: a bridge
    that chooses the state from the reply has to fail the second and third cases.
  - `tasks/get` on an unknown, foreign or expired handle answers `-32602` and
    leaves the keeper with no recorded operation.
  - `tasks/get` after the keeper evicted the job answers a successful result
    whose status is `failed` with nested `error` `-32603` and the fixed message
    (not a JSON-RPC error response); a second `tasks/get` still answers the same
    successful frozen record, and the fake keeper records no further operation.
  - `tasks/get` on a well-formed keeper error reply answers a JSON-RPC error
    response `-32603` with no state transition, and a later successful read still
    completes the task.
  - `tasks/get` after a lost attachment answers a successful result with status
    `failed` and nested `error` `-32603`, and the next `tasks/get` returns the
    same frozen record (also as a successful result).
  - `tasks/cancel` on an unknown handle answers `-32602` with no keeper operation;
    on an unfrozen record after eviction it answers `-32602` and drops the record;
    on a keeper error reply it answers `-32603` and leaves the record;
  - `tasks/cancel` on a frozen record: the client has already polled to a terminal
    state and the keeper then evicts the job; `tasks/cancel` answers the empty
    result and the following `tasks/get` returns the same frozen record, and
    neither makes a keeper call.
  - `tasks/update` on an unknown handle answers `-32602`; on a known handle it
    answers an empty result with no keeper operation.
  - frozen state: after a `tasks/get` returns a terminal record, the fake keeper
    drops the job and records no further operation; the next `tasks/get` returns
    the same state and text, and `lastUpdatedAt` is unchanged.
  - record eviction: the fixture has two frozen records where the earliest-created
    is not the earliest-frozen, and the 64-record bound evicts the earliest-frozen
    record.
  - equality: for a finished record, the completed task's
    `result.content[0].text` equals the text the same bridge returns from
    `transfer_status` for that job, byte for byte, including the `link_unstable`
    hint when the record carries it.
  - advertisement: the `initialize` result of a legacy connection and the
    `server/discover` result of a 2026-07-28 connection both carry the extension,
    and `tasks/get`, `tasks/update` and `tasks/cancel` are method-not-found on the
    legacy connection.
  - eligibility: a bare `tools/call` as the first tool call after a declaring
    discovery answers today's text.
- Launched-bridge tests, one bridge and keeper per client kind.
  - Fallback pin: an `mcp.NewClient` with default capabilities over
    `mcp.CommandTransport` (the pattern of `cmd/ssjack/internal/transfertest`)
    calls `remote_upload`, `remote_download`, `remote_exec` and `app_exec` and
    asserts today's exact text, that the descriptions still describe the polling
    step, and that no task result appears. It compares literal strings taken from
    FILE-TRANSFER.md and REMOTE-MCP.md, so it can fail.
  - Task path: a second `mcp.Client` declares the extension through
    `ClientCapabilities.AddExtension`, connects over `mcp.CommandTransport` with a
    `Transport` decorator that records the raw `tools/call` answer, registers
    `tasks/get`, `tasks/update` and `tasks/cancel` with
    `mcp.AddSendingCustomMethod`, and drives them with `mcp.CallCustomMethod`. It
    asserts the handle fields (`resultType` `task`, `taskId` equal to the job id,
    `status` `working`, `pollIntervalMs` 10000, `ttlMs` 7200000, RFC 3339
    timestamps), one `tasks/get` answer with `resultType` `complete`, and that
    both `remote_exec` and `app_exec` still answer `Started job` here.
- Discovery probe. `[pinned SDK v1.8.0]` The SDK's legacy connect path never sends
  `server/discover` (`mcp/client.go` takes the discover branch only for
  2026-07-28 and later), so the legacy refusal of `server/discover` is checked
  with an explicit raw request on that connection, not with a client call.
- Status text. Each `statusMessage` equals the golden string built from the
  record's fields, for example `Phase: transfer · Mode: chunked · Chunks: 12/64 ·
  Attempts: 3 · Bytes: 52,428,800 · Files: 0 · Dirs: 0 · Speed: 1.3 MB/s`, so
  `12/64` and `MB/s` are expected content and no blanket separator ban applies.
  Canary strings - a remote path marker and a root-relative local path marker
  planted in the `tools/call` start arguments, and a remote stderr marker and a
  secret-looking marker planted in a keeper ERROR reply (a generic keeper error
  is answered with the fixed `-32603` message, so its text must never reach the
  wire) - are asserted absent from the full raw JSON of the task handle, of every
  `tasks/get` answer and of the `tasks/cancel` acknowledgement, in both the
  in-process and the launched-bridge test; a keeper `Message` on a record is
  legitimately rendered as a field and is therefore not a canary carrier. The
  final result is compared only against the status text it is defined to equal.
- Stability. The timing-sensitive checks (queueing, acknowledgement ordering, the
  one-hour retention, the 64-record bound) run on injected clocks or timers the
  way `jobwait.Timer` and the manager already do, and every wait is
  `flakediag.Begin` / `OnFailure` plus `flakediag.WaitFor` or `WaitForDesc` with a
  deadline; there is no bare sleep.
- CI gate. The new tests live in packages the diff selector already owns
  (bridge, transfer, remotemcp), so an ordinary feature push runs them on the
  three platforms; a sprint completion still needs `[ci:full]` (docs/CI.md), and
  scoped success is not a full gate.
- Where they live: the in-process checks are the task tests of package
  `internal/bridge` with the record set's unit tests in
  `internal/bridge/internal/tasks`; the launched-bridge checks are
  `cmd/ssjack/internal/mcptasktest`, which spawns the production stdio bridge
  as a child process for the fallback pin, the task path with its canary
  assertions, and a raw legacy probe.

### Implementation order and non-goals

Each step is independently mergeable:

1. This document and the cross-links in FILE-TRANSFER.md, APP-CONTRACT.md and
   REMOTE-MCP.md. No behaviour change.
2. Transport method surface: admit `tasks/get`, `tasks/update` and `tasks/cancel`
   for revision 2026-07-28 only, still method-not-found on earlier revisions.
   Tests only, no advertisement, no behaviour change.
3. Task records and handlers in the bridge: the 64-record bound, the one-hour
   retention counted from the read that shows a terminal state, an injected clock,
   `tasks/get` over the on-demand status read, `tasks/cancel` over
   `transfer_cancel` with the follow-up status record as the outcome, and `-32602`
   for unknown ids. Unit tests with a real broker client and a fake keeper; not
   advertised yet, so no client can see them.
4. Transfers: the `tools/call` interception for `remote_upload` and
   `remote_download` together with the advertisement, landed in one step so a
   supporting client never sees an advertised extension without a task path.
5. The acceptance tests below and their CI wiring.
6. Exact-SHA review, CI on the three platforms, then the full gate at sprint
   completion.

State in the tree: steps 1-5 are landed;
steps 2-5 are covered by tests.

- Step 1: this document and the cross-links in FILE-TRANSFER.md,
  APP-CONTRACT.md and REMOTE-MCP.md.
- Step 2: the bridge's stdio transport admits `tasks/get`, `tasks/update` and
  `tasks/cancel` on revision 2026-07-28 only, and answers method-not-found on
  every earlier revision (`cmd/ssjack/internal/remotemcp`).
- Step 3: the bounded RAM-only record set, the one-hour retention, the
  injected clock and the three method handlers are
  `internal/bridge/internal/tasks`, with their unit tests beside them.
- Step 4: the advertisement (both `server/discover` and the legacy
  `initialize` answer), the `tools/call` interception for the two transfer
  tools and the tool-description sentence are
  `internal/bridge/internal/tooltext/registry.go`. The interception runs the
  tool's own handler, so the input schema, the keeper start and the refusal
  result are the transfer tool's.
- Step 5: the in-process acceptance tests are the task tests of package
  `internal/bridge` (real `broker.Client`, fake keeper, SDK server over an
  in-memory transport); the launched-bridge tests are
  `cmd/ssjack/internal/mcptasktest`.

Non-goals: channels and any server-initiated request; `notifications/tasks` and
delivery over `subscriptions/listen`; `tasks/result` and `tasks/list`; logging
(`notifications/message`); resource subscriptions; durable or on-disk tasks and
resume across a bridge or keeper restart; a task path for `remote_exec` and
`app_exec` (a later design with its own prerequisites); `input_required`,
elicitation and MRTR (task #475); a task for the declarative tools,
`remote_targets`, `app_list` or the read, status and cancel tools; SSE, HTTP or
WebSocket transport work for these tools; any new secret, path, remote output or
retained command output in a task record; a new startup flag or owner
registration; and any change to `wait_seconds` or to the polling path for
clients without the extension.

## Later design: exec and application tools

A task path for `remote_exec` and `app_exec` is specified in
[MCP-TASKS-EXEC.md](MCP-TASKS-EXEC.md). Both prerequisites it needed have
landed:

- A truthful cancel result from the command and application job managers.
  `[ssjack code]` `Cancel` answers `Cancelled: true` only when the job had
  not yet recorded a terminal state and the cancellation was requested, and
  `Cancelled: false` for a job that already ended, keeping its own recorded
  outcome; `app_cancel` delegates to the same manager
  (`internal/remote/internal/jobs/jobs.go`, `Cancel`;
  `internal/application/application.go`).
- A paged output contract with real offsets: docs/EXEC-OUTPUT-PAGING.md
  (decisions D1–D7), under which an exec task result carries no command
  output and the model fetches pages with `remote_read`/`app_read`.

No exec or application task behaviour is specified in this document. The
prerequisites above are landed, and the separate design that uses them is
[MCP-TASKS-EXEC.md](MCP-TASKS-EXEC.md).

## Open questions for the owner

The first eight are design choices; the last four are the uncertainties this
document cannot settle from the sources and which the accepted design leaves
open.

Resolved at implementation: every question below already carried a stated default, and every default is the behaviour now in the tree; no question was decided against its default. The list stays as the owner's record of what can still be changed, and it no longer blocks the implementation.

1. Advertisement gating: advertise the extension unconditionally in full mode
   (the default here), or behind a startup flag so an owner can keep tasks out of
   the harness task list?
2. `pollIntervalMs`: 10000 (the default, one keeper round trip per poll), or a
   shorter interval for small transfers at the cost of more calls that other
   tools queue behind?
3. Retention: one hour from the moment the task freezes, with the 64-record bound
   dropping the oldest frozen record first (the default), or longer, at the cost
   of memory?
4. Cancel and staged parts: neither the acknowledgement nor the reply says
   anything about a chunked transfer's staged parts, and the task result carries
   only today's status text (the default). Should the design surface anything
   about them, or leave it there?
5. Status detail: the full field-line list in `statusMessage` (the default), or
   only the state word, to show less in the harness task list?
6. Failure status: `failed` only when the record cannot be read (the default), or
   should a task also report `failed` for a job that ended with an error class?
7. Cross-session addressing: keep task ids scoped to the bridge session that
   created them (the default), or make a finished task resolvable by a second
   session on the same keeper, which would need keeper-side state?
8. Client limits: state once here which harness surfaces cannot receive tasks
   (VS Code extension, local desktop sessions, subagents, one-shot runs) — the
   default — or leave it out of the documentation entirely?
9. A bound for the queue: a single waiting call's broker exchange is bounded by
   its 35 s budget, but the queue ahead of it has no source-defined deadline, so a
   poll can wait behind other callers for an unbounded time. Should the bridge cap
   the queue wait (failing the read instead of waiting) and at what value, or
   leave it as it is?
10. Acknowledgement latency for `tasks/cancel`: the empty result waits for the
    keeper's cancel reply, because that is how an evicted job becomes `-32602`.
    Should the bridge accept the delay (the default), or acknowledge before the
    cancel and lose the `-32602` case?
11. Retention of unpolled jobs: a terminal state is first observed by a read, so a
    job that finishes while nobody polls can be evicted from the keeper's
    64-record set before the bridge ever sees it, and the task then ends `failed`.
    Is that acceptable, or does the keeper need a longer retention for tasks?
12. A stopped bridge: a client whose bridge exited gets a transport error, not
    `-32602`, because no process is left to answer. Is that acceptable, or should
    something in the harness surface a fixed message instead?

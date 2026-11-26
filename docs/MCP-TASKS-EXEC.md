# MCP tasks for the ssjack exec and application tools

Status: design. It specifies the MCP Tasks extension
(`io.modelcontextprotocol/tasks`) for `remote_exec` and `app_exec`, the two
tools that start command and application jobs. It builds on the transfer-task
design in `docs/MCP-TASKS.md` (structure, record store, extension gate,
advertisement, error envelopes) and on the paged output contract in
`docs/EXEC-OUTPUT-PAGING.md` (decisions D1–D7, binding here). Both
prerequisites named by the transfer design have landed in the tree: the
truthful cancel of the command and application job managers
(`internal/remote/internal/jobs/jobs.go`, `Cancel` distinguishes an ended job;
`internal/application/application.go` delegates `app_cancel` to the same
manager), and the paged output contract.

The tags below mark the source of every statement in this document.
`[client docs]` is taken from the sources the transfer design cites
(code.claude.com/docs/en/mcp, the extension overview and SEP-2663); this
document does not re-verify them, it cites the parent's findings.
`[pinned SDK v1.8.0]` likewise. `[ssjack code]` is observed in this repository; it is followed by the
parenthesised file reference, in the style of docs/MCP-TASKS.md, for example
"`[ssjack code]` (`internal/remote/internal/jobs/jobs.go:309-322`)". The Decisions section records the choices delegated by the owner to the implementer.

## Why

`remote_exec` and `app_exec` answer `Started job <job_id>` at once and the
model polls `remote_read`/`app_read`, optionally with `wait_seconds` up to 25
(`[ssjack code]` (`internal/bridge/internal/tooltext/registry.go`), `startTool` and
`readTool`; docs/REMOTE-MCP.md, "Result text of the ssjack tools"). The costs
are the ones the transfer design lists: every poll floods the chat, a waiting
call occupies the single keeper request slot of its connection, and only the
model can cancel. `[client docs]` The MCP Tasks extension lets a supporting
client follow and cancel the job itself.

The exec tools differ from the transfers in one decisive way: a command job
carries output, and the transfer design forbids command output in a task
record (docs/MCP-TASKS.md, non-goals). The paged output contract settles this:
the task result carries no output at all (D1), only status, exit code, resume
offsets and flags, and the model fetches pages with the read tools it already
has. This document is that contract applied to the task path.

The decisions of this document, and the section that takes each one:

| Decision | Taken here | Section below | Rejected alternative and reason |
| --- | --- | --- | --- |
| Tool scope | `remote_exec` and `app_exec` only, and only for a client that declares the extension | Tool scope and activation | A task path on the read and cancel tools too: a second way to do what those short calls do, and the record would have to carry output, which D1 forbids (stated under "Tool scope and activation") |
| Identity and record | Task id is the job id; the record holds state, exit code, offsets and flags, and never command output, command text, a path or a secret | Task identity and record | A new bridge-chosen task id with a prefix: a new identifier and no new information, where the job id is already unique, printable and printed to the model today |
| State mapping | A nonzero exit or a remote error is a command outcome: the task ends `completed` with it in the result text; `failed` stays machinery-only | State mapping | Mapping a nonzero exit to `failed`: the machinery's nested `error` replaces the exit code and loses it (justified in "State mapping") |
| Learning the state | Every `tasks/get` is one ordinary read at offset 0 whose chunk bytes are discarded before rendering; no new keeper operation | Learning the state without output | A new side-effect-free status-only keeper operation: duplicated wire surface for this path's benefit alone, rejected by the paging document |
| Cancel | `tasks/cancel` calls `remote_cancel`/`app_cancel`; the truthful reply decides nothing, the following read does | Cancellation | Taking the cancel reply's boolean as the task state: `true` means only that a cancellation was requested, so an already-finished job would be mislabelled |
| Timeouts | `timeout_seconds` is unchanged; a timed-out job is a `completed` task with its error line | Timeouts and lifetime | Mapping a timed-out job to `failed`: it loses the exit code the polling path shows (decision 6) |
| Elicitation | The confirm gate runs before task creation; a declined operation starts no job and creates no task | Interaction with the elicitation gate | An `input_required` task that asks through the task itself with `inputRequests`: the gate answers before the task exists, which is strictly simpler |
| Secrets | The record carries no output; D7 masking is unchanged; the one new exposure is byte counts and the error line | Secrets and exposure | Inlining a bounded first output page in the result (D1's rejected alternative): widens exposure and contradicts the transfer-design precedent |
| Result text | Two fixed field lines per state, derived from the EXEC-OUTPUT-PAGING example | Result text per state | Reusing the reads' `Next:` line verbatim: blurs result-versus-read provenance (decision 4) |
| Failure modes | Machinery failures stay the transfer design's split; an evicted job freezes `failed` | Error behaviour | Persisting or retaining output in the task record to survive job eviction (D6's rejected alternative) |
| Tests | Task store, bridge interception, keeper manager, launched stdio bridge | Test plan | Rendering the deciding read and filtering chunk text out of the rendered result: fragile, because it depends on the render format (rejected by the paging document) |
| Order and non-goals | Four mergeable slices; no polling-path change | Implementation order and non-goals | A status-only keeper operation again, here because it would add a keeper-side slice to the order; rejected for the same duplicated-wire-surface reason |

## Client facts

The transfer design's "Client facts" section applies unchanged: the extension,
the handle shape, the statuses, the `tasks/get` polling loop, the `failed`
error envelope, `-32602` for an unknown id, `tasks/cancel` on a person's stop,
and the surfaces that cannot receive tasks. Three points matter specifically
here:

- `[client docs]` On `completed` the normal `tools/call` result travels in the
  top-level `result` object; on `failed` the top-level `error` object carries
  the message Claude is told; on `cancelled` Claude is told the terminal
  `statusMessage`, or else the generic `Task was cancelled by the server`.
  What Claude Code does with a `completed` exec
  result versus a `failed` one beyond showing that text is not stated in the
  client documentation; anything below that depends on it is marked
  unverified.
- `[client docs]` `statusMessage` is shown in the harness `/tasks` list; a
  response that omits the field clears it.
- `[client docs]` Cancellation is cooperative: the server acknowledges the
  intent and may still finish the work.

## Tool scope and activation

- The task path covers exactly two tools: `remote_exec` and `app_exec`
  (`[ssjack code]` (`internal/bridge/internal/tooltext/registry.go`) registers both
  through `startTool`). They run long (up to `timeout_seconds`, default
  600 s), the model polls them most, and the keeper already bounds them (at
  most 4 active jobs, 64 retained records:
  `[ssjack code]` (`internal/remote/internal/jobs/jobs.go:16-21`)).
- Activation is the same four conditions as the transfer path: revision
  2026-07-28; the request's own
  `_meta["io.modelcontextprotocol/clientCapabilities"].extensions` carries
  `io.modelcontextprotocol/tasks`; the tool is one of the two exec tools; and
  the keeper returned a job id
  (`[ssjack code]` (`internal/bridge/internal/tasks/middleware.go`), `intercept` —
  extended to the exec tool names). The declaration is read from the request's
  own `_meta`; nothing an earlier discover or initialize stored makes a later
  request eligible. A refused start (unknown target, command too large,
  concurrency or retention limit, refused admission, `app_exec` confirm
  missing) answers today's error result with the tool error flag and never a
  task.
- Every client without the declaration keeps today's text and polling path
  byte for byte: `Started job <job_id>`, the read step, `wait_seconds`, the
  four waiting slots. The task path replaces the polling path for a supporting
  client; it does not add a parallel one.
- Never, in any step: `remote_read`, `app_read`, `remote_cancel`,
  `app_cancel`, `remote_targets`, `app_list`, the transfer tools (they have
  their own path in docs/MCP-TASKS.md) and the declarative
  `resource_plan`/`plan_apply`. The read and cancel tools are short calls
  whose task would be a second way to do what the tool does; the read tools in
  particular would make the task record carry output, which D1 forbids.

## Task identity and record

- One task per job, and the task id is the job id, with no prefix: 64
  lowercase hex characters are printable ASCII without spaces, inside the
  128-character limit, already unique within the session and already printed
  to the model today (`[ssjack code]` (`internal/remote/internal/jobs/jobs.go:150`),
  `wire.RandomToken`). No new identifier and no new information reach the
  model.
- A task exists only after the keeper returned a job id. A refused start has
  no job id and no task: it answers today's error result unchanged.
- A task belongs to the bridge session that created it. `tasks/get` and
  `tasks/cancel` for an id this session did not create, or never issued,
  answer JSON-RPC `-32602` with no keeper call, the same error for every
  unknown id, so a probe learns nothing about another session.
- Records are RAM-only and die with the child bridge process, reusing the
  transfer record set as it is implemented
  (`[ssjack code]` (`internal/bridge/internal/tasks/store.go`)): 64 records, one hour
  of retention counted from the moment the record freezes, eviction dropping
  the oldest frozen record first and, when none is frozen, the oldest record
  at all, and a dropped handle answering `-32602` from a live bridge. This is
  the deliberate divergence from the extension's durability rule the transfer
  design records; the transport is stdio and jobs are already cancelled when
  the session closes. `ttlMs` stays 7200000 and `pollIntervalMs` stays 10000
  (`[ssjack code]` (`internal/bridge/internal/tasks/wire.go:13-20`)).
- Strictly what the record must not hold: no command output bytes, no
  rendered or base64 output text (decision 1: no
  inlined page), no command text or argv, no target or
  application name, no path, no vault or bootstrap material, and no keeper
  error text. It holds only: the id, created/updated times, the task state,
  the frozen result text, the `cancelRequested` flag, the tool-kind
  discriminator (an enum of the two exec tools, `remote_exec` or
  `app_exec` — no command text), and — while the task is
  not frozen — the previous read's content-free control fields (done, exit
  code, error class, per-stream offsets, more and lost flags) so
  `lastUpdatedAt` moves when the job's record changes, not when its text does
  (`[ssjack code]` (`internal/bridge/internal/tasks/store.go:30-39`), the `last`
  field, retyped for the exec read output). The chunk bytes of the read that
  decides the task are discarded before anything is stored.
- Keeper eviction of the job while a task is open is the failure mode
  "Keeper job evicted" below: the task freezes `failed` with the fixed
  machinery message, because no later read can recover what the model was
  never shown (D6 documents the same eviction for paging reads).

## State mapping

The central decision. The keeper's read operation reports, for a finished
job: `done`, an exit code, an optional error string, per-stream offsets,
`more` and `lost` (`[ssjack code]` (`internal/remote/internal/jobs/jobs.go:214-241`)).
The mapping:

| Job outcome | Task state | What the model sees |
| --- | --- | --- |
| Running | `working` | the handle and each poll; no `statusMessage` (below) |
| Done, exit code 0 | `completed` | the `Status:` and `Resume:` result text (below) |
| Done, nonzero exit code | `completed` | the same text with `exit code <n>`, `n` nonzero |
| Done with a runner error (connection lost, guard failure, transport failure — `Error:` line, exit code -1) | `completed` | the `Status:` line plus an `Error:` line with the fixed one-line message, then `Resume:` |
| Timed out (`timeout_seconds` elapsed; the runner's context deadline exceeded) | `completed` | the same shape as a runner error, error line naming the timeout |
| Cancelled (cancellation requested while the job ran; the run ended from that cancellation) | `cancelled` | the fixed line `Cancelled job <job_id>` as the terminal `statusMessage`, no `result` |

- A nonzero exit code or a remote error is a COMMAND OUTCOME, not a transport
  failure, and therefore `completed` with the exit code in the result text.
  Justification: the extension reserves `failed` for a JSON-RPC error, and
  `[client docs]` a tool result that ended with the error flag set is
  `completed`; the transfer design already keeps every job outcome out of
  `failed`. Today's polling path shows `Job <job_id>: done (exit code <n>)`
  and an `Error:` line without the tool error flag
  (`[ssjack code]` (`internal/bridge/internal/tooltext/render.go:166-195`);
  docs/REMOTE-MCP.md), so a `completed` task reproduces exactly what the
  model would see after polling, while a `failed` task would replace the exit
  code with the machinery's nested `error` object and lose it.
  `[client docs]` state only that the `failed` message is what Claude is
  told; whether a `completed` exec result with a nonzero exit code changes
  Claude Code's behaviour beyond showing the text is unverified — the design
  does not depend on it, because the text itself is unambiguous.
- `cancelled` is reported when the recorded end of the job is the run's own
  context cancellation error; that is what the job ended with, not proof of who
  or what caused it (see the classification under "Cancellation"): the run ended with the run's own context cancellation error
  (`[ssjack code]` (`internal/remote/internal/jobs/jobs.go:185-200`) records the
  runner's `ctx.Err()`). A race in which the runner finished first keeps the
  run's own outcome (`completed`), which is exactly the truthfulness
  prerequisite landed in the manager
  (`[ssjack code]` (`internal/remote/internal/jobs/jobs.go:309-322`) and
  `internal/remote/internal/jobs/jobs_cancel_test.go`). Closing the keeper
  session cancels the running jobs keeper-side (the manager's context is
  bound to the session), but the bridge process survives: the broker client
  only reports a failed exchange (`ErrSessionClosed`), and the bridge's
  `server.Run` loop keeps it alive. The bridge can therefore no longer read
  the job at all — the next `tasks/get` of an unfrozen task, which needs a
  keeper read, is a lost attachment (exchange or connection failure), while a
  task that already froze keeps replaying its frozen answer with no keeper
  call — so the unfrozen task freezes `failed` with the
  fixed machinery message `-32603` `the task could not be read`, never a
  context-cancelled job outcome, because no read of that job can succeed
  afterwards. A bridge process that is itself gone has no task records to
  answer anything: the client sees a transport error, not `-32602` ("A
  stopped bridge"). A live bridge can observe a context-cancelled end of a
  job only after a cancel call — a direct `remote_cancel`/`app_cancel` by
  the model or `tasks/cancel`. The classification table in "Cancellation"
  covers this.
- `failed` is reserved for the task machinery: a job the keeper no longer
  knows, and a lost keeper attachment. It carries the nested `error` with code
  `-32603` and the fixed message `the task could not be read`, never job data
  (the transfer design's envelope, verified against the extension there).

## Learning the state without output

- There is no status operation for command and application jobs: the only
  keeper operation that reports exit code, completion state, per-stream totals
  and lost flags is the read
  (`[ssjack code]` (`internal/remote/internal/jobs/guard.go:132-152`);
  docs/EXEC-OUTPUT-PAGING.md, "Where the result fields come from"). Each
  `tasks/get` on an unfrozen record therefore performs one ordinary read at
  offset 0 for both streams with `wait_seconds` 0, on the ordinary call path
  and the shared keeper connection — the option (a) the paging document
  chooses — and derives its per-stream control fields from the read BEFORE
  the chunk bytes are discarded. The read reports the offset AFTER its
  chunk — `capture.read` returns `offset + int64(end-index)`, and its
  `more` is computed from that post-chunk position
  (`[ssjack code]` (`internal/remote/internal/jobs/guard.go:132-152`)) —
  so per stream the Resume offset is derived as `next - len(chunk)`,
  clamped at 0, where `next` is the read's reported offset and `chunk`
  its bytes; `more` is yes when that chunk is non-empty or the read
  itself reports `more=yes`, and no otherwise; `lost` is the read's
  flag. Three cases follow from this: an empty stream (chunk empty, no
  bytes seen) derives offset 0 and `more=no`; a lost stream (`lost=yes`,
  the chunk starts at the oldest retained byte) derives that oldest
  retained byte as the Resume offset, and the skipped range is
  permanently gone (D5); and a one-byte stream makes the read report
  offset 1 and `more=no`, from which the derivation correctly recovers
  offset 0 and `more=yes`. The chunk bytes are discarded before any
  rendering, so no chunk text or base64 line can reach the handle, the
  `statusMessage` or the result (decision 5 confirms D1 here). The memory cost is
  at most two raw 32 KiB chunks per poll — nothing is rendered, so the
  216 KiB worst case of D2 applies only to a rendered read; reads are
  non-destructive, so the model's own first read from the derived offsets
  returns the same bytes.
- No new keeper operation is added. A side-effect-free status-only operation
  was rejected by the paging document (duplicated wire surface for this path's
  benefit alone) and this design keeps that rejection. The existing keeper
  operations used are exactly `start`, `read` and `cancel` for the command
  manager and `app_start`, `app_read`, `app_cancel` for the application one
  (`[ssjack code]` (`internal/remote/internal/jobs/jobs.go:331-365`);
  `[ssjack code]` (`internal/application/application.go:253-307`)).
- While the job runs, the read reports `done=false`; the poll answers `working`
  with no `statusMessage`. Unlike the transfer task, there are no content-free
  progress fields to show — every field of an exec read except done and exit
  code describes output — so the exec task omits `statusMessage` while working
  rather than inventing a state word the polling path does not print. The
  client clears the field (`[client docs]`).
- `lastUpdatedAt` changes only when the read's control fields differ from the
  previous poll's, and stops changing when the record freezes
  (`[ssjack code]` (`internal/bridge/internal/tasks/store.go`), the freeze rule).
- The keeper's eviction of a finished job on a later start removes the first
  finished job in insertion order
  (`[ssjack code]` (`internal/remote/internal/jobs/jobs.go:135-149`)), so a finished
  job can disappear before any poll observes it; that is the failure mode
  below.

## Cancellation

- `tasks/cancel` reaches `remote_cancel`/`app_cancel` — the same cancel
  operation the cancel tools reach, with the same authorization — through the
  record's stored tool kind. The truthful cancel landed in the managers: a job
  that had already recorded a terminal state answers `Cancelled: false` and is
  not signalled; a job that had not ended answers `Cancelled: true` after the
  cancellation was requested, and the record keeps whatever outcome its own
  run then produces (`[ssjack code]` (`internal/remote/internal/jobs/jobs.go:309-322`);
  `internal/remote/internal/jobs/jobs_cancel_test.go`;
  `[ssjack code]` (`internal/application/application.go:303-306`), which delegates
  `app_cancel` to the same manager). The tool descriptions already document
  this wording (`[ssjack code]` (`internal/bridge/internal/tooltext/registry.go`),
  `remote_cancel`/`app_cancel` descriptions).
- The mapping reuses the transfer design's rules exactly. The empty
  acknowledgement says only that the request was passed on; the task state
  always comes from the following read:
  - `true` then a read showing the job running: the task stays `working`.
  - `true` then a read showing the run ended from the cancellation: the task
    freezes `cancelled` with the fixed line `Cancelled job <job_id>` as the
    terminal `statusMessage`, no result.
  - `true` then a read showing the runner finished first (`done` with its own
    exit code or error): the task freezes `completed` with that outcome's
    result text. This is the case the untruthful cancel would have mislabelled.
  - `false` (the job was already terminal, including already cancelled, and
    had not been polled yet): the acknowledgement is empty, no state is taken
    from the reply, and the next read freezes the task at the job's true
    state — `cancelled` for a job already cancelled, otherwise `completed`
    with its outcome.
  - `false` for a job whose task had already frozen: unreachable, because a
    frozen record answers the empty result with no keeper call (the freeze
    rule), as in the transfer design.
- What the bridge can observe about WHO cancelled the job. The recorded error
  text is only the runner's `ctx.Err()` string
  (`[ssjack code]` (`internal/remote/internal/jobs/guard.go:49-61`),
  `closeGuarded` preserves the runner's own exit value, gives guard-close
  errors precedence, and returns `ctx.Err()` only when the run also
  returned an error; `jobs.go:185-200` records `err.Error()`), the exit
  code, and the exec task
  record's own `cancelRequested` flag, which is set only by a `tasks/cancel`
  through this bridge. The recorded error text does NOT say who cancelled:
  the manager's context is bound to the session
  (`[ssjack code]` (`internal/remote/internal/jobs/jobs.go:331-333`),
  `Handle` runs `context.AfterFunc(ctx, m.cancel)`), so a keeper session
  close cancels every running job keeper-side, and a runner that returns
  its context error then records the same `context.Canceled` text that a
  cancel call produces (`closeGuarded` returns a context error only when the
  run also returned an error, and a context-shaped runner error with a live
  job context is normalized to the fixed job error) — but the bridge
  process survives the close (the broker client only reports a failed
  exchange, `ErrSessionClosed`, and `server.Run` keeps the process alive),
  and the next read of such a job by an unfrozen task is a lost attachment,
  freezing that task `failed` with the machinery message (a task that already
  froze keeps its frozen answer). Classification of the OBSERVED
  terminal values (the recorded error text and the exit code exactly as the
  runner recorded them, not fixed):

  | Observable end | Recorded error text | Exit code | `cancelRequested` | Task state and why |
  | --- | --- | --- | --- | --- |
  | `tasks/cancel` answered `true`, then a context-cancelled end | `context canceled` | any, as the runner returned it | yes | `cancelled`: the flag shows a cancellation was requested through this bridge and the text shows the run ended from one |
  | The model called `remote_cancel`/`app_cancel` directly (no `tasks/cancel`), then a context-cancelled end | `context canceled` | any, as the runner returned it | no | `cancelled`: same recorded text and exit code — indistinguishable from the row above by the error text alone; it maps to `cancelled` because a live bridge can effectively observe this end only after a cancel call (next bullet) |
  | Per-job timeout (`timeout_seconds` elapsed) | `context deadline exceeded` | any, as the runner returned it | either | `completed` with the timeout `Error:` line: the distinct deadline text is observable |
  | Keeper session close | (whatever was recorded before the close) | any, as the runner returned it | either | not observable as a job outcome: the close cancels the job keeper-side, but the bridge survives and can no longer read the job at all, so the next `tasks/get` of an unfrozen task is a lost attachment and the task freezes `failed` with `-32603` `the task could not be read`, never a context-cancelled outcome; an already frozen task keeps replaying its frozen answer |
  | The runner's own error (connection lost, guard failure, transport failure) | the runner's own text (`remote operation failed`, guard text) | any, as the runner returned it | either | `completed` with the `Error:` line: no context-cancellation text, so the cancellation rule does not fire |

  These recorded values do not prove who or what caused a cancellation;
  they show only what the job ended with.

  Rows 1 and 2 are indistinguishable in the recorded error text and exit
  code; the `cancelRequested` flag is the only difference, and it cannot be
  required for the `cancelled` mapping, because a direct cancel with the
  cancel tool is a real cancellation that the truthful mapping should
  report. The simplifying observation: closing a keeper session cancels the
  running jobs keeper-side (`jobs.go:331-333`, the `AfterFunc` binding),
  but the bridge survives the close and can no longer read any of those
  jobs (every read is a lost attachment), so a live bridge can
  effectively observe a context-cancelled end of an unfrozen task only after
  a cancel call was made through it (`tasks/cancel`) or directly with the
  cancel tool. The mapping therefore stays: a context-cancelled end maps to
  `cancelled`; a deadline-exceeded end maps to the timeout outcome; the
  runner's own error maps to the error outcome. Decision 7 records this
  classification.
- A cancelled task has no result text and hence no `Resume:` line, but its
  retained output stays pageable
  (decision 3: cancelled buffers keep their retained
  output). Because the task id equals the job id, the model can find that
  output without any Resume line by reading from offset 0 with
  `remote_read`/`app_read` — always valid for retained output — and take
  `more` and `lost` from those reads, paging exactly as for a finished job.
- Cancellation is therefore eventual and unconfirmed in the same sense as the
  transfer path: the bridge cannot promise the command stopped, only that the
  request reached the manager and what the record later says. For a remote
  command, closing the connection does not prove detached remote processes
  stopped (docs/REMOTE-MCP.md, `remote_cancel`); for an application job,
  cancelling revokes the child transport, and a detached remote process may
  continue (`[ssjack code]` (`internal/application/application.go`), the runner's
  scope lifecycle; docs/APP-CONTRACT.md, "Child transport environment").
- A frozen record is never changed by `tasks/cancel`: no keeper call, empty
  result, record unchanged. For an unfrozen record whose job the keeper no
  longer knows, the record is dropped and the answer is `-32602`, as in the
  transfer table.
- `confirm` is not part of this path. `remote_exec` has no `confirm` field at
  all; `app_exec` keeps `confirm=true` as a start-call argument
  (`[ssjack code]` (`internal/remote/internal/jobs/jobs.go:25-29`);
  `[ssjack code]` (`internal/application/application.go:44-49`)).

## Timeouts and lifetime

- `timeout_seconds` (1..3600, default 600) is a start-call argument and is
  unchanged by this design
  (`[ssjack code]` (`internal/remote/internal/jobs/jobs.go:118-123`); app_exec the
  same via `application.Input`). The job's own context deadline fires, the
  runner records the deadline error, and the next poll freezes the task
  `completed` with the error line — a timed-out job is a command outcome
  ("State mapping"), not a task failure.
- Closing the keeper session cancels the running jobs exactly as today: the
  manager's context is bound to the session and `Close` cancels the running
  jobs (`[ssjack code]` (`internal/remote/internal/jobs/jobs.go:109-115,
  331-333`); docs/FILE-TRANSFER.md, "Cancellation and lifetime"). The bridge
  process survives the close — the broker client only reports a failed
  exchange (`ErrSessionClosed`), and `server.Run` keeps it alive — so the
  task records do not vanish, but no read of a keeper-cancelled job can
  succeed afterwards: an unfrozen task freezes `failed` with the fixed
  machinery message at its next poll ("Error behaviour", lost attachment); a
  task that already froze keeps its frozen answer and costs no keeper call.
  No task outlives its keeper session in any readable sense.
- Keeper eviction of the job while the task is open: before the task freezes,
  a read that answers `unknown operation` freezes the task `failed` with the
  fixed machinery message ("Error behaviour"); after the task freezes, the
  record no longer reaches the keeper and nothing changes it. The finished
  job's output buffer dies with the eviction (D6), so a task that froze
  `failed` this way leaves the model with whatever pages it already fetched
  and the duty to report partial output.
- A client that stops polling can lose its handle to the 64-record bound or
  the one-hour frozen retention, exactly as in the transfer design; a dropped
  handle answers `-32602`.

## Interaction with the elicitation gate

The confirmation gate (docs/MCP-ELICITATION.md) is owner-enabled with
`--confirm-elicitation`, default OFF, and gates on the per-request form
capability. Only `app_exec` of the two tools here is ever eligible:
`remote_exec` has no `confirm` field and is excluded there as well.

- The dialog happens BEFORE task creation, and before any state-changing
  keeper call. A non-observational `app_exec` under an enabled gate answers
  `input_required`; no job starts, no job id exists, and no task record is
  created while the human decides. The sole pre-acceptance keeper request is
  the side-effect-free `app_classify` classification
  (docs/MCP-ELICITATION.md, section 6). The ordering is already fixed in the
  tree: the confirm middleware is installed after the tasks middleware, so it
  wraps outside the `tools/call` interception
  (`[ssjack code]` (`internal/bridge/internal/tooltext/registry.go:220-224`)).
- A decline or cancel action, a timeout, or an invalid retry returns the
  gate's fixed tool error (`operation was not started: declined` /
  `cancelled` / `timed out` / the generic validation error) with the error
  flag and no job, no task and no state change. No task handle exists to
  cancel or poll: a declined operation never reached the keeper's job
  manager.
- An accepted retry dispatches the unchanged `app_exec` handler; the job
  starts, and if the same request declares the tasks extension the
  interception returns the task handle for the new job id. A client can
  declare both the elicitation form capability and the tasks extension; the
  two gates compose independently.
- What is deferred: an `input_required` task — asking the question through
  the task itself with `inputRequests` — is not designed here. The gate
  answers before the task exists, which is strictly simpler and matches the
  gate's own compatibility trade-off: `[client docs]` a non-interactive
  session cancels a task that asks for input, and the gate's decline path
  already guarantees no start. Elicitation during a running task stays out of
  scope, as it already is in the transfer design (task #475).
- With the gate OFF (the default), or the form capability absent, `app_exec`
  dispatches exactly today's flow and the task path applies on the extension
  declaration alone.

## Secrets and exposure

- The task record carries no output (D1) and the deciding read's chunk bytes
  are discarded before rendering, so nothing the outputguard masked for
  capture and nothing the app bootstrap-token writer masked
  (`[ssjack code]` (`internal/remote/internal/jobs/guard.go:63-90`),
  `NewGuardedManager`; `[ssjack code]` (`internal/application/application.go:217-230,
  352-423`)) reaches the handle, the `statusMessage` or the result (D7).
  Binary or base64 representation adds no new surface because no bytes travel
  in the task at all.
- The record also carries no command text, argv, target or application name,
  path or keeper error text ("Task identity and record").
- What is genuinely new on the wire, stated plainly: the `Resume:` line
  reveals per-stream byte totals and lost flags of remote output — volume
  metadata the polling path already prints in its `Next:` line — and the
  `Error:` line of a failed run reveals the job's one-line fixed error
  message, which the polling path already prints too. Exit codes likewise.
  No exposure exists here that `remote_read` does not already have.
- The extension declaration is neither logged nor stored, as in the transfer
  design. The asymmetry the transfer design notes applies: a `statusMessage`
  travels to the harness `/tasks` list. This design sends none while the task
  is `working` and none for the terminal `completed` and `failed` states; the
  one exception is a frozen `cancelled` task, whose terminal `statusMessage`
  is the fixed line `Cancelled job <job_id>` with no result ("Result text per
  state"), the same line the transfer task freezes. The exec task adds no
  other text to that surface.

## Result text per state

One text content block, no structured content, no output schema; bounded to
the fixed field set below, well under 1 KiB, independent of output volume.
Derived from the task-result example of docs/EXEC-OUTPUT-PAGING.md; no path,
no remote content, no chunk bytes.

`completed`, exit code 0:

```text
Status: finished · exit code 0
Resume: stdout_offset=0 stderr_offset=0 · more: stdout=yes stderr=no · lost: stdout=no stderr=no · job <job_id>
```

`completed`, nonzero exit code: `Status: finished · exit code <n>`.
`completed` with a runner error or a timeout adds one line between them:

```text
Error: remote operation failed
```

(the job's fixed one-line error, single-lined exactly as the polling path
single-lines it; a timeout records the deadline error). A frozen `cancelled`
task carries no `result`; its terminal `statusMessage` is the fixed line
`Cancelled job <job_id>`, the same fixed line the cancel tools print
(`[ssjack code]` (`internal/bridge/internal/tooltext/render.go:158-163`)),
exactly as the transfer design freezes it: `freeze` clears any earlier
progress message and the cancelled branch then sets the fixed line, which
`wire()` carries in every `tasks/get` answer of the frozen record
(`[ssjack code]` (`internal/bridge/internal/tasks/service.go:84-86`),
`store.go:69-72` and `store.go:42-65`; the client shows `statusMessage` for
a `cancelled` task and falls back to generic text only when it is absent).
`failed` (machinery only) carries the nested `error` `-32603`,
`the task could not be read`, no result text.

The `Resume:` line means: fetch remaining pages with `remote_read`/`app_read`
passing exactly the derived offsets; drain both streams until `done` with
`more=no` on both; treat any `lost=yes` range as permanently gone (D3, D5).
The offsets are the ones derived from the deciding read per "Learning the
state without output" — per stream `next - len(chunk)` clamped at 0, which
for a retained stream is its oldest retained byte, 0 when nothing was lost —
and are exactly the offsets the model must pass (D1, D4; decision 4, the distinct `Resume:` format). The model's own reads render full chunks under the documented bound
of D2; the task result itself never carries one (decision 1).

## Error behaviour

One table covers the three methods for the exec task path; the envelope rules,
the `-32021` capability error and the frozen-state rules are the transfer
design's, applied unchanged. "Handle unknown" means this bridge has no record
for the id; "keeper job evicted" means the record exists but the keeper
answers `unknown operation`; a "read error" is a well-formed error reply from
the keeper; a lost attachment is an exchange or connection failure.

| Method | Handle unknown | Keeper job evicted | Read error | Lost attachment |
| --- | --- | --- | --- | --- |
| `tasks/get` | `-32602`, no keeper call | successful result: task freezes `failed` with nested `error` `-32603`, `the task could not be read` | JSON-RPC error response `-32603` with the same fixed message; no state transition, the task stays `working`, the next poll retries | successful result: task freezes `failed` with nested `error` `-32603`, `the task could not be read` |
| `tasks/cancel` | `-32602`, no keeper call | unfrozen record: `-32602`, the record is dropped; frozen record: empty result, no keeper call, record unchanged | `-32603`, `the cancellation could not be requested`; record unchanged | same as a read error; record unchanged |
| `tasks/update` | `-32602` | empty result, nothing changed | never calls the keeper | never calls the keeper |

Shared-store routing: the exec records live in the same RAM record set as the
transfer records, one map keyed by job id
(`[ssjack code]` (`internal/bridge/internal/tasks/store.go:77-90`),
`create` keyed on the job id, and `lookupLocked` is the only lookup both
seams share). An id therefore answers from whichever record exists: a
transfer record is answered by the transfer handlers and the transfer
`Tools` seam, an exec record by the exec seam, and a raw job id with no task
record in this bridge — never issued, already dropped, or another session's
— is answered `-32602` (`CodeInvalidParams`, the fixed message
`unknown task`) by both handlers with no keeper call
(`[ssjack code]` (`internal/bridge/internal/tasks/service.go:56-66,
96-118`), `unknownTask` in both `get` and `cancel`). The exec record stores
its tool kind (the record extension this design adds; "Cancellation" uses it
to pick the cancel operation), so the two seams cannot be confused for a
known id.

Capability-gate errors, the split the middleware actually makes
(`[ssjack code]` (`internal/bridge/internal/tasks/middleware.go:139-152`),
the `gate` middleware): a `tasks/*` request whose own `_meta` carries a
protocol revision below 2026-07-28, or no revision at all, answers
`-32601` (`CodeMethodNotFound`) with the message `method not found` —
legacy clients see the method as absent; a current-revision (>= 2026-07-28)
request that lacks the extension declaration in its own
`io.modelcontextprotocol/clientCapabilities` answers `-32021`
(`CodeMissingRequiredClientCapabilities`) with the message `missing
required client capability` and the data
`{"requiredCapabilities":{"extensions":{"io.modelcontextprotocol/tasks":{}}}}`.
The same two-part split applies to `tools/call` on the two exec tools, but
there a non-declaring request is not an error at all: it takes today's
polling path ("Tool scope and activation").

Tool-path errors that are not new: an eligible `remote_exec`/`app_exec` start
that the keeper refuses answers today's error result with the tool error flag
and never a task; a read of a task's own `Resume:` offsets that the model
passes wrongly answers the existing `invalid output offset` tool error
(`[ssjack code]` (`internal/remote/internal/jobs/guard.go:132-137`)), which the task
record never produces because it always reads at offset 0. A bridge process
that is itself gone (the client disconnected) gives a transport error, not
`-32602`, because no process is left to answer (the transfer design's "A
stopped bridge"). A closed keeper session leaves the bridge process alive,
so it still answers — but the next read of a job the session carried, made
by an unfrozen task, is a lost attachment, and that task freezes `failed`
with the machinery message per the table above; a task that already froze
replays its frozen answer.

## Failure modes

- A finished job evicted before any poll observes it: the task freezes
  `failed` with the machinery message; the exit code and offsets are lost
  with the job record (D6). The model reports partial output from the pages
  it fetched, never completeness.
- A well-formed keeper error reply: `-32603`, task stays `working`, next poll
  retries; an IPC failure is not evidence the job stopped or failed.
- Duplicate start: a re-issued `remote_exec`/`app_exec` is a new job, a new
  job id and a new task; the keeper's own bounds (4 active, 64 retained,
  per-manager) refuse the start when they are exhausted, and the refusal is
  today's error result.
- Repeated `tasks/get`: each unfrozen poll is one keeper round trip at offset
  0 whose bytes are discarded; two polls can differ; a frozen poll costs no
  keeper call.
- Client restart or a resumed conversation: records are RAM-only; a live
  replacement bridge answers `-32602` and `[client docs]` Claude Code keeps
  asking up to five minutes before reporting the outcome as unknown.
- The job finishes while nobody polls and the model never reads the output:
  the task completes and carries only status, exit code and offsets; the
  output is fetched or not, as the model decides. This is decision 5's
  trade-off, accepted here.

## Test plan

Each case names its owning layer. Existing layers are reused: the task record
set and the three method handlers live in `internal/bridge/internal/tasks`
(unit tests beside them, fake `Tools` seam); the bridge interception lives in
`internal/bridge/internal/tooltext/registry.go` with the in-process task
tests of package `internal/bridge`; the keeper operations live in
`internal/remote/internal/jobs` (already covered by
`jobs_cancel_test.go`); the real stdio path is
`cmd/ssjack/internal/mcptasktest`, which launches the production bridge as a
child (`[ssjack code]` (`cmd/ssjack/internal/mcptasktest/doc.go`),
`bridge_tasks_test.go`, `raw_test.go`).

- Task store (`internal/bridge/internal/tasks`, fake exec `Tools`):
  - `TestExecTaskMapsNonZeroExitToCompleted` — a read reporting `done`,
    exit 3, freezes `completed`; the result text carries `exit code 3` and
    the `Resume:` line, and the record's state is not `failed`.
  - `TestExecTaskMapsRunnerErrorAndTimeoutToCompleted` — `done` with an
    error string freezes `completed` with the `Error:` line; the deadline
    error string produces the same shape.
  - `TestExecTaskCancelTrueFollowedByDone` — cancel reply `true`, then a
    read with the run's own exit code: the task freezes `completed`, not
    `cancelled`.
  - `TestExecTaskCancelTrueFollowedByCancelled` — `true`, then a read whose
    error is the context-cancellation error: freezes `cancelled` with the
    fixed line as the terminal `statusMessage` and no `result`.
  - `TestExecTaskCancelFalseThenTerminal` — `false`, then `done`: freezes
    `completed` with the recorded outcome; and `false` then an
    already-cancelled read freezes `cancelled`.
  - `TestExecTaskResultContainsNoChunkBytes` — the deciding read's chunks
    carry a unique marker (and a marker crafted to render as base64): the
    frozen result text contains neither, while a following read from the
    derived offsets returns the marker bytes (the paging document's test,
    owned here).
  - `TestExecTaskResumeOffsetsRoundTrip` (replaces the earlier
    `TestExecTaskResumeLineMatchesReadNext`, which wrongly asserted that a
    Resume offset equals the next read's `Next` offset — a read at offset 0
    reports the offset after its chunk) — a property test: for each stream,
    reading with the ordinary `remote_read`/`app_read` from exactly the
    reported `Resume:` offsets and concatenating the pages reproduces the
    entire retained byte stream. Cases: a one-byte stream (the read reports
    offset 1 and `more=no`; the derived Resume must be offset 0 with
    `more=yes`); the empty stream (Resume 0, `more=no`); an exactly 32 KiB
    stream; and a stream larger than the 256 KiB retention (the read reports
    `lost=yes` and the Resume offset is the oldest retained byte; the
    concatenated pages reproduce only the retained suffix and the skipped
    range is reported gone). The `Resume:` line's flags are PRE-READ
    metadata: `more=yes` iff the stream had a non-empty retained chunk in
    the deciding read, and `lost` as the deciding read reported it; the
    test asserts them once against the fixed expectation per case
    (one-byte: `more=yes`; empty: `more=no`; over-256-KiB: `lost=yes`).
    The model's later paging reads report POST-READ flags (`more=no` once
    drained; a read starting at the oldest retained offset can report
    `lost=no`), so for those reads the test asserts only drain-to-`more=no`
    and byte equality.
  - `TestExecTaskRecordCarriesNoSecrets` — canaries planted in the start
    arguments (command text, target/app name, a path, a secret-looking
    marker), in the keeper's reply, and in the read chunks of the deciding
    read are absent from the WHOLE in-memory store, not only from serialized
    responses: the test walks the record with reflection against an
    explicit allow-list (below) and asserts no canary appears in any field; a
    compile-time or reflection guard fails when a field is added to the exec
    record without updating the allow-list. The serialized handle,
    `tasks/get` answers and `tasks/cancel` acknowledgement are still
    asserted as well. The check must not rely on `%+v`, which does not
    reliably show values behind nested pointers: it walks the record with
    reflection through pointers, slices, maps and interfaces (or marshals
    the whole record with an encoder that dereferences everything) and
    compares every string and byte leaf against the canaries, in addition
    to the field-name allow-list. The allow-list is: id, times, status,
    message, the retyped control-field `last`, result, frozen marker,
    `cancelRequested`, and the tool-kind discriminator (an enum of
    `remote_exec`/`app_exec`, no command text).
  - The transfer-table mechanics on exec records: unknown/foreign/expired
    handle `-32602` with no keeper operation; eviction freeze `failed` (a
    second poll returns the same frozen record, no further keeper call);
    well-formed error reply `-32603` with no transition; lost attachment
    freeze `failed`; `tasks/cancel` on frozen record empty result, on
    evicted unfrozen record `-32602` and dropped; `tasks/update` empty
    result; `lastUpdatedAt` frozen after the freeze.
- Bridge routing (package `internal/bridge`, in-process SDK server):
  - `TestExecInterceptionNeedsDeclaration` — a declaring
    `remote_exec`/`app_exec` call answers a handle with `taskId` equal to the
    job id, `status` `working`, `pollIntervalMs` 10000, `ttlMs` 7200000; the
    same call without the extension declaration answers
    `Started job <job_id>` byte for byte; a refused start answers today's
    error result, never a handle.
  - `TestExecCapturedStartOnlyFromEligibleCall` — the job-id capture fires
    only when the interception wrapped the call, so a fallback call never
    creates a record.
  - `TestConfirmGatePrecedesExecTaskCreation` — with the gate enabled and
    the form capability declared, a non-observational `app_exec` answers
    `input_required`, creates no task record and makes no state-changing
    keeper call; after an accepted retry, the answer is the task handle; a
    declined retry returns the fixed error and no record; `remote_exec`
    never elicits.
- Keeper manager (`internal/remote/internal/jobs`) — already landed and
  covered: `TestCancelAnswersTruthfully` and its siblings own the truthful
  cancel for command and, by delegation, application jobs
  (`internal/remote/internal/jobs/jobs_cancel_test.go`); offset/lost
  semantics are owned there per docs/EXEC-OUTPUT-PAGING.md. This design adds
  no keeper change, so no new keeper-layer case.
- Launched stdio bridge (`cmd/ssjack/internal/mcptasktest`):
  - Fixture change needed first: the existing `launchKeeper` answers
    `start`/`app_start` with a minted id without running anything
    (`[ssjack code]` (`cmd/ssjack/internal/mcptasktest/bridge_tasks_test.go:528-529`)),
    so it cannot serve a launched-stdio exec case, which needs a real
    command. The exec tests get a keeper fixture backed by a real
    `remote.Manager`/jobs manager with a local, test-controlled runner (the
    fixture owns the runner function, so cases can script exit codes,
    errors, a timeout and a cancellation without any network). It goes into
    a new file `cmd/ssjack/internal/mcptasktest/exec_keeper_test.go`:
    `bridge_tasks_test.go` is the transfer fixture and its cases and is
    already large, so a separate file keeps both under the 1000-line rule
    and keeps the folder at 4 code-and-test files (doc.go,
    bridge_tasks_test.go, raw_test.go, exec_keeper_test.go) of the allowed
    7.
  - `TestMCPTaskExecPathOverTheLaunchedBridge` — with that fixture: run a
    real `remote_exec` job, assert the
    handle fields, freeze `completed`, and assert the result text equals the
    fixed two-line contract; run the nonzero-exit case over a real shell
    command.
  - `TestMCPExecFallbackPinOverTheLaunchedBridge` — a default-capability
    client gets today's exact `Started job` text for both exec tools, and
    `tasks/*` stay method-not-found on a legacy connection (the existing raw
    probe pattern).
  - Canary absence asserted over the raw frames of the whole exchange, as
    the existing `TestMCPTaskLaunchedBridgeAnswersCarryNoCanaries` does for
    transfers.
- Stability: injected clocks for retention and freeze times, `flakediag`
  waits with deadlines, no bare sleeps — the existing task-test rules
  (docs/MCP-TASKS.md, "Acceptance tests").

## Implementation order and non-goals

Layout rules: at most 1000 lines per code file and at most 7 code files per
folder counting tests. `internal/bridge/internal/tasks` currently holds 5
files (middleware.go, service.go, store.go, wire.go, tasks_test.go); this
design adds 2 (exec.go plus its test file, 5 + 2 = 7, at the limit — if the
exec file would exceed 1000 lines, put the exec `Tools` seam into the
existing `service.go` rather than adding a file).
`cmd/ssjack/internal/mcptasktest` currently holds 3 files (doc.go,
bridge_tasks_test.go, raw_test.go); this design adds
`exec_keeper_test.go` (4 of 7). The bridge registry file is below the line
limit.

1. This document and the cross-links in docs/REMOTE-MCP.md and
   docs/APP-CONTRACT.md, whose exec task links now point to this design. No
   behaviour change.
2. Exec task records and handlers: the exec `Tools` seam (`Read`, `Cancel`,
   the fixed `Resume:`/`Status:`/`Error:` renderers), the state mapping, the
   discard-before-render rule, `internal/bridge/internal/tasks/exec.go` with
   unit tests beside it. Not reachable by any client yet.
3. Interception: extend the `tools/call` interception to `remote_exec` and
   `app_exec`, add the job-id capture to `startTool`
   (`internal/bridge/internal/tooltext/registry.go`, mirroring
   `tasks.CapturedStart` in `transferStart`), one sentence in each exec tool
   description. The advertisement already exists and needs no change, so this
   step lands interception and visibility together and a supporting client
   never sees an advertised exec tool without a task path. **Landed.**
4. Acceptance tests: the in-process cases of package `internal/bridge` and
   the launched-bridge cases of `cmd/ssjack/internal/mcptasktest`, with the
   CI wiring following the diff-selection rule (docs/CI.md).

Non-goals: output pages, chunk bytes, base64 or rendered output anywhere in
the task record or result; a status-only keeper operation; `input_required`
for the confirm gate (the gate answers before the task exists); elicitation
or MRTR during a running task (task #475); a task path for the read, cancel,
list and transfer tools; changes to `timeout_seconds`, `wait_seconds`, the
32 KiB chunk limit or the 256 KiB retention; changes to the polling path for
clients without the extension; durable or on-disk tasks; any new secret,
path, command text or remote content in a task record; a new startup flag.

## Decisions

The following decisions were made on 2026-11-26, delegated by the owner to the implementer; all recommended options were taken. Each maps to the corresponding decision in docs/EXEC-OUTPUT-PAGING.md where applicable.

1. **No output in task results (paging decision 1).** The result carries no output; the model reads it with `remote_read`/`app_read`. This preserves the task-record non-goal and keeps output retrieval in existing read tools. **Rejected:** a bounded inline first page, which widens exposure and complicates size bounds.
2. **Accept the rendered-response bound (paging decision 2).** Document about 108 KiB rendered per stream and 216 KiB for both streams for non-UTF-8; keep pages at 32 KiB. This accounts for replacement expansion and base64 while preserving the current chunk contract. **Rejected:** shrinking responses for non-UTF-8, which would change the documented read format and client expectations.
3. **Cancelled output remains pageable from offset 0 (paging decision 3).** Keep retained output readable after cancellation until eviction, matching current manager behavior. **Rejected:** truncating on cancel, which discards currently retained output.
4. **Use a distinct `Resume:` line (paging decision 4).** Keep result offsets distinct from reads' `Next:` line to make result-versus-read provenance unambiguous. **Rejected:** reusing `Next:` verbatim.
5. **Keep D1 despite the read cost (paging decision 5).** A finished job costs at least one read call even when the model does not need output; the task benefit is no polling plus completion notification. **Rejected:** inline a bounded first page, which contradicts the task-record non-goal and complicates the size bound.
6. **Timeout maps to `completed` with an error line.** This preserves the command outcome and the error/exit information shown by the polling path. **Rejected:** `failed`, which replaces the outcome with a machinery error and loses the exit code.
7. **Recognize cancellation by matching the fixed recorded error text `context canceled`.** This uses the recorded runner error without adding wire surface; pin the exact matched fixed text in a test so jobs-side wording changes fail CI rather than silently breaking the mapping. An explicit terminal-cause field remains a later option if error texts become configurable. **Rejected:** adding that field now, which requires a keeper-side wire change.
8. **Omit `statusMessage` while working.** Exec reads have no content-free progress fields, so omitting it avoids inventing a state word the polling path does not print. **Rejected:** a fixed status word such as `running`.




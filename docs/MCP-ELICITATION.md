# MCP Elicitation for confirmation

**Status:** The confirmation gate is implemented and wired behind the owner startup flag `--confirm-elicitation` (default OFF). OFF preserves byte-for-byte unchanged behavior; the feature is available in full mode only and is set only at keeper startup, never through tool arguments, environment in agent reach, or agent-writable files. This slice is not a vault setting. Whether the real Claude Code client sends the `_meta` form capability remains **UNVERIFIED**.

## 1. Purpose and scope

MCP elicitation can present a form to a user through a capable client while a tool call is in progress. The bridge may use it as an additional opportunity for a person at the client to review a bounded summary before a mutating operation starts. It is not a new authorization mechanism and it must not be described as owner approval.

The exact confirm-required operations currently exposed by the tool registry are: `remote_upload` and `remote_download` when `overwrite=true`, both using the shared `transfer.StartInput` schema with fields `target`, optional `root`, `local`, `remote`, optional `overwrite`, and optional `confirm`; and `app_exec` when its registered application command is non-observational, using `application.Input` with fields `application`, `arguments`, optional `confirm`, and optional `timeout_seconds`. Source evidence is the `StartInput.Confirm` field and `application.Input.Confirm` field, plus the tool registrations in `internal/bridge/internal/tooltext/registry.go`; upload/download do not define separate confirm fields. `remote_exec` uses `remote.StartInput`, has no `confirm` field, and is excluded. Ordinary transfers without overwrite, observational app commands, status/read/cancel calls, and all other tools retain current behavior. A `confirm=true` on an otherwise non-confirming operation does not itself require an elicitation.

The existing `confirm` flags remain caller acknowledgments, as stated in `FILE-TRANSFER.md` and `APP-CONTRACT.md`. Elicitation is an optional additional prompt and is **OFF by default**. It is enabled only by an explicit owner-controlled startup/keeper setting or vault configuration that an agent cannot write; it is never enabled or disabled through tool arguments or agent-writable workspace/settings files. When OFF, dispatch and response behavior remain byte-for-byte the current behavior. When ON, a client that declares form elicitation but cannot display it may cancel; that means no operation starts and, without a retry, no final server tool result exists. This is the owner's explicit compatibility trade-off. Future mandatory-per-operation policy is out of scope.

## 2. Threat model and assurance

### What each signal means

- **`confirm=true`:** the tool caller supplied an affirmative boolean. It does not establish who supplied it, that a human saw the arguments, or that the person understood or approved their effects.
- **Elicitation response:** the MCP client returned a response for the bridge's keyed `elicitation/create` request. This records only what the client asserted. It is not cryptographic proof of a human, a trustworthy display, user identity, or owner authorization. An agent with write access to the MCP settings file could install an Elicitation hook and auto-answer; this is stronger than caller-supplied `confirm=true` but weaker than owner TUI/keeper approval.
- **Owner TUI/keeper approval:** a separately designed approval path could authenticate a decision through the owner's controlled TUI/keeper boundary. This proposal does not implement or claim that property. An MCP dialog, even one shown interactively, is not equivalent to owner-authorized TUI/keeper approval.

Threats include a model supplying `confirm=true`, malicious or compromised MCP clients, a client that presents misleading UI or answers without a person, a changed/replayed response, and sensitive values in arguments. Elicitation only mitigates accidental initiation when a client actually displays a useful prompt and a person responds deliberately. The keeper's existing guards, registrations, harness authorization, path validation and operation checks remain authoritative.

**Client caveat (prompt-given, not independently verified here):** Claude Code 2.1.327 is reported to declare elicitation form/url on 2026-07-28 connections and show a dialog in an interactive terminal that the model cannot answer; `claude -p` cancels, and an Elicitation hook can auto-answer. In particular, a hook may answer affirmatively without human review. Therefore even a positive response cannot be labeled human approval. Client behavior and hook configuration are not verified from this repository.

## 3. Wire exchange and state binding

The pinned dependency in `go.mod` is `github.com/modelcontextprotocol/go-sdk v1.8.0`. Its `mcp/protocol.go` defines `CallToolParams.InputResponses` and `RequestState`, and `CallToolResult.InputRequests`, `RequestState`, and the internal result type; `InputRequestMap` uses `elicitation/create`. In `mcp/shared.go`, `ServerRequest.ClientCapabilities()` exposes capabilities for the current request. The SDK server middleware source in `mcp/server.go` installs `serverMultiRoundTripMiddleware()` unconditionally; `mcp/mrtr.go` takes the legacy path based on protocol version, not elicitation capability. Therefore implementation must ensure that the feature-off / absent-capability path cannot return `inputRequests` to that middleware and trigger an undeclared elicitation.

Eligibility is a positive capability gate, not a protocol-version inference: ask only when the feature is owner-enabled, the 2026-07-28 modern `server/discover` flow is in use, and the current `tools/call`'s `_meta` positively declares form elicitation (`io.modelcontextprotocol/clientCapabilities.elicitation.form != nil`). The exact modern metadata shape is `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"elicitation":{"form":{}}}}`; URL-only declaration is insufficient for this form. Do not require `initialize` to enable this modern path. `initialize` capability metadata is only a legacy fallback source for non-modern request handling; never elicit on that legacy path. In particular, preserve old-client behavior unchanged and prevent the SDK legacy server-side automatic `Elicit` path from prompting, since it can otherwise create ambiguity about capability and dispatch. If the modern request's `_meta` lacks form capability, preserve the exact current path and response shape. The first `input_required`/retry wire exchange below applies only to modern 2026-07-28 MRTR with the positive per-`tools/call` `_meta` form-capability gate. Verify these APIs against the pinned module when implementation begins; this proposal does not alter the dependency.

For an opted-in request on the modern 2026-07-28 `server/discover` flow, use one elicitation round and one request key only when that individual `tools/call`'s `_meta` declares form capability. The modern client-call metadata shape is `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"elicitation":{"form":{}}}}`; an `initialize` declaration is not required and URL-only capability does not qualify. The first tool call is a normal `tools/call`, including unchanged tool name and full original argument object. Example request:

```json
{
  "jsonrpc": "2.0",
  "id": 17,
  "method": "tools/call",
  "params": {
    "_meta": {
      "io.modelcontextprotocol/protocolVersion": "2026-07-28",
      "io.modelcontextprotocol/clientInfo": { "name": "ExampleClient", "version": "1.0.0" },
      "io.modelcontextprotocol/clientCapabilities": { "elicitation": { "form": {} } }
    },
    "name": "remote_upload",
    "arguments": { "target": "build-host", "root": "release", "local": "bundle.tar", "remote": "/srv/bundle.tar", "overwrite": true, "confirm": true }
  }
}
```

Under the pinned SDK's typed `CallToolResult` fields, an `input_required` result has `content:null` (the SDK marshals its nil `Content` slice) alongside `resultType`, `inputRequests`, and `requestState`. Illustrative JSON-RPC response (opaque state and numeric id vary):

```json
{
  "jsonrpc": "2.0",
  "id": 17,
  "result": {
    "content": null,
    "inputRequests": {
      "ssjack-confirm-v1": {
        "method": "elicitation/create",
        "params": {
          "mode": "form",
          "message": "Review this operation before it starts.",
          "requestedSchema": { "type": "object", "properties": {}, "additionalProperties": false }
        }
      }
    },
    "requestState": "<opaque continuation state>",
    "resultType": "input_required"
  }
}
```

The protocol `ElicitResult.Action` is the sole decision: `accept`, `decline`, or `cancel`. There is no user-provided decision field in the form; an `accept` action requires no extra decision content. The pinned go-sdk v1.8.0 `ElicitResult.Content` is `omitempty`; therefore `{"action":"accept"}` is valid and content is absent. The client retries the same tool name and arguments but uses a **new JSON-RPC request id**, with `inputResponses` keyed by the exact request key and the exact returned `requestState`:

```json
{
  "jsonrpc": "2.0",
  "id": 18,
  "method": "tools/call",
  "params": {
    "_meta": {
      "io.modelcontextprotocol/protocolVersion": "2026-07-28",
      "io.modelcontextprotocol/clientInfo": { "name": "ExampleClient", "version": "1.0.0" },
      "io.modelcontextprotocol/clientCapabilities": { "elicitation": { "form": {} } }
    },
    "name": "remote_upload",
    "arguments": { "target": "build-host", "root": "release", "local": "bundle.tar", "remote": "/srv/bundle.tar", "overwrite": true, "confirm": true },
    "inputResponses": { "ssjack-confirm-v1": { "action": "accept" } },
    "requestState": "<same opaque continuation state>"
  }
}
```

These are illustrative protocol-level fixtures; request ids and opaque state necessarily vary. The SDK v1.8.0 MRTR client middleware copies the original params, populates responses/state, and constructs a new client request; server legacy middleware instead reconstructs a server request and re-invokes the handler. Do not assume a retry reuses the original JSON-RPC id. The result for explicit `decline`/`cancel` actions follows the retry outcomes below; it must not call the handler that starts the job. If an accepted action includes `content`, validate it exactly against the requested schema (empty object only); omitted content is valid. The protocol's request identity is the keyed `inputResponses` entry plus matching continuation state, not a user-supplied operation ID. Decline, cancel, timeout, and invalid retry outcomes must produce no job start, transfer start, staging, task record, job reservation, or other state-changing keeper call.

### Continuation-state requirements

The bridge must keep continuation data bounded and short-lived, and must not start a keeper operation while waiting. Bind state to: originating MCP session/connection where available, tool name, canonical normalized argument bytes (including `confirm` and all effect-relevant fields), request key, and an expiry. Do not trust a client-supplied description or state as operation authority.

Use an authenticated opaque state token (random unguessable nonce plus MAC) and/or a bounded in-memory record keyed by the nonce. The record/token must be one-use, non-replayable, and expire promptly; a concrete initial proposal is a 2-minute active expiry, at most 128 pending confirmations per server, and a fixed maximum serialized-state size (1 KiB). Retain only bounded expired tombstones for a further 2-minute classification window, with a total tombstone cap of 128; evict oldest tombstones first. During that window, a retry for a retained expired token can be reported as timed out. Once evicted or otherwise unknown, it receives the generic invalid-state error; never promise timeout classification beyond the retention window. Capacity eviction fails closed. Never persist pending confirmation state. State must not contain raw arguments or secrets in readable form; a record should hold only the minimum binding digest and expiry, and only if needed to recover the original validated operation.

On retry, require exact tool identity and canonical arguments, exact continuation state, the same request key, a valid single response with a known action, and unexpired unused state. An expired token is classified as timed out only if its tombstone is retained within the defined window; after eviction it is unknown and gets the generic invalid-state error. A mismatch, missing/unknown response, altered arguments, duplicate retry, or replay fails closed with a fixed tool error and no side effect. Do not let the model mutate arguments between rounds. Consume state atomically before allowing the tool handler to proceed so concurrent replay cannot start a second operation. A malformed or unavailable continuation never falls back to starting the operation.

## 4. Dialog content and disclosure limits

The dialog is a review summary, not a copy of arbitrary tool arguments. Its entire payload may show only non-attacker-controlled facts: operation kind, direction, an owner-registered server/application display name, entry count, total bytes, and overwrite status. Never show user- or agent-supplied names or paths—or any value derived from them, including hashes—including filenames, target names, root names, application names, command names, or path basenames; filenames can themselves be secret. Do not assume a target or application label is owner-controlled: establish provenance from an owner registration/configuration boundary before showing it; otherwise use a generic fixed label such as “registered target” or “application.” Values such as entry count and total bytes must come from side-effect-free validated preflight and be bounded. If they are unavailable, omit them. Overwrite status derives from the validated operation input, not a displayed path/name.

## 5. Outcomes and compatibility

| Condition | Proposed behavior |
| --- | --- |
| Owner option is OFF (default) | Preserve exact current flow and response bytes/shapes; no elicitation. `confirm=true` remains caller acknowledgment only. |
| Owner option is ON; client lacks the required form elicitation capability | Preserve exact current flow: dispatch the original call under existing rules; do not claim approval. |
| Owner option is ON; client declares form capability in this modern `tools/call`'s `_meta` and the operation needs confirmation | Return `input_required` before any state-changing keeper call, job reservation/creation, transfer start, staging, or task record. For non-observational `app_exec` only, the sole permitted pre-acceptance keeper request is side-effect-free application-command classification. If the client cannot display the form, cancellation/no retry means no start and no synthetic server result; this is the owner's compatibility trade-off. |
| Accept with valid bound retry | Consume state and invoke the unchanged current tool path once. The keeper still validates `confirm=true` and all existing authorization. |
| Explicit `decline` action on retry | No job started and no transfer started; no state-changing keeper call; return tool error `operation was not started: declined` with `isError: true`. |
| Explicit `cancel` action on retry | No job started and no transfer started; no state-changing keeper call; return `operation was not started: cancelled` with `isError: true`. |
| Retry received during the 2-minute expired-tombstone retention window | No job started and no transfer started; no state-changing keeper call; return tool error `operation was not started: confirmation timed out` with `isError: true`. |
| Missing/invalid answer, altered parameters, missing/unknown token, retry after tombstone eviction, duplicate retry, replay, or other binding/state validation failure | No job started and no transfer started; no state-changing keeper call; return the single generic error `operation was not started: confirmation could not be validated` with `isError: true`; do not disclose which check failed. |
| Elicitation hook auto-answers | A valid `accept` follows the ordinary accepted retry path. It is still not human or owner approval; do not present it otherwise. |

Tool errors above are only possible when the server receives a retry (or when an SDK path actually delivers an error to a bridge boundary that can return a tool result). At such a boundary, a recognized cancellation/timeout may map to its precise corresponding error above; another delivered SDK error may map to the generic validation error. Under modern MRTR, client-side SDK cancellation/timeout/disconnect may end the local call without a retry; the server has already returned `input_required` and cannot invent a final `tools/call` result. In that no-retry case no operation/job starts, there is no final server tool result for the input-required round, the client sees its own cancellation/transport failure, and pending state expires and is reclaimed. Do not promise global normalization at the server for failures it cannot observe. For a request without positively declared form capability in modern `tools/call` `_meta`, for any legacy path, or when confirmation is not required, dispatch the exact current flow and preserve its existing success/error text and shape; do not alter its error shape. The legacy path never elicits: initialize is only its capability fallback source and must not trigger the SDK legacy server-side automatic `Elicit` behavior. Modern 2026-07-28 capability is gated per `tools/call` `_meta`, not by `initialize`.

## 6. Jobs, tasks, and listener boundaries

### app_exec classification

`app_exec` eligibility is determined by the keeper's side-effect-free `app_classify` operation. It validates the registered application and command with the exact admission checks of `app_start` minus the confirm rule, and returns only `non_observational`. The bridge classifier calls it with a 3-second deadline and holds no keeper connection while the human decides. Execution still rechecks everything; the keeper remains authoritative. If classification fails or the application is unknown, `app_exec` is not elicited.

Confirmation precedes every state-changing keeper call. Before an accepted retry, do not start a job, start a transfer, stage data, reserve a job, create a task record, hold the keeper broker connection while awaiting the user, or make any other state-changing keeper call. The sole permitted pre-acceptance keeper request is the side-effect-free app_exec classification described above. Only after a valid accepted retry does the bridge execute the existing tool handler.

After acceptance, preserve current outcomes:

- `remote_upload` / `remote_download` start a transfer and return the existing job ID; clients declaring the Tasks extension may then receive the existing task path, with the task ID equal to that job ID.
- Other transfer clients and `app_exec` retain their current job-ID response and status/read path. `app_exec` has no Tasks path today.
- There is no need to use long-lived `subscriptions/listen` for elicitation. It is a job/listener notification channel, not the confirmation response channel. The bridge waits for the MRTR retry through the normal protocol exchange; it does not hold a keeper broker request open.

Existing Tasks support is specifically for transfer tools and is implemented by `internal/bridge/internal/tasks`; it intercepts the tool call and manages transfer jobs. Elicitation is a distinct MRTR concern. Do not treat `tasks/update`, `tasks/get`, or `subscriptions/listen` as substitutes for `inputResponses`.

## 7. Owner-controlled optional policy

The optional elicitation feature is **OFF by default**. Its enablement point is the `ssjack --confirm-elicitation run` startup flag in full mode. The flag value travels from the keeper to the bridge MCP process (`ssjack mcp`) over the existing authenticated keeper wire channel as a `confirm_config` operation, answered at bridge startup; an unavailable or failed answer defaults to OFF. When OFF, the existing request path and wire behavior remain byte-for-byte unchanged. When ON, a declared-form-capable client's inability to display the prompt and resulting cancellation means no start; with no retry the server cannot emit a final tool result. This is an explicit owner trade-off, not an accidental loss of current behavior. A future mandatory-per-operation mode is out of scope. No policy can be changed by the model through arguments or workspace files.

## 8. Implementation plan

1. **SDK/MRTR seam:** use each modern 2026-07-28 `tools/call`'s `_meta` as the positive form-elicitation gate; `initialize` is only the legacy capability fallback source, and legacy requests never elicit. Control or bypass the SDK v1.8.0 middleware so undeclared or legacy clients cannot enter its server-side automatic `Elicit` path; test request metadata capability separately from protocol revision.
2. **Confirmation state and gate:** add bounded, expiring, one-use continuation binding; canonicalize and compare tool arguments; handle duplicate/replay/mismatch and cancellation before dispatch. Before accepted retry, prohibit every state-changing keeper call, job reservation/start, transfer start, staging and task record. Permit only side-effect-free app_exec classification as a pre-acceptance keeper request; verify it has no side effects.
3. **Safe review text:** add a fixed allowlist summary builder with scalar validation, escaping and output bounds. Do not invoke transfer/app start to obtain metadata. Omit unavailable size/count and sensitive path information.
4. **Wire and side-effect acceptance tests:** raw JSON-RPC tests assert exact `input_required` bytes/shape including `content:null`, stable key, opaque state, retry with a new JSON-RPC id, fixed error outcomes and unchanged default-OFF/no-capability current-flow behavior. Test all three eligible tools. Before accepted retry, assert no job started, no transfer started, no staging, task record, job reservation or other state-changing keeper call; separately verify the permitted app_exec classification request itself has no side effects. Cover explicit decline/cancel retries and retained expired tombstones distinctly.
5. **Tasks/job regression:** verify accepted uploads/downloads enter the existing task path only after keeper job ID exists; verify fallback clients keep job IDs and app_exec remains on `app_read`; assert that no connection or listener is held open while waiting for the human (the only permitted pre-acceptance keeper call is the short side-effect-free app_exec classification).
6. **Owner opt-in and policy exclusion:** add optional elicitation enablement only through a deliberate owner-controlled startup/keeper setting or vault configuration that agents cannot write; keep it OFF by default and preserve exact current behavior when OFF. Do not add future mandatory-per-operation policy in this step.

Do not run builds or tests as part of this design task. The tests above are a proposed plan, not executed verification.

## 9. Test plan

When implemented, test with raw wire fixtures and SDK clients both with and without elicitation capability. Assert exact request and retry JSON, including `resultType: input_required`, one keyed `elicitation/create` form request, `requestState`, echoed response key, and SDK-compliant response shape. Use distinctive sentinel values in every argument and assert that secrets, raw argv, absolute local paths, credentials, content, arbitrary client fields, every value derived from caller-supplied names/paths, including hashes, and error text never appear in elicitation metadata or fixed errors.

Cover:

- overwrite upload and download, and non-observational `app_exec`; verify non-overwrite transfers and observational app commands preserve their no-elicitation behavior; verify `remote_exec` is unchanged;
- capable and incapable clients, default-OFF and owner-enabled modes, modern per-`tools/call` `_meta` capability gating without an `initialize` requirement, legacy fallback capability sourcing with no elicitation and unchanged old-client behavior, missing/malformed/declined/explicitly cancelled/timed-out retries, client-local cancellation/timeout/disconnect with no retry, capability boundary and ordinary retry; distinguish no-retry local failure from a server tool result/error and prove no job starts and pending state expires/reclaims;
- exact parameter binding including changed target, root, local/remote path, overwrite, application, argv, confirm, tool name and response key;
- bounded active and tombstone capacity, retained-window timeout classification, tombstone eviction/unknown-token generic error, and expiry;
- controls, invalid UTF-8, oversized scalar values, path display policy and summary bounds;
- no job started and no transfer started before acceptance; also assert no state-changing keeper call, task record, job reservation, listener, staging or external side effect; for non-observational `app_exec`, permit only side-effect-free classification and separately assert that classification itself created no job/task, reserved nothing and otherwise changed no state; exactly one normal dispatch after valid acceptance; actual keeper execution rechecks classification;
- accepted transfer task/job semantics and app_exec job/read semantics unchanged;
- explicit `decline`/`cancel` retries and stale/expired retries return their specified fixed tool errors; no-retry client cancellation, timeout or disconnect starts no job, produces no synthetic server tool result, and leaves state to expire/reclaim; verify any mapping of delivered SDK errors only at the bridge boundary that actually receives them.

Tests should prove absence of side effects using a counting/fake keeper and should assert raw request/response bytes, not only typed SDK values.

## 10. Open questions (proposed defaults)

1. **Should non-overwrite transfers be prompted?** Proposed default: no; first step is only existing confirm-required cases.
2. **What may the dialog disclose?** Proposed default: no user/agent-supplied names, paths, or any values derived from them, including hashes. Use only fixed operation facts and a display label whose owner-registration provenance is established; otherwise use a generic label.
3. **Can the transfer engine provide side-effect-free size/count preflight?** Proposed default: no new preflight for step one; omit size/count until one exists and is proven read-only.
4. **How long may a pending answer live?** Proposed default: two-minute active expiry, one use, RAM-only, plus bounded expired tombstones retained for two minutes (up to 128); after eviction/unknown token the error is generic.
5. **What happens without elicitation capability?** Proposed default: exact current behavior, with caller `confirm=true` remaining no more than acknowledgment; no implicit rejection or claim of human review.
6. **Can any client response count as owner approval?** Proposed default: no. A separate owner-authorized TUI/keeper workflow would require its own design and authentication boundary.
7. **What if cancellation/timeout/disconnect produces no retry?** Proposed default: no operation starts; pending state expires and is reclaimed; the server emits no synthetic final tool result for the `input_required` round, and the client owns the visible local cancellation/transport failure. Only an explicit cancel retry (or an error delivered to an actual bridge boundary) can produce a server tool result.
8. **Should mandatory owner policy be included now?** Proposed default: explicitly no; the optional feature itself is enabled only by owner-controlled startup/keeper or vault configuration, OFF by default. Mandatory-per-operation policy remains future/out of scope; no setting is accessible to model-controlled arguments or agent-writable files.

## Source basis and unverified claims

Repository facts verified for this design: `go.mod` pins go-sdk v1.8.0; `internal/transfer/internal/manager/handle.go` defines `StartInput` with `Confirm` and overwrite requiring confirmation; `internal/application/application.go` defines `Input.Confirm`, validates non-observational commands require confirm, and starts app jobs only after validation; `internal/bridge/internal/tooltext/registry.go` registers the relevant tools and transfer tasks; `docs/FILE-TRANSFER.md`, `docs/APP-CONTRACT.md`, and `docs/MCP-TASKS.md` describe current contracts. `internal/bridge/internal/tooltext/render.go` provides bounded one-line/result-rendering helpers, not general input sanitization; app output masking in `application.go` is limited to exact-token masking on child-process output.

SDK API/source evidence was inspected directly in the pinned go-sdk v1.8.0 module: `mcp/protocol.go` for MRTR types and JSON tags (including `CallToolResult.Content` as `json:"content"`, `ElicitResult.Content` as `omitempty`, and `CallToolParams` retry fields); `mcp/mrtr.go` for retry construction, new client request creation, and the legacy server middleware; `mcp/server.go` for unconditional installation of server MRTR middleware; and `mcp/shared.go` for `ServerRequest.ClientCapabilities()`. Claude Code 2.1.327 behavior and hook behavior are prompt-given facts and were not independently verified. All token structure, bounds, outcomes, privacy choices, open-question defaults and implementation details in this document are proposals, not implemented behavior.

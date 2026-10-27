# Conformance and negative matrix

**Status: proposed acceptance criteria; not implemented or approved.** Synthetic fixtures only. Approval unavailable: do not invent credentials, tokens, prompts, identities, approval services, or authorization paths. Passing checks do not authorize production drivers. See protocol, driver, policy, lifecycle and schemas.

## Synthetic happy path

Synthetic status: request `{"target":"demo","driver_id":"example.synthetic","kind":"cache","schema_id":"example.cache.desired.v1","resource_id":"primary"}` returns `{"state":"present","revision":"r1","observed_at":"2025-01-01T00:00:00.000Z","projection":{"capacity":2,"mode":"ephemeral"}}`. Cache capacity 0..10 and mode `ephemeral|persistent` as in schemas.md.

The deterministic effect comparator is ascending Unicode scalar order on `(class,summary_id,destructive)` (false before true). Emit a resize effect exactly when desired capacity differs from observed capacity; emit a mode effect exactly when desired mode differs from observed mode. Effects contain only changed dimensions, in comparator order. Old full bridge plus old full keeper remains unchanged.

1. Launcher selects declarative; one-use authenticated attachment negotiates protocol 1 and exact six tools. Client validates deterministic JSON Schema and enrolled documents. `both` invalid; full mode retains eight legacy tools. Any requested-mode/protocol negotiation failure is an explicit refusal, never silent downgrade. Old keeper refuses declarative; new bridge refuses old keeper.
2. `driver_list` exposes enrolled metadata; `resource_status` observes fixture projection/revision `r1`.
3. `resource_plan` request `{"target":"demo","driver_id":"example.synthetic","kind":"cache","schema_id":"example.cache.desired.v1","resource_id":"primary","desired":{"capacity":4,"mode":"persistent"},"request_id":"AQEBAQEBAQEBAQEBAQEBAQ"}` returns `{"plan_id":"AAAAAAAAAAAAAAAAAAAAAA","digest":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","expires_at":"2025-01-01T00:05:00.000Z","effects":[{"class":"cache.configure","summary_id":"cache.capacity","destructive":false},{"class":"cache.configure","summary_id":"cache.mode","destructive":false}],"precondition":"r1"}`. Digest is illustrative only, not a computed digest or test vector; compare output structure/order and precondition, not digest bytes. The corresponding distinct policy records are each delegated and non-destructive.
4. Apply request is `{"plan_id":"AAAAAAAAAAAAAAAAAAAAAA","request_id":"AQEBAQEBAQEBAQEBAQEBAQ"}`. Its successful typed result is `{"operation_id":"AgICAgICAgICAgICAgICAg","state":"SUCCEEDED"}`. The fixture's two effects are applied in order under CAS, changing `r1` to `r2` once. A no-op result after that transition uses fresh observation `{"verified":true,"projection":{"capacity":4,"mode":"persistent"}}` and revisions `{"applied":null,"delivered":null,"observed":"r2","adopted":null}` under exclusive ownership. No-op does not call apply or invent a revision.

`operation_read` reports evidence independently; adoption null absent enrolled verification. Same-live-session retries use durable idempotency. Attachment loss forbids reconnect and quarantines resource pending human inspection/fresh authorized launch. Times are UTC RFC3339 milliseconds.

Do not present JSON bodies as Ktav examples: Ktav encodes request/result payloads as strings, and these illustrative JSON snippets are not exact wire vectors. Successful application envelopes use `{ "result":<typed result>,"error":null }`; failures use `{ "result":null,"error":<typed error> }`. Operation states are uppercase. A no-op has no `applied` or `delivered` revision, has the actual fresh `observed` revision (null only under exclusive ownership), `adopted:null`, and a successful `result` with `verified:true` and the freshly observed desired projection. A subsequent no-op after the described CAS therefore observes `r2`; it does not invoke apply or fabricate a revision.

Before durable invocation-start/process call, proven failure means no invocation/effect. Once invocation may have started, outcome is unknown absent evidence.

| Area | Injection | Required result |
|---|---|---|
| Handshake | Missing/old protocol, mode/session mismatch, altered/extra/missing tool or schema | Fail closed, no full-mode fallback/invocation |
| Dispatcher | Legacy/unknown/forged operation | MODE_DENIED, restricted dispatcher, no fallthrough |
| Canonicalization | Duplicate keys, noncanonical/invalid UTF-8, trailing bytes, non-finite number, digest mismatch | Reject before invocation; no effect |
| Schema | Invalid JSON Schema document, unresolved ID/digest, unknown field | Reject enrollment/input; no foreign lookup/effect |
| Distribution | Missing document/artifact digest, changed schema under same ID, tampering | Reject before execution; immutable reviewed schema, no registry fetch |
| Identity | Changed executable/dependency/config/principal/OS identity/target/schema/sink, writable hook, missing dependency | Disable enrollment, invalidate plans; no invocation |
| Scope/secrets | Foreign resource, arbitrary path/endpoint/command, undeclared sink, guessed SecretRef | Foreign IDs indistinguishable NOT_FOUND; else deny; no resolution/disclosure |
| Approval | Required exceptional approval; fake token, model confirmation, TTY/local prompt | APPROVAL_REQUIRED, no executable approval plan/mutation; observe/plan allowed |
| No-op | Empty effects | Durable operation; fresh observe confirms desired+precondition; no apply/revision fabrication |
| Preconditions | Stale revision, absent CAS and no exclusive owner | PRECONDITION_FAILED/POLICY_DENIED pre-invocation |
| Idempotency | Same key+digest, changed digest, lost reply | Original result; changed digest CONFLICT; never duplicate effect |
| Expiry | Expired plan/repeated cleanup | PLAN_EXPIRED; idempotent cleanup, no invocation/revival; reserved retries return original record |
| Revocation | Principal/target/driver/enrollment/policy revoked for reserved/running | Stop not-started; request cancel started; block client reads/continuation; quarantine possible invocation |
| Capacity | Ordinary/emergency capacity exhausted | Refuse before effects: 32 ordinary active/session, 64 ordinary active globally, 64 ordinary processes globally, 16 emergency cancellation processes globally, ≤80 total processes; per-session storage 16 MiB/256 combined records |
| Interlock | Same canonical resource via session, alias, re-enrollment; uncertain outcome | Shared interlock; quarantine and deny reads/planning/apply |
| Bounds | Desired >32 KiB, projection >8 KiB, frame >64 KiB, schema depth >16/nodes >4096 | Reject before invocation/projection; bounded memory, no truncation |
| Framing | Extra JSON frame/bytes or oversized payload | Reject; subprocess exactly one request/response; broker framing separate |
| Output/evidence | Unknown/free-form field, unsafe sink, raw errors/stdout/stderr, missing verification | Reject output; no raw data; never infer convergence/delivery/adoption |
| Cancellation | Unsupported, pending/detached, lost reply, local termination | One durable intent, coalesced retries; accurately report unsupported/pending/unknown; no rollback claim |
| Retention | Budget full, active/unknown records, terminal <30 days | Refuse before effects; evict only eligible terminal records |
| Attachment loss | Disconnect after claim, including possible invocation | No reconnect/refresh/second claim/alternate credential/foreign lookup; quarantine scoped resource or enrollment/session |

Typed output cannot prove arbitrary backend text nonsecret; only reviewed typed output is eligible. Secret delivery/adoption remain null in v1.

## Limits and status

Driver subprocess frames ≤65536 payload bytes excluding prefix; complete ≤65540. Broker Ktav payload ≤262144 excluding prefix. Desired/projection caps separate. Active limits: ordinary 32/session and 64 globally (queued/running/unknown); processes 64 ordinary globally and 16 emergency cancellation globally, at most 80 combined. Four ordinary plus one cancellation process per enrollment. Per-session storage is 16 MiB and 256 combined records inclusive; cancellation reserve 4096 bytes per operation. No separate 256-active global cap. Limits and lifecycle budgets are proposed, not implemented. Human review required for enrollment, artifact/schema distribution, OS identity, principal, target, sink, connector and adoption. Tracking #131 declarative runtime, #125 application store, #140 crypto/unlock: task references only.

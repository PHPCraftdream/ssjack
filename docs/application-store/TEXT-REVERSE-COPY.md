# Reverse selected-text copy v1

This is the `reverse-copy-v1` adapter contract. Its actual Clawwright client and root-keeper/SSH pair are implemented; [full CI 41796602948](https://github.com/PHPCraftdream/ssjack/actions/runs/41796602948) passed on ssjack `0576409` with Clawwright `053655da09086986a23f66efe42dd5e8a2907f70`. See [paired evidence](CLAWWRIGHT-TEXT-PAIR.md). V2 is a separate opt-in [streaming path](TEXT-STREAM-HTTP.md), not an increase to v1 limits. This is no production enrollment, adoption or crash-durability claim.

## Human authority and lifecycle

Use the distinct root registration command `ssjack text-adapter register-reverse` (interactive; no registration fields in argv). It creates a grant bound to the existing authority fields: grant ID, recipient UID, exact store directory device/inode and path, installation hash, encoded snapshot hash, profile, public credential-identity digest, exact command, exact absolute file, exact canonical references (1–16, same store/snapshot), and UTC expiry. The reverse mode is `reverse-copy-v1`. Do not treat a hydrate grant or a synthetic delivery grant as reverse authority. Identity inspection and revocation use the existing `ssjack ... text-adapter identity` and root `ssjack text-adapter revoke GRANT_ID` flows.

Run with the same serve entry point and arguments as the adapter: `ssjack -p PROFILE --vault VAULT text-adapter serve GRANT_ID HARNESS [ARGS...]`. Serve validates grant/profile/credential and store identity, then exposes the dedicated pinned-HTTPS/MCP context. The recipient runs non-root; registration runs as root. The human must verify the approved command and exact file are appropriate. File metadata equality is authorization binding, not a shell argument substitution or proof of what the command writes.

## Dedicated transport

Require exactly `["text_reverse_copy"]` in `transport_info` capabilities. The reverse listener advertises `transport_info` and `text_reverse_copy`, not generic `transport_start`, `transport_input`, `transport_read`, or `transport_cancel`. It is separate from and does not alter existing raw Listen sessions. Reverse mode does not imply, call, or authorize `text_hydrate`; the forward `text_hydrate` contract remains unchanged and reverse never falls back to it.

Call the single tool with exactly these input fields:

```json
{"operation_id":"AAECAwQFBgcICQoLDA0ODw","file":"/approved/config","mode":"reverse-copy-v1"}
```

`operation_id` is canonical unpadded base64url for exactly 16 bytes in the core. The server applies its existing input string bounds (128 bytes for operation ID, 4096 for file); `file` must equal the grant's exact file. HTTP request bodies are limited to 256 KiB. No input text or template is accepted. The tool has one operation per capability; there is no durable replay ledger. Never retry or restart after an unknown outcome.

The result is one of `{"status":"withheld"}`, `{"status":"unknown"}`, or `{"status":"received","text":"..."}`. For received, `text` is safe UTF-8 and may be the empty string. For withheld or unknown, omit `text`; do not represent it as empty, null, or a guessed value. Withheld means no runner invocation. After invocation, an observed runner/authority/transformation failure yields unknown without copied text. Lost or incomplete network replies are classified UNKNOWN by the client; the server cannot know which bytes reached a disconnected peer. Unknown does not establish whether the command ran or what it did. Received means the command completed successfully and final checks passed; it does not establish application adoption, correctness, or durable storage.

## Data handling and transform

The exact approved command runs with empty stdin. Its raw stdout is captured only in bounded trusted process memory (at most 1 MiB); stderr and runner errors are discarded. No raw stdout fallback is returned. The implementation does not archive output, write temporary files, or rewrite live files as a backup side effect. Returned text is transformed in memory and is never sent through generic transport tools.

Reverse replacement uses the engine's exact supplied reference-to-value mapping, mapping each exact value back to its canonical versioned token. It is literal, leftmost-longest, nonoverlapping, single-pass; inserted output is not rescanned. Unmatched ordinary bytes, including UTF-8 and a BOM, are preserved. The adapter rejects NUL, invalid UTF-8, and unsupported opaque or oversized input. The byte-oriented engine rejects empty mapping values, equal references or values, values containing the literal `$ssjack` marker, and reverse input containing a registered canonical placeholder; ambiguous mappings fail closed. Malformed or unknown marker-like text that is not a registered canonical placeholder is preserved according to engine behavior.

There are at most 16 references; aggregate decrypted selected values are bounded to 1 MiB. Raw stdout and transformed output are each bounded to 1 MiB. HTTP bodies are bounded to 256 KiB; decoded file input to 4096 bytes; server operation ID input to 128 bytes, while core canonical ID length is exactly 16 decoded bytes. The operation deadline is the earliest of 60 seconds, grant expiry, and caller deadline.

### Cancellation linkage

Each authenticated reverse HTTP request owns an immutable, request-local MCP server/handler closure that captures that request's actual outer `r.Context`. A helper combines the captured request context with the SDK tool context, preserving the earlier deadline; cancellation observed by HTTP or cancellation from the SDK cancels the operation. Cleanup stops the cancellation registration and cancels the derived context. This uses neither a global context nor header-derived authority. It does not promise that an instant disconnect kills a remote process or that process death/adoption can be inferred. The finite core limit remains at most 60 seconds, bounded by grant expiry and caller deadline; network response writing remains separately bounded to 10 seconds as described above.

MCP notification/session cancellation is not synonymous with HTTP disconnect: this linkage is explicit. Prior CI run 41547256956 established that SDK callback-context cancellation alone did not cancel the prompt runner; it did not inspect the SDK's internal cancellation cause. The pinned-HTTP concurrency test (positive B while A and C follow cancellation) is part of the adapter regression coverage; the current exact-source receipt is linked above. The actual-root lost-response test retains unchanged assertions. Inherited-pipe child tests use bounded parent kill/wait and do not assume runtime pipe polling is available; no public contract depends on that runtime assumption, and the source handoff already records it.

The user remains responsible for exact value mapping completeness, escaping/representation, consumer compatibility, and storage. The engine provides no JSON quoting, escaping, URL encoding, derived-secret handling, or discovery of unknown secrets. No unknown-secret certification is made.

## MCP response size (enforced complete-body bound)

`internal/apptransport/text_reverse_response.go` defines `TextReverseResponseLimit = (24 << 20) + (64 << 10)`, exactly **25,231,360 bytes**. This limits the complete encoded HTTP response body, including JSON-RPC envelope and SDK content; it is not a payload-only allowance. `Server` separately sets `http.Server.MaxHeaderBytes` to 16 KiB for incoming request headers; that is not an outgoing response-body limit.

A reverse-only response writer buffers the SDK response body before attempting publication, and suppresses copied text only for failures it observes before publication (for example, an oversized buffered body or an already-canceled request context). This is not atomic network delivery: even with a complete SDK body buffered, the final network `Write` or `Flush` may fail after sending a prefix because of disconnect or timeout. A lost or incomplete reply is therefore **unknown**, classified by the client; the server cannot establish what the client received. Do not claim all-or-nothing network delivery. The writer tests cover exact-cap success, overflow, and canceled-context no-publication behavior; see the current exact-source CI receipt above.

The server starts a reverse response write deadline immediately before publication: the earlier of 10 seconds from that point and the request context deadline. Request cancellation advances the write deadline, and the watcher is joined. The deadline is cleared only after a successful write and flush while the request remains uncanceled; failures retain an expired write deadline. If the response writer does not support deadlines, publication fails closed with zero response-body write attempts (including for a large buffered body). The 10-second write allowance begins after control handling and SDK response construction, not at request arrival. Deadline/cancellation cases have `net.Pipe` regression tests; source-specific execution evidence is linked above.

The TEST budget root starts its 15-second budget after positive-control readiness. Only short grant registration plus constructor/listener/request setup is within that budget; scheduling failure is possible. This test budget grants no production time bypass.

The real pinned `github.com/modelcontextprotocol/go-sdk` v1.0.0 is exercised by HTTPS wire test `TestReverseTextWireLargeValidUTF8`. It checks 1 MiB UTF-8 cases including byte 0x01, control bytes, quotes, backslash, `<>&`, U+2028/U+2029, and Unicode; verifies exact decoded structured and text-content copies; and asserts raw wire body length is at most the cap. These wire assertions remain part of the CI regression suite; the exact-source full receipt above supersedes the original authoring-only status.

Downstream clients MUST read the full body, bounded to `TextReverseResponseLimit` using a cap+1 read and reject any overrun or incomplete full-body read, then validate successful HTTP status, JSON-RPC envelope/id/status, UTF-8, and decoded-text cap before publishing any selected text. A lost, incomplete, malformed, or otherwise unvalidated reply is **unknown**, classified by the client; never retry an uncertain operation. Keep request body at 256 KiB, raw and decoded command output at 1 MiB, references at 1–16, aggregate selected secrets at 1 MiB, and deadline as the earliest of 60 seconds, grant expiry, and caller deadline. Forward `text_hydrate` retains its published Group B contract (`d1db...`) unchanged and is not coupled to this reverse-only response cap.

Required root acceptance: TestTextReverseMappingsConnected, TestTextReverseLateConnected, TestTextReverseExpiryConnected, and effect-edge helpers invoked by TestTextReverseConnected cover literal multi-reference/equal-value/overlap behavior, dispatched revocation and expiry, pointer mutation, exact caller deadlines, and canceled HTTP responses. The required root CI runner rejects SKIP; supplied mapping completeness remains the operator's responsibility.

## Trust and verification boundary

Root registration and same-UID process isolation are administrative boundaries, not protection from a malicious root user, recipient process, harness, trusted runtime, kernel, or compromised host. A trusted runner and pinned HTTPS/MCP channel do not prove that the approved command's side effects are limited to the intended file. Secret-bearing output exists transiently in trusted process memory and can be exposed by a compromised runtime or host.

The actual v1 client and paired path are covered by the source-specific full receipt above; low-level assertions are not the entire acceptance proof. They do not establish safe handling of unselected secrets, live production enrollment or application adoption. Unknown outcomes remain non-retryable.

# Task261 source handoff

Source-only handoff. All listed authored tests are SOURCE-PRESENT ONLY, AUTHORED NOT RUN. No local execution (including compilation or gofmt), tests, public CI launch, or git writes were performed. Do not infer runtime acceptance or task completion. Parent owns review, publication, public CI, and cleanup; parent CI remains required.

## Source path and behavior

`root register-reverse` / `serve` → `NewReverseTextAdapter` → `ListenWithReverseTextAdapter` → pinned-HTTPS `text_reverse_copy` → grant/store/exact references/snapshot pin → bounded private capture → reverse replacement → late checks → safe text. Raw stdout capture is capped at 1 MiB; stderr is `io.Discard`. Production HMAC comparison uses constant-time comparison. The reverse-only encoded response-body cap is 25,231,360 bytes; distinct forward caps remain unchanged. Once dispatch begins, failures yield status unknown. Forward schema and capabilities are preserved in source; runtime regression validation was NOT RUN. See [TEXT-REVERSE-COPY.md](TEXT-REVERSE-COPY.md).

## Source inventory

- `cmd/ssjack/text_adapter_linux_amd64.go`
- `internal/declarativeauthority/text_adapter_linux_amd64.go`
- `internal/appstorecrypto/text_reverse_adapter_linux_amd64.go`, `text_reverse_outcome.go`
- `internal/appstorecrypto/text_reverse_connected_linux_amd64_test.go`
- `internal/appstorecrypto/text_reverse_mapping_connected_linux_amd64_test.go`
- `internal/appstorecrypto/text_reverse_late_connected_linux_amd64_test.go`
- `internal/appstorecrypto/text_reverse_expiry_connected_linux_amd64_test.go`
- `internal/appstorecrypto/text_reverse_expiry_control_linux_amd64_test.go`
- `internal/appstorecrypto/text_reverse_effect_edges_linux_amd64_test.go`
- `internal/appstorecrypto/text_reverse_authority_linux_amd64_test.go`, `text_reverse_capture_linux_amd64_test.go`
- `internal/appstorecrypto/text_adapter_linux_amd64.go`
- `internal/apptransport/server.go`, `text_reverse_response.go`, `text_reverse_test.go`, `text_reverse_response_test.go`, `text_reverse_wire_test.go`, `text_reverse_write_test.go`, `text_reverse_request.go`, `text_reverse_request_test.go`
- `docs/application-store/TEXT-ADAPTER.md`, `TEXT-REVERSE-COPY.md`
- `scripts/ci/test_declarative_scoped.py`, `scripts/ci/text_adapter_scoped.py` (inventory previously missing)
- `.github/workflows/feature.yml` and `.github/workflows/ci.yml` are read-only existing callsites; not changed.

## Authored test coverage (not run)

The six mandatory connected acceptance names are source-present: forward 2 (`TestTextAdapterConnected`, `TestTextAdapterBounds`) and reverse 4 (`TestTextReverseConnected`, `TestTextReverseMappingsConnected`, `TestTextReverseLateConnected`, `TestTextReverseExpiryConnected`). The gate requires PASS and forbids SKIP for all six; gated tests may skip when disabled, so this is a CI acceptance requirement, not evidence of a pass.

Reverse authored cases include actual root/nonroot encrypted fixtures; multiple references with leftmost-longest selection, repeats, equal-value refusal, aggregate overflow and positive control; late root revocation at explicit dispatch/handshake; snapshot pointer mutation and restore; exact caller-deadline propagation with cancellation after dispatch; grant deadline with exact expiry-after-dispatch, positive active control, and unknown outcome followed by withheld replay; and canceled HTTP request after dispatch with response body withheld and replay having no side effects. The encoded-body bound case uses the actual pinned SDK 1.0.0 serialization, worst-case 1 MiB escaping, duplicated JSON, and exact decoded-size/cap checks. New response-write deadline/cancellation `net.Pipe` tests are authored NOT RUN. Other connected coverage includes pinned-HTTPS positive path, canonical reference, repeated Unicode/BOM, empty and ordinary text, runner error/nonzero, raw-output/output-expansion overflow, invalid UTF-8/NUL, literal placeholder, late installation close, cancellation/replay, and grant/profile/credential/hash/version rejection. These describe authored source only, not execution results.

The reverse server buffers the complete SDK body before attempting publication and suppresses copied text only when it observes failure before publication. Complete SDK buffering does not guarantee atomic network delivery: final write/flush can disconnect or time out after a prefix. A missing or incomplete reply is UNKNOWN as classified by the client. Clients must await the full bounded body and validate HTTP status, JSON-RPC id/status, UTF-8 and decoded cap before publishing selected text; no retry. Unsupported write deadlines fail closed with zero response-body write attempts. The production 10-second owned write deadline begins immediately before network publication. Separately, the expiry test completes fixture creation and its positive control before registering the short-lived grant. Relevant listener/construction and request processing remain within the 15-second expiry budget as scheduled. No all-or-nothing network-delivery claim is made.

## Remaining review / public-CI gaps

- Execution receipts: compilation, gofmt verification, race validation, and required root CI acceptance are still outstanding. Parent review must independently verify the source inventory, case assertions, and mandatory PASS/no-SKIP selection; worker/source reports are not proof of completeness or runtime acceptance.
- Real live SSH is intentionally excluded from this acceptance scope. Future Task259/260 client work remains separate.

These are execution/review and explicitly excluded-scope gaps, not claims that authored required cases are missing. Previously accepted producer CI run `41533475792` is parent-reported, not new validation for this source-only handoff.

## First published candidate CI and follow-up source

Parent-published candidate `bb97175` was tested in CI run `41547256956`. Observed results: `TestTextAdapterConnected`, `TestTextAdapterBounds`, and `TestTextReverseMappingsConnected` passed; the lost-HTTP-context runner did not finish within 10 seconds; the expiry child inherited an FD where `SetReadDeadline` was unsupported, followed by late parent EOF. These are log observations, not claims about SDK internals.

The follow-up source changes capture the outer HTTP request context per request and combine it with the SDK context, with owned cleanup. The child-ack pipe `SetReadDeadline` was removed; parent-context kill/wait and the parent-grant read deadline are bounded. The production 10s deadline begins immediately before network publication; expiry readiness is independent test setup.

This patch is AUTHORED NOT RUN; no new CI run was performed. The earlier blanket “all tests not run” qualification applies to the new changes only; the candidate CI observations above are prior evidence.

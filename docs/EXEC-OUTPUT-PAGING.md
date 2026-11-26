# Exec output paging

This document designs the paged output contract for future `remote_exec`/`app_exec` task results (#485), prerequisite 2 of 2 for #474; sibling #484 truthful cancel is assumed landed. It follows the transfer-task design in `docs/MCP-TASKS.md` and adds no command output to task records.

## Current behaviour

- Each job retains 256 KiB per stream in a rolling buffer; reads are limited to 32 KiB; 64 job records are retained in RAM and at most 4 jobs are active. At job start, eviction removes the first completed job in insertion order; there is no time-based expiry. [ssjack code] `internal/remote/internal/jobs/jobs.go:16-21`
- Offsets are `int64`, independent for stdout and stderr, and count bytes in that stream. [ssjack code] `internal/remote/internal/jobs/jobs.go:35-58,213-240`
- An offset before the oldest retained byte advances to that byte and sets `lost=true`; an offset below zero or beyond the stream total returns `invalid output offset`. `more` means the offset is behind the total. [ssjack code] `internal/remote/internal/jobs/guard.go:111-145,148-152`
- Reads check completion before reading buffers; exit code/error are supplied when done. The manager returns raw `[]byte`. [ssjack code] `internal/remote/internal/jobs/jobs.go:213-240`
- A chunk renders as `stdout (bytes A-B):` (A is `next - len(data)`, clamped to zero), followed by text with invalid UTF-8 replaced by U+FFFD and an end marker. If the chunk contains invalid UTF-8, an additional `stdout base64 (bytes A-B): <base64 of original bytes>` line is rendered. [ssjack code] `internal/bridge/internal/tooltext/render.go:99-121,197-228`
- The next line is `Next: stdout_offset=%d stderr_offset=%d · more: stdout=%s stderr=%s · lost: stdout=%s stderr=%s`; overflow has a per-stream warning. An empty chunk renders `No new output.` [ssjack code] `internal/bridge/internal/tooltext/render.go:179-194`
- `remote_read` and `app_read` share one handler; their documentation says offsets count original bytes. [ssjack code] `internal/bridge/internal/tooltext/registry.go:136-149,236-251`
- `app_read` and `app_cancel` delegate to the same shared job manager and have identical semantics; app output is captured via secret writers, with the bootstrap token masked before capture. [ssjack code] `internal/application/application.go:284-307,217-230`
- Exec returns `Started job <id>`; read returns a stdout chunk then a stderr chunk and the `Next` line. Completion requires done and both `more=no`; credentials are masked before text is built. [ssjack code] `docs/REMOTE-MCP.md:346-418`
- Task-record non-goals forbid any new secret, path, remote output, or retained command output in a task record. Completed records are bounded to 64 and have one-hour frozen retention. A result is one text block with the polling guard and masking. [ssjack code] `docs/MCP-TASKS.md:769-779,275-282,313-331`

## Design decisions

| ID | Chosen option | Reason | Rejected alternatives |
|---|---|---|---|
| D1 | Task result carries **no command output**. It contains status, exit code, completion flag, resume offsets (`stdout_offset`, `stderr_offset`), per-stream `more`/`lost` flags, and instructions to fetch pages with `remote_read`/`app_read`. | Honors the task-record non-goal and keeps output retrieval in the existing read tools. | First-page-in-result exception: widens exposure, contradicts the transfer-design precedent, and complicates size bounds. |
| D2 | Keep the existing 32 KiB `chunkLimit` per stream per read, unchanged. Bound the rendered read response in rendered bytes. Per stream the text copy is at most 2x the chunk (64 KiB for 32 KiB): `strings.ToValidUTF8` replaces each maximal run of invalid bytes with one U+FFFD (3 bytes), and the worst case is alternating one invalid byte and one valid ASCII byte — 2 input bytes become 4 output bytes. When the chunk is not valid UTF-8, the base64 copy adds about 43.7 KiB (base64 of 32 KiB). Label and end-marker lines add a small constant. Worst case per stream is about 108 KiB, both streams together about 216 KiB (both chunks non-UTF-8 with alternating bytes); produced by input alternating invalid and ASCII bytes. Common case (valid UTF-8): text copy only, at most the chunk size — 32 KiB per stream, 64 KiB plus constants for both. | Preserves the current chunk contract while stating a bound that accounts for replacement expansion and base64. | A bound stated in chunk bytes only, which ignores the up-to-2x replacement expansion and the base64 copy. |
| D3 | Page stdout and stderr separately and independently; do not interleave them. Fetch stdout until `more=no`, then stderr, or fetch in any order because offsets are stream-local. Both streams must be drained before completion. | Matches their independent offsets and `more`/`lost` state while requiring both streams for completion. | A shared offset or interleaved page sequence. |
| D4 | Offsets are always byte-true. Multi-byte characters may split at page boundaries; document that a split character renders as two U+FFFD replacements across pages, while the base64 copy reconstructs the exact original bytes. | Maintains exact byte offsets and the fixed page size. | Snapping pages to UTF-8 boundaries breaks the fixed 32 KiB contract and byte-true offsets. |
| D5 | If a stream has `lost=true`, the result and every read report it. The model may resume from the reported offset (the oldest retained byte) and must treat the skipped range as permanently unavailable. Claim completeness only when done, both `more=no`, and both `lost=false`. | Makes rolling-buffer loss visible and prevents false completeness claims. | Treating a resumed read as complete despite lost output. |
| D6 | Output lives only in the RAM job record (256 KiB per stream), with a lifetime independent of any task record. Eviction of a completed job during paging is a documented failure mode: a read returns the standard unknown-job error and the model must report partial output. | Separates task-record retention from job-output retention and describes the bounded-memory failure mode. | Persisting or retaining output in the task record. |
| D7 | Keep secret-masking guarantees unchanged: credentials are masked before text is built and the app bootstrap token before capture. Paging adds no exposure because the result carries no output. Binary/base64 lines can carry the same secrets as text; masking-before-render already covers this residual risk. | Preserves the existing masking boundary across all rendered representations. | Treating base64 as inherently secret-free or introducing output into task results. |

## Task result shape

Under D1 nothing has been consumed on the model's behalf, so the reported offsets are the offsets the model must pass to read the whole retained output: per stream, the oldest retained byte — 0 when nothing was lost, and when an offset is not 0 the corresponding `lost` flag is yes. The `more` fields keep their read-response meaning: `more=yes` when the stream has bytes at or after the reported offset, so an unread non-empty stream is `more=yes` and only a fully drained or empty stream is `more=no`.

```text
Status: finished · exit code 0
Resume: stdout_offset=0 stderr_offset=0 · more: stdout=yes stderr=no · lost: stdout=no stderr=no · job <job_id>
```

(stdout has retained output the model has not seen; stderr produced nothing.)

Fetch remaining pages with `remote_read`/`app_read` passing exactly the reported offsets; drain both streams until done with `more=no` on both; treat any `lost=yes` range as permanently gone.

The result carries no output bytes, so its size is a fixed field set, well under 1 KiB, independent of output volume. Unverified: exact task-result rendering depends on the not-yet-implemented task path of #474.

## Where the result fields come from

Today the only keeper operation that reports exit code, completion state, per-stream totals and `lost` flags is the read operation, which returns up to 32 KiB of chunk bytes per stream and rejects offsets beyond the stream total. [ssjack code] `internal/remote/internal/jobs/guard.go:132-152`; `internal/remote/internal/jobs/jobs.go:213-241`

Chosen option (a): when the task finishes, the bridge issues one ordinary read at offset 0 for both streams, uses only the status fields (done, exit code, error, the per-stream oldest-retained offsets from the "Task result shape" definition, more, lost), and discards the chunk bytes without rendering them. Because the guarded capture path masks output before capture (`internal/remote/internal/jobs/guard.go:63-90`), the discarded bytes carry no unmasked secrets, and discarding happens before any rendering, so no chunk text or base64 reaches the task result. The memory cost is one bounded read per finished task: at most two raw 32 KiB chunks, because nothing is rendered (the 216 KiB figure of D2 applies only to a rendered read). Reads are non-destructive: the model's own first read from the same reported offsets returns the same bytes, so nothing is skipped.

Rejected: (b) a new side-effect-free keeper operation returning only status fields — cleaner in that no bytes are discarded, but it adds keeper/bridge wire surface and duplicates read logic for #474's benefit alone. Rejected: rendering the read and filtering chunk text out of the rendered result — fragile because it depends on the render format. If the owner prefers (b), it can replace (a) before #474 lands; the rest of this document does not change.

Test: `TestTaskResultContainsNoChunkBytes` (task layer, future #474) — run a job whose output contains a unique known marker, let the task finish, and assert the task result text contains neither the marker nor any base64 line, while a following read from the reported offsets still returns the marker bytes.

## Cancel, timeouts, and exit codes

- Cancellation: with #484's truthful cancel assumed landed, the result reports cancelled only when the job actually stopped. A cancelled job pages like a finished job: captured output stays readable at the same offsets until eviction; cancellation itself discards nothing. [ssjack code] `internal/remote/internal/jobs/jobs.go` (records survive completion or cancel until evicted).
- Timeouts: a job ended by its own timeout/failure reports the job's error and exit status exactly as the read path already does when done; paging continues on captured output. [ssjack code] `internal/remote/internal/jobs/jobs.go:213-240`
- Exit codes: the task result carries the exit code; offsets are unaffected by how the process ended.

## Error behaviour

| Situation | What the model sees | Expected handling |
|---|---|---|
| Offset < 0 or beyond stream total | tool error `invalid output offset` [ssjack code] `internal/remote/internal/jobs/guard.go:111-145` | correct the offset from the last reported `Next` line |
| Unknown or evicted job | standard unknown-job error | report partial output; never claim completeness |
| Buffer overflow (lost=yes) | per-stream warning line + lost flag in `Next` [ssjack code] `internal/bridge/internal/tooltext/render.go:185-194` | treat the skipped range as permanently gone; resume at the reported offset |
| Read of a cancelled job | normal read semantics on the retained buffer | page as usual |
| Non-numeric offset argument | tool argument validation error | fix the argument, do not guess offsets |
| Wait timeout while more=yes | normal read response, more=yes | read again later with the same Next offsets |
| Connection/session closed while paging | read fails | retry with the same Next offsets; offsets are server-side state valid while the job record lives |

## Test plan

Each invariant is owned by the layer that implements or documents it:

- Job manager (`internal/remote/internal/jobs`) owns byte-true offsets, lost marking, eviction order, and returning raw bytes. Cases:
  - `TestReadOffsetContinuity` — sequential reads over >64 KiB of output reproduce the exact original byte stream from concatenation.
  - `TestOffsetBeyondTotalRejected`.
  - `TestLostAfterOverflow` — write >256 KiB, read from 0, expect jump to oldest retained byte with lost=true.
- Renderer (`internal/bridge/internal/tooltext`) owns label bytes A-B, U+FFFD replacement, base64 of original bytes, and Next line format. Cases:
  - `TestBase64MatchesOriginalBytes`.
  - `TestSplitMultibyteAcrossPages` — 3-byte UTF-8 char split at the 32 KiB boundary renders one partial replacement char per page and the two pages’ byte ranges concatenate to the original bytes.
  - `TestBinaryOutputPage` — 32 KiB of random bytes renders ~43.7 KiB base64, valid Next offsets counting original bytes, and a total response within the documented worst-case bound.
  - `TestAlternatingInvalidBytesPage` — 32 KiB alternating one invalid byte and one ASCII byte renders a text copy of up to 64 KiB (2x expansion, one U+FFFD per invalid byte) plus ~43.7 KiB base64.
- Bridge registry owns the continuation contract (offsets count original bytes, pass Next offsets back). Case: `TestRegistryReadDocOffsetsOriginalBytes` (documentation/assertion level).
- Task layer (future #474) owns page sequence and size bound. Cases: `TestTaskResultContainsNoChunkBytes`; `TestResumeLineMatchesReadNext`; `TestCancelledJobPaging`.
- Edge/lifecycle cases:
  - `TestEvictionDuringPaging` — start 65 jobs while paging job 1, expect unknown-job error on the next page read.
  - `TestCancelMidPaging` — cancel then drain both streams to done.
  - `TestOverflowDuringPaging` — overflow occurs between two page reads, second read reports lost=true and a jumped base offset.
- CI scope: follow the project rule — ordinary pushes use diff-based test selection; run in public GitHub CI, not locally.

## Non-goals

- No change to the 32 KiB chunk limit or 256 KiB retention; no persistence of output to disk; no output in task records; no new secret exposure; no interleaving of stdout/stderr into one byte space; no client-side offset arithmetic beyond echoing the reported Next offsets; no modification of docs/MCP-TASKS.md here (the parent links this document).

## Decisions

These decisions were made on 2026-11-26, delegated by the owner to the implementer; all recommended options were taken. Each maps to the corresponding decision 1–5 in `MCP-TASKS-EXEC.md`.

1. **D1: No command output in task results.** The model fetches pages with `remote_read`/`app_read`, preserving the task-record non-goal and existing read-tool retrieval. **Rejected:** a bounded inline first page, which widens exposure and complicates size bounds.
2. **D2: Accept about 108 KiB rendered per stream and 216 KiB for both streams for non-UTF-8; keep pages at 32 KiB.** This accounts for replacement expansion and base64 while preserving the current chunk contract. **Rejected:** shrinking responses for non-UTF-8, which changes the documented read format and client expectations.
3. **D3: Cancelled jobs keep output pageable from offset 0.** Retained output remains readable until eviction, matching current behavior. **Rejected:** truncating on cancel, which discards retained output.
4. **D4: Use a distinct `Resume:` line, not the reads' `Next:` line.** This makes result-versus-read provenance unambiguous. **Rejected:** reusing `Next:` verbatim.
5. **D5: Keep D1 even though a finished job costs at least one read call.** The task benefit is no polling plus completion notification, not fewer round trips when output matters. **Rejected:** inline a bounded first page, which contradicts the task-record non-goal and complicates the size bound.

# Private selected-text v2 framing core

Status: framing and incremental template validation only. No v2 HTTP endpoint,
streaming SSH producer or Clawwright client is delivered by this package. Separate
crypto/authority modules prepare private tickets, but there is no execution route.
V1 CLI/transport limits and behavior are unchanged. An operation ID is correlation
metadata, not authorization or human approval.

`internal/appstoretextstream` provides synchronous `Encode` and `Decode` between
bounded readers/writers. NDJSON data frames have exactly `type`, `operation_id`,
`sequence` and `data`. `data` is canonical padded base64. A terminal frame has
exactly `type`, `operation_id`, `sequence`, `bytes` and `frames`, with type
`complete`. Sequences begin at zero and are contiguous. Empty documents have no
data frames and a zero-count completion frame.

Bounds are independent: 32 KiB decoded data per frame, 48 KiB per encoded JSON
record, 4096 data frames, 64 MiB decoded document, and 96 MiB total input wire data.
A caller supplies a positive decoded quota no larger than the profile maximum.
The writer accumulates bounded chunks even when the input reader returns tiny
fragments. The reader never retains the full document and refuses unknown or
duplicate fields, noncanonical base64, mismatched operations/sequences/counters,
missing newline/terminal completion and anything after terminal completion.

Decoded output is **tentative** until Decode succeeds and the surrounding
operation's authority, text validation and runner outcome also succeed. A late
failure may follow partial output; callers must not publish it or report received.
The codec alone does not enforce UTF-8/NUL rules, placeholder mappings, immutable
references, credentials, file/direction grants, private MAC preparation or final
file publication. Those belong to the producer and client integration.

Errors do not include raw frame bodies. No public content digest is added.
Cancellation and no-progress checks are bounded; interruption of a blocking
underlying reader/writer remains the transport owner's responsibility. No workers
are detached or started by this synchronous codec.

This package must only receive public template bytes or the already-transformed
private result appropriate to its direction. It does not authorize framing raw
registered secret values into any model-facing transport or result.

## Preparation API boundary

The incremental template scanner accepts UTF-8 without NUL, preserves scalar
boundaries and permits reserved `$ssjack` markers only inside exactly selected
canonical placeholders. It owns bounded lookahead, not a whole-document buffer.

`TextStreamAdapter.Prepare` checks its authenticated v2 grant, fixed file and
operation identity before reading, then rechecks authority after validation. A
separate-domain per-capability HMAC covers the metadata binding, template bytes
and final byte count. Only a random process-local ticket and count are returned;
the MAC and template content are never returned. At most one ticket is retained,
with finite expiry and best-effort MAC cleanup on Close. Preparation never calls
SSH. Ticket consumption, comparison with the execution pass, HTTP framing and
actual SSH execution still require integration and are not claimed by this API.

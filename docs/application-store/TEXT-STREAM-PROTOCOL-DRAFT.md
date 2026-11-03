# Selected-text streaming v2: implementation contract draft

Status: design for tasks 273/274, not an implemented endpoint or CLI feature.
The accepted v1 profiles and their limits remain unchanged. The new core engine
alone does not implement this protocol.

## Why a separate profile

The pinned MCP SDK serializes complete JSON tool results. Raising the v1 body
cap would still retain the full document in memory. Large forward input also
cannot remain one template string in a JSON request. The streaming path needs
bounded framing and explicit authenticated completion, not a larger scalar.

A separate private HTTP stream route must reuse the existing pinned loopback
TLS transport, bearer capability, exact profile and finite root-installed grant.
It must not become a generic raw read, execution or secret retrieval endpoint.
V1 clients refuse the new capability instead of silently changing validation.
V2 clients never fall back to a secret-bearing legacy/raw operation.

The initial profile should support at most 64 MiB of decoded input and output,
with existing selected-secret/reference limits retained. This is bounded large
text support, not arbitrary-size files. Grant expiry, caller cancellation and
finite operation/network deadlines still apply. Frame parsing and I/O must not
allocate a buffer proportional to the document's total size.

## Framing and completion

- Closed header schemas bind operation ID, file, direction and the exact granted
  references. Public refs and a capability token are not human approval.
- Decoded data frames are at most 32 KiB; base64 framing avoids splitting JSON
  strings or treating partial UTF-8 sequences as complete text.
- Each frame has a contiguous sequence number. Header/frame wire sizes, decoded
  totals, frame counts and final completion are bounded independently.
- A terminal frame binds the operation and successful byte/frame totals. The
  client accepts received only after that frame, complete HTTP body/EOF, exact
  totals and text validation. Duplicate, trailing, truncated or malformed frames
  cannot publish an output file.
- No public unkeyed digest of templates, raw source or selected secret values is
  introduced. Transport authenticity/order and private operation MACs own these
  checks; error diagnostics contain neither raw bodies nor SSH stderr.
- Post-dispatch uncertainty produces unknown without a public copied result and
  without automatic retry. No stream is resumed after a lost reply.

## Forward: bounded preparation and one execution attempt

To avoid raw-template disk staging, preparation and execution use two passes.
Preparation reads bounded frames, checks canonical reserved placeholders and
UTF-8/NUL rules across boundaries, verifies that all refs are granted, and computes
an operation-private MAC. It never invokes SSH. It retains only bounded metadata
and an opaque single-use process-local ticket with finite expiry.

Execution consumes that ticket exactly once, rechecks authority, then streams
hydrated bytes through the fixed approved SSH writer using bounded RAM pipes.
Its private MAC and counters must match preparation before received is possible.
If the source changes between passes, a late rejection may follow partial remote
effects; that is unknown, not withheld or atomic rollback. The existing product
never promises atomic application adoption. Refusal during preparation must have
zero runner calls. A ticket is not a durable cross-process replay ledger.

The client holds and identity-checks the original template file across passes;
there is no new decrypted secret temporary file. Runtime/private snapshot pinning
continues to use the existing encrypted snapshot path and crypto guarantees.

## Reverse: tentative private transformed frames

The fixed approved SSH reader's stdout feeds private bounded RAM pipes into
ReplaceStream. Raw source never goes through MCP-facing results, operator files,
logs, argv, environment or stderr. Matching and raw-input ambiguity checks remain
independent of read/frame boundaries. Raw/transformed text validation is
incremental; completion cannot certify an invalid trailing sequence.

The private client may stage only the already-transformed selected copy using
the same exclusive, same-parent publication boundary as existing backup output.
It must not stage raw source or selected secret values. Staged copy bytes remain
private until complete successful validation and exclusive final publication;
failed operations remove their owned partial output and return no text. The
operator still owns mapping completeness: unmatched other secrets are not
certified absent, exactly as with the accepted v1 backup. This does not authorize
incidental raw-secret plaintext staging or weaken database encryption.

Large-copy APIs should publish to an explicitly selected output file and return
status/metadata, not accumulate a whole-document string. Existing bounded
backupText results and public exports retain their v1 contract.

## Required proof before publication

Use actual Clawwright CLI, keeper grants, authenticated transport and isolated
SSH composition for a file larger than 1 MiB. Add counterfactuals for wrong
profile/direction/refs/file, malformed preparation with no SSH contact, source
change between passes, limits, tiny/oversized frames, invalid UTF-8/NUL, late
ambiguity, nonzero SSH exit, cancellation, lost completion, short writes and
existing output. All pipeline workers must terminate and join on every path.

Keep crypto profiles, immutable references, source-layout/tooling receipts and
ordinary structured/provider non-enrollment unchanged. A draft, mock or green
core test is not producer/client pair acceptance. All execution is GitHub CI;
no real user file, credential or server is part of implementation testing.

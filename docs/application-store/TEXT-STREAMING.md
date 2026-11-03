# Large-text streaming: core contract

`internal/appstoretext.ReplaceStream` is a private replacement primitive, not a
new wire capability or public secret API. Existing v1 selected-text transport
limits and grants remain unchanged until a separately versioned producer/client
path is implemented and accepted.

## Engine behavior

- Literal, leftmost-longest, nonoverlapping replacement. Output is not rescanned.
- The same exact-reference and mapping validation as `Replace`; total selected
  value bytes additionally cannot exceed 1 MiB.
- Input and output have explicit finite byte quotas. A one-byte input overflow
  probe is permitted. Quotas are not unlimited-file or unlimited-runtime claims.
- Memory depends on the largest bounded mapping/placeholder and fixed 32 KiB
  chunks, not total file size. Writes are no larger than 32 KiB.
- Matches may span arbitrary reader boundaries, including a value spanning many
  reads. Reverse-copy ambiguity checks inspect raw input independently of
  replacement skips, so a registered placeholder cannot hide inside consumed
  bytes or across reader boundaries.
- Unknown bytes remain unchanged. As with the existing engine, completeness of
  mappings and literal representation is the operator's responsibility.

## Tentative output and cancellation

The writer is a trusted tentative sink. A late invalid placeholder, read error,
quota violation, write error or cancellation can occur after previous writes.
Only complete successful return permits a caller to publish a received copy.
This low-level API does not provide atomic publication, delivery evidence,
authentication, retry safety or rollback of previous writes.

Callers must provide bounded/cancelable I/O. Checking context before/after reads
and writes does not interrupt a blocking reader or writer by itself. Persistent
operator-side staging, if required, must be encrypted; this primitive does not
authorize plaintext temporary files or forwarding tentative data to a model.
Approved deployment consumers may receive plaintext within their separately
authorized destination boundary.

The crypto profiles, app-store formats, master-key lifecycle and existing
transport uncertainty rules are not changed by this engine implementation.

## Acceptance boundary

Differential tests compare bounded cases with the existing engine. Additional
CI tests cover multi-megabyte text, maximum mapped values, chunk boundaries,
late raw-input ambiguity, explicit byte quotas, short writes, stalled readers
and cancellation during final publication to the tentative writer. These are
synthetic correctness tests, not local load tests or live-server execution.

Producer/wire integration, a complete authenticated response and Clawwright's
exclusive validated publication remain separate acceptance units. A green core
engine test does not mean large files are already supported by the CLI.

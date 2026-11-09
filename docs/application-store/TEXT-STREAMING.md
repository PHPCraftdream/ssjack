# Large-text streaming: core contract

`internal/appstoretext.ReplaceStream` is the private replacement primitive used
by the separate v2 producer/client path. It is not a public secret getter.
V1 limits/grants remain unchanged. The current [v2 HTTP/CLI path](TEXT-STREAM-HTTP.md)
and actual Clawwright pair passed in
[full CI 41796602948](https://github.com/PHPCraftdream/ssjack/actions/runs/41796602948)
on ssjack `0576409`; the engine alone is not evidence of that complete path.

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

Producer/wire integration, final authenticated completion and Clawwright's
exclusive validated publication have their own connected acceptance, in addition
to engine tests. See [HTTP/CLI contract](TEXT-STREAM-HTTP.md) and
[paired evidence](CLAWWRIGHT-TEXT-PAIR.md). The accepted v2 CLI supports bounded
large text, not unlimited files, arbitrary binary backups or application adoption.

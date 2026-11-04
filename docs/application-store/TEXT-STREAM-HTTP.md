# Private text-stream HTTP transport APIs

Status: directional producer/transport and Clawwright streaming CLI/API have
functional paired CI acceptance. Forward and reverse listeners remain separate
and opt-in; v1 defaults and limits are unchanged. Full-sprint verification and
release remain separate gates.

The verified pair is ssjack `9ce209e45c8a8d6c2345f960c3708a3f58ebcea5` and
Clawwright `b0babb132d74532746501b3aeda92e088d343d17` in
[CI 41755082293](https://github.com/PHPCraftdream/ssjack/actions/runs/41755082293).
Both mandatory legacy and streaming pairs reported PASS without SKIP. The v2 case
uses the actual Clawwright CLI entry, root finite grants, UID 65534, pinned HTTPS
and authenticated/pinned SSH for greater-than-1-MiB deploy/backup/exact restore,
source preservation, existing-output refusal and exact-version refusal before
SSH. It does not establish production enrollment, interactive approval/unlock
prompts, crash durability or OpenClaw adoption.

## Explicit CLI path

An independently trusted root operator runs `ssjack text-adapter register-stream`
and enters the finite exact registration metadata interactively, including the
resolved credential record identity, refs/snapshot, file, command and expiry.
The displayed v2 grant requires the exact `APPROVE STREAM TEXT ADAPTER GRANT_ID`
phrase before writing the separate registry. Flags or a parsed grant are not
human approval. `revoke-stream GRANT_ID` addresses only that v2 namespace.

The non-root operator starts
`ssjack [-p PROFILE] text-adapter serve-stream GRANT_ID HARNESS [ARGS...]`.
Named `--server`/`--account` selectors also resolve through the authenticated vault
load; the stable selected record ID is used for grant checks and server scope.
The operator unlocks the credential database and bound application-store
installation through hidden terminal input. The child receives only the usual
private endpoint/token/pin bootstrap, not vault/master values. Broker sessions
and wrong grants refuse; no fallback to v1 occurs. For reverse streaming, root
instead uses `register-reverse-stream` and confirms
`APPROVE REVERSE STREAM TEXT COPY GRANT_ID`. The same `serve-stream` entry selects
the reverse listener only for an authenticated `reverse-copy-stream-v2` grant;
it never enables both directions. `revoke-stream` covers either v2 direction.

The Clawwright child selects v2 with `--stream-references grant-refs.json` on
`deploy-text` or `backup-text`. The file is a bounded UTF-8 JSON array of the exact
canonical placeholder strings from the grant, not secret values or approval.
The existing `SSJACK_TEXT_LAUNCH=1` and expected `SSJACK_TEXT_PROFILE` child mapping
converts only the temporary endpoint/token/pin bootstrap. Use `serve-stream`, not
the legacy serving entry; there is no protocol fallback. Restore uses a separate
forward context and the unchanged captured reference-only file.

`ListenWithTextStreamAdapter` explicitly enables two POST paths on the existing
pinned loopback TLS listener: `/text-stream-v2/prepare` and
`/text-stream-v2/execute`. The same exact host, single bearer, no Origin and no
query constraints apply. A legacy listener refuses these paths. The v2 listener
advertises protocol 2 and only `text_hydrate_stream_v2`; it does not register raw
exec/stdin/stdout MCP tools or v1 text tools. `transport_info` remains metadata-only.

Requests use one `application/x-ndjson` Content-Type. The first newline-terminated
JSON record is a closed header with `format: ssjack-text-stream-v2`, a canonical
16-byte base64url `operation_id`, the resolved credential `profile`, exact `file`,
and the selected canonical `references` array. Execute also requires a canonical
16-byte base64url `ticket`; Prepare must not supply it. Headers are limited to
16 KiB. The producer checks exact profile/file/reference-set equality against its
captured grant; parsed header fields are not permission.

The remaining body uses [bounded framing](TEXT-STREAM-FRAMING.md). Body size,
read/write deadlines and decoded quotas are finite. Decoder-to-producer transfer
uses a bounded private pipe. Decoder errors close that pipe with an error;
producer rejection closes the body/pipe and joins the decoder. Successful
preparation requires authenticated producer success and complete framed EOF.
Execution reports received only when both producer and decoder succeed while the
request is active. Late framing/transport uncertainty cannot become received.

Responses are small JSON metadata: format, operation_id and status. A prepared
reply also has a random ticket and byte count (zero count may be omitted).
Execute returns only withheld/unknown/received metadata, never hydrated text,
SSH stdout/stderr, raw source or content hashes. Responses are not cacheable.
No automatic retry or resume is defined.

## Reverse streaming API

`ListenWithReverseTextStreamAdapter` enables only
`POST /text-stream-v2/reverse-copy` in addition to metadata-only `transport_info`.
It advertises protocol 2 and only `text_reverse_copy_stream_v2`. Forward, legacy
text and raw execution routes remain unavailable on this listener.

The request is exactly the same closed header as Prepare, followed immediately
by body EOF. Tickets, data frames and trailing bytes are refused before dispatch.
The selected reverse-v2 grant must match the exact credential, source file and
reference set; metadata matching does not grant authority.

SSH stdout flows only through bounded private RAM pipes, reverse literal
replacement and incremental text validation. Stderr is discarded. Output is a
tentative reference-only copy, not a rewrite of the source. Both decoded raw
input and transformed output are limited to 64 MiB; selected values retain the
1 MiB aggregate bound. Late ambiguity, malformed text, nonzero SSH exit,
cancellation or failed authority/snapshot rechecks produce unknown, not success.
All pipeline workers are joined before the producer returns.

Successful responses use `application/x-ndjson` and the bounded data/complete
framing. The complete frame is withheld until the producer returns received
after all final checks, even if its output pipe has already reached EOF. A
failure after tentative data yields an incomplete stream, which the client must
reject without publication. A failure before any data is written returns bounded
JSON withheld/unknown metadata instead. Clients must require the expected content
type, exact operation ID, complete counters and complete body EOF, then publish
only the transformed copy. Missing completion never authorizes retry or resume.

Transport tests use real TLS/bearer requests with synthetic adapter implementations
to exercise multi-megabyte framing, missing completion, opt-in/authentication and
raw-tool refusal. They do not replace positive registered-root/SSH/client pair
acceptance.

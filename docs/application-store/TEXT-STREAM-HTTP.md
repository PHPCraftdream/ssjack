# Private forward-stream HTTP transport APIs

Status: internal forward transport wiring, not a delivered Clawwright feature.
CLI registration/startup, actual root-granted route acceptance and the streaming
client are still pending. Reverse streaming is not implemented by this route.
V1 remains unchanged.

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

Transport tests use real TLS/bearer requests with synthetic adapter implementations
to exercise multi-megabyte framing, missing completion, opt-in/authentication and
raw-tool refusal. They do not replace positive registered-root/SSH/client pair
acceptance.

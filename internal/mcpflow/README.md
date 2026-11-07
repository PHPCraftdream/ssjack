# Bounded MCP HTTP exchange ownership

This pocket owns HTTP I/O lifetime, not endpoint approval, credentials, local grants
or a model-facing API. `mcphttp.NewUpstream` supplies the fixed public HTTPS policy
and private header-preparation/clear callbacks. Callbacks are trusted local code;
clear must not block or reenter. No network request occurs during construction.

Each transport has a lease of at most 10 minutes (or the earlier parent deadline),
4096 admitted HTTP messages and four active exchanges, including unread streaming
responses. One listening GET and one cleanup DELETE are permitted. Reopening a
listening stream is refused, including SDK reconnection after an SSE EOF without
an event ID. No automatic renewal, cross-endpoint retry or uncertain mutation
replay is provided. The SDK transport also explicitly disables its retry setting.

Requests are finite POSTs labelled application/json or bodyless GET/DELETE; the
private SDK, not this resource layer, constructs and validates MCP messages. Request bodies are privately
copied and checked against exact Content-Length and 64 KiB before peer effects.
Protocol header names are closed, duplicate/resumption/idempotency headers refuse,
and total prepared headers are at most 16 KiB. GetBody is removed before dispatch.
Owned request buffers are cleared after the peer RoundTrip and joined memory reads.

Responses stream through a 256 KiB byte limit. Body errors and overflow use only
fixed `ErrExchange`, never peer diagnostics. Redirects and error-status bodies are
not forwarded; optional 404/405 listening/cleanup responses retain only their status
and an empty body. Header output is restricted to MCP/content metadata. Status text
is reconstructed and Response.Request is removed so injected authentication cannot
be recovered through that pointer. Successful MCP message bodies remain private SDK
input: this layer does not replace the later parsed-result guard/error boundary.

Response close cancels its request before closing the source, joins an active read,
and releases admission exactly once. Context cancellation closes even an unconsumed
response (the pinned SDK does not explicitly close its DELETE response). Owner Close
cancels all exchanges and clears credentials only after owned I/O joins. Incomplete
Close retains material and can be waited again; failed source Close is sticky,
returns failure and does not clear material or claim safe completion. Go erasure is
best effort; this does not certify power-loss behavior, all standard-library internal
goroutines, remote session revocation or a process-memory sandbox.

The tests use bounded fake HTTP peers, controlled in-memory body barriers and no
public endpoints. They cover exact/overflow bounds, source ownership, response
sanitization, no replay, admission limits, cancelled/unconsumed bodies, incomplete
join and failed cleanup. Real TLS/SDK composition is exercised in mcphttp tests.
The remote selector, grants, supervised bridges and harness integration remain
unfinished; this pocket alone does not enable the remote MCP product path.

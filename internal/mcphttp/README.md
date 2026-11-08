# Fixed remote MCP endpoint policy

This pocket now constructs a lazy private authenticated HTTP capability through
`NewUpstream`. It composes fixed endpoint/header policy with `mcpflow` body bounds,
lease, cancellation and joined shutdown. Construction performs no network request.
The private grant layer (`mcpgrant`) composes `NewUpstream` lazily at explicit
issuance; the supervised bridge runtime (`internal/mcpbridge`) composes it
through the grant layer at explicit issuance, and the product startup activates
it only for a receipted non-empty choice. This capability is
not itself evidence of owner approval or a model-facing credential getter.

The fixed endpoint must be canonical HTTPS without userinfo, query, fragment or
control bytes. DNS names are ASCII (punycode is accepted), dotted and bounded;
IP literals must pass the public-address policy. Ports are canonical decimal.
Requests cannot substitute the URL/path or Host override. The issued HTTP client
installs `rejectRedirect`; exchange also refuses redirect responses before client
redirect handling. Even same-origin redirects are not followed.

Dial admission checks every answer before any connection, refuses more than 16
answers without truncation, then dials a resolved literal rather than resolving
the hostname again. Mixed public/private answers refuse as a whole. Loopback,
private, link-local, multicast, metadata/CGNAT, documentation, benchmark, reserved,
IPv4-compatible, NAT64, Teredo, 6to4 and scoped/zone addresses are refused. IPv4-mapped
addresses are unmapped before classification. IPv6 is restricted to global unicast
allocation space with additional special-range exclusions. An error is fixed
`ErrTransport`, never a DNS/dial diagnostic; dial failure is not automatically
retried on a second address. This is not protection against a trusted administrator
changing OS routing, root certificates, the resolver or the running process.

The standard HTTP transport has no environment proxy, verifies the original host
with system roots and TLS 1.2 or newer, and bounds dialing, TLS handshake, response
headers, header bytes and connections. These constraints do not relax independent
private delivery or SSH routes. Public-only remote MCP policy is intentionally
stricter than the encrypted record schema, which can store an unavailable endpoint.

## Private authentication material

The private builder reuses `mcpdirectory.ValidateAccount`, refuses disabled records
and owns the bytes for the already supported none/Bearer/Basic/custom-header modes.
It prepares only a cloned exact-endpoint request. Case-insensitive caller collisions
with Authorization, Proxy-Authorization, Cookie or selected credential headers
refuse; source headers are not modified and material retains no source request or
caller credential buffers. Go request cloning shares the body at the header-preparation seam; `mcpflow`
independently copies, bounds and closes that source before peer effects.

The only returned matching capability contains raw known credentials, actual
Authorization/header literals and Basic's actual base64 credential component.
This protects known transmitted forms without claiming generic encoded-value DLP.
There is no public header or value getter. Closing private material clears its
owned byte buffers and prevents reuse; existing snapshots retain their captured
protection. Previously prepared Go request strings cannot be reliably erased or
revoked by clearing those buffers. The exchange owner cancels and joins
owned I/O before closing material; failed/incomplete close retains it and reports
failure. Go erasure remains best effort, not a memory sandbox.

## Pinned SDK findings

The repository pins `github.com/modelcontextprotocol/go-sdk v1.0.0`; no dependency
or project version was changed. Its `StreamableClientTransport.MaxRetries == 0`
means five retries, not zero. `Take` issues one lazy transport using `-1`, an
explicit bounded HTTP client without a cookie jar, and redirect refusal. Reuse
refuses. Callers must close their SDK session before the upstream owner, must not
format raw SDK errors into model output, and must never replay an uncertain mutation.
The pinned SDK supports `2025-06-18`, `2025-03-26` and `2024-11-05`, and rejects
unsupported initialization versions. This is not a claim of 2026 protocol support.
The bridge must preserve that explicit compatibility boundary rather than silently
adopting a different protocol or upgrading dependencies.

Sources: [streamable transport](https://github.com/modelcontextprotocol/go-sdk/blob/v1.0.0/mcp/streamable.go),
[protocol constants](https://github.com/modelcontextprotocol/go-sdk/blob/v1.0.0/mcp/shared.go),
[client initialization](https://github.com/modelcontextprotocol/go-sdk/blob/v1.0.0/mcp/client.go).

Policy tests inject private lookup/dial functions and use in-memory connections.
A private loopback TLS fixture separately exercises the real pinned SDK with
verified test roots and Basic/custom-header authentication. The public constructor
still refuses that loopback endpoint; there is no public test or insecure mode.
No test performs public DNS or provider requests, adds a credential getter or calls
a model. Transport expiry is at most 10 minutes; it does not silently renew. Its
owner must call Close for joined cleanup even after expiry.

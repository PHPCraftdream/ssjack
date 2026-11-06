# Fixed remote MCP endpoint policy

This pocket is an unused transport-policy foundation. No runtime calls it yet.
It does not hold credentials, mint a session grant, implement MCP requests, launch
a bridge or enable a remote connection. Private authentication/header custody,
request/response body bounds, grant lifetime and joined shutdown remain separate
integration work; this policy alone is not a usable authenticated MCP client.

The fixed endpoint must be canonical HTTPS without userinfo, query, fragment or
control bytes. DNS names are ASCII (punycode is accepted), dotted and bounded;
IP literals must pass the public-address policy. Ports are canonical decimal.
Requests cannot substitute the URL/path or Host override. The future HTTP client
must install `rejectRedirect`; it must never follow even same-origin redirects.

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

## Pinned SDK findings

The repository pins `github.com/modelcontextprotocol/go-sdk v1.0.0`; no dependency
or project version was changed. Its `StreamableClientTransport.MaxRetries == 0`
means five retries, not zero. A future upstream transport must use a negative
value to disable SDK retries and must never replay an uncertain mutation.
The pinned SDK supports `2025-06-18`, `2025-03-26` and `2024-11-05`, and rejects
unsupported initialization versions. This is not a claim of 2026 protocol support.
The bridge must preserve that explicit compatibility boundary rather than silently
adopting a different protocol or upgrading dependencies.

Sources: [streamable transport](https://github.com/modelcontextprotocol/go-sdk/blob/v1.0.0/mcp/streamable.go),
[protocol constants](https://github.com/modelcontextprotocol/go-sdk/blob/v1.0.0/mcp/shared.go),
[client initialization](https://github.com/modelcontextprotocol/go-sdk/blob/v1.0.0/mcp/client.go).

Tests inject only private lookup/dial functions and use in-memory connections.
They perform no public DNS lookup or live endpoint request and add no runtime
configuration, test bypass, credential getter or model-provider call.

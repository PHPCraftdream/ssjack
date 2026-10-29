# Optional read-only anchor HTTPS binding

This isolated package maps a canonical 48-byte anchor Read to one HTTPS POST
with `application/octet-stream` request/accept headers. Only HTTP 200 with an
exact 352-byte signed, correlated reply is accepted. It is an optional transport
profile, not an existing enrolled service or a production MCP integration.

`New` requires an explicit HTTPS endpoint, nonempty CA pool, client certificate
and matching exportable PKCS8-compatible private key, service Ed25519 public key,
and nonzero store ID. URL userinfo, queries and fragments are rejected. There is
no credential file lookup, system trust fallback, default endpoint or environment
proxy. Configuration is caller-controlled, not model-selected.

Each `Read` requires a live context with an explicit deadline. It generates a
fresh cryptographic request ID, uses a fresh TLS 1.3 connection without session
resumption, checks a verified server chain and a compatible client-certificate
request before HTTP is sent, and verifies the reply signature and exact
operation/store/request correlation. Responses are capped at 353 bytes and
headers at 4096 bytes. Redirects, cookies, compression, connection reuse and
application retries are disabled. There are no Create/CAS or generic send APIs.
DNS resolution and network access occur only when the caller invokes Read.

One read per client state is admitted with a nonblocking lock. Client copies
share lifecycle state; Close waits for an active read, clears owned private DER
and permanently closes every alias. Certificate DER, private DER, public signer
and roots are copied at construction. Nonexportable/HSM keys are unsupported.
Clearing owned DER is best effort: parsed private keys and TLS/runtime copies
are not guaranteed erased. This is not a process-wide operation budget.

Supplied trust is not human enrollment or trusted endpoint provenance. A client
certificate request does not prove server-side certificate validation, per-store
role policy, authorization, service linearizability, freshness, rollback safety
or nonce reservation. Signed Rejected/Unknown/NotFound outcomes remain verified
observations, not action permissions. Backend details are hidden behind opaque
errors; context cancellation may be returned separately. No production tool,
secret delivery, mutation, durable state, filesystem writer or sealing is wired.

Tests use synthetic certificates and localhost servers only. They cover valid
correlated reads, fresh IDs/connections, configuration ownership, proxy bypass,
TLS/mTLS refusal before HTTP, trust-pool copying, invalid reply/status/length,
redirect refusal, cancellation, deadlines, shared Close and busy admission.
Execution belongs to public GitHub CI; no real endpoint or credentials are used.

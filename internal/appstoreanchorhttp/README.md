# Minimal authenticated anchor endpoint

This opt-in server composes the canonical service core and concrete durable ledger
for the encrypted application-store writer. It serves metadata only: no secret
values, plaintext files, generic getter, shell or deployment driver. It opens no
credential files or listener. A caller must supply an explicit listener, canonical
Host authority, owned runtime TLS certificate/key, Ed25519 signing key, nonempty
client CA pool and a bounded immutable certificate/store/role registry.

TLS is exactly 1.3, requires verified client certificates, disables tickets and
HTTP/2, and configures no early data. Client identity is SHA-256 of the verified
leaf DER. Only the exact configured credential/store pair selects a reader/writer
Grant and concrete ledger. Unknown certificates or stores never invoke it;
request fields cannot assert role or identity. One store cannot map to competing
backend instances in the same server. Supplied enrollment/trust provenance remains
the operator's responsibility; configuration is not proof of human identity.

The only route is POST `/anchor` at the fixed authority, binary content type,
without query/encoded-path/absolute-form URL, browser Origin or content encoding.
Bodies are capped at 305 bytes before exact DTO parsing. Valid replies are the
352-byte correlated Ed25519 envelope; errors never include backend details.
Capacity/canonical collisions yield Rejected, uncertain/busy/unavailable backends
yield Unknown, and a mutation result is signed only after durable Execute returns.
The TLS boundary does not add journal semantics that the core cannot prove.

Admission is fixed at 32 connections and eight handlers. Header/body/network write
deadlines are bounded. Outstanding IDs are scoped by credential/store through
response flush. Read collisions and changed canonical requests are rejected;
an identical in-flight mutation returns Unknown, never a false no-effect denial
or a duplicate invocation. Completed durable replays retain the original result.

Certificate DER, parsed private key, roots, signing key and registry are copied at
construction. Nonexportable keys are unsupported. Copies share lifecycle; Serve
is one-use, Close stops admission/connections and waits for actual handlers before
clearing the owned Ed25519 signing bytes. Caller-owned backends remain caller-owned.
TLS/runtime key copies are not guaranteed erased. Filesystem IO can block beyond
network deadlines; cancellation/Close cannot promise a hard total time bound or
revoke an in-flight ledger operation. A lost response requires authenticated
Read/reconciliation, not automatic mutation retry or an assumption of no effect.

Synthetic public-CI tests use actual TLS requests, independent client certificates,
the existing Read client, actual create/reserve/commit DTOs and persistent restart
replay. They cover reader denial, unknown/untrusted client refusal, TLS12/missing
cert refusal, HTTP shape/size, credential/role ownership, CA-pool copying, shared
Close and ID leases held through a blocked response flush. The private-handler
lease unit fixture does not establish authentication; real-network tests cover
that boundary. The concrete ledger is currently Linux-only; other native jobs
still compile the server and exercise portable credential checks.

There is no production launch/enrollment, private-key persistence, application
snapshot writer or consumer delivery yet. A secure encrypted-credential launcher
and the reference-only placeholder path remain separate required integration.

# Optional fixed-scope anchor HTTPS bindings

`Client` remains strictly Read-only. `New(Config)` requires an explicit HTTPS
endpoint, nonempty CA pool, matching exportable client certificate/private key,
service Ed25519 public key and nonzero store ID. It owns credential copies and
selects no files, system trust, default endpoint or environment proxy. Supplied
configuration is caller-controlled, not model-selected or trusted enrollment.

`Client.Read` generates one fresh cryptographic request ID and sends canonical
Read48. A separate opt-in `NewWriter(Config)` creates `Writer`, whose `Submit`
accepts only immutable admitted Create/Reserve/Commit requests for the fixed
store. It never accepts raw request bytes, arbitrary operations or alternate
endpoints. Server-side enrolled certificate roles remain mandatory; constructing
Writer with a reader certificate does not make that credential a writer.
`Writer.Read` makes a fresh ordinary Read for explicit caller reconciliation.

Both transports require an explicit live context deadline, fresh TLS 1.3/no
resumption connection, verified server chain and compatible client-certificate
request before any HTTP body is sent. Exact correlated signed Reply352 and HTTP
200 are required; body/header caps remain 353/4096 bytes. Redirects, cookies,
compression, proxy use, connection reuse and application retries are disabled.
Only private exchange internals are shared; Client gains no mutation method.

`Submit` validates the exact resulting proposed state with `CheckMutation`:
Committed -> ExactRecordedResult, Conflict/Unknown -> ReadRequired, and signed
Rejected -> ReportedRejected. Network/timeout/correlation/signature/wrong-state
failure after entering exchange returns no reply, ReadRequired and an error.
Local preflight/closed/busy failures return no classification because this call
did not enter exchange; they do not prove anything about another in-flight call.
No automatic Read, retry, replacement request ID or idempotency key is generated.
The controller still needs authenticated Read-first reconciliation and durable
original-byte replay permission before resubmitting; recorded outcomes are not
necessarily the latest current state.

One operation per client state is admitted nonblockingly. Writer copies share
Close and their internal Read/Submit exclusion. Close waits for actual operation
return and clears owned private DER; TLS/runtime copies are not guaranteed erased.
Nonexportable/HSM keys and host-wide resource/erasure guarantees are unsupported.

Supplied trust is not human provenance, authorization, verified intent fsync,
linearizability, historical ID uniqueness, nonce reservation or permission to
seal/deliver secrets. No production MCP tool, generic secret-get, consumer sink
or snapshot writer is enabled. SSH formats and fixed cryptographic profiles are
unchanged.

Public CI tests preserve all Read-only transport cases and add real durable mTLS
service create/reserve/commit/original replay/reconciliation, reader-credential
denial, invalid local scope/type/deadline, shared Close/busy, signed wrong-state
and correlation rejection, Unknown/status handling and absence of automatic
retry. Fixtures use synthetic credentials and localhost servers only; no local
test/build execution or real credential access is performed.

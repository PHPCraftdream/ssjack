# Private captured remote MCP credentials and one-shot launch capabilities

This pocket owns private captured remote-MCP credentials bound to an exact
saved-state revision plus saved-cipher digest evidence, a finite admission
lifetime and a construction context, and mints fresh bounded one-shot launch
capabilities (lazy mcphttp upstreams) only for one explicit confirmed owner
choice. It is not authorization by itself; there is no RPC or tool
registration, no model-facing operation and no credential getters.

Admission refusals: stale profile/revision, empty or oversized (more than 16)
choices, duplicate, unknown or disabled records. Context cancellation and the
finite lifetime are rechecked at admission, at every record boundary and
before a launch is returned; the exact deadline instant refuses, and a
cancelled or expired mint never returns a usable launch. Issued launches carry
both the capture's construction parent and the caller's issuance context into
their exchange lifetime. Exactly one successful issuance exists per capture; repeated
issuance refuses. A failed or cancelled mint attempt also consumes the
capture, because uncertain effects are never replayed; recapture with fresh
evidence instead.

Owned credentials are deep-copied bytes independent of caller buffers and of
Vault adoption or close. A failed construction clears its owned copies, and
Close clears owned bytes. Go erasure stays best effort; this is not a
process-memory sandbox.

Launch is lazy: no network occurs before the supervised bridge Takes and connects.
Each minted upstream permits exactly one one-shot Take, at most 16 upstreams
are minted, and each inherits the finite mcpflow lease (at most 10 minutes, no
renewal). Every upstream carries a union outputguard capability covering all
transmitted authentication literals, including Basic's encoded component. When
mint-time cleanup cannot join completely, the retained upstreams stay
reachable through the capture and its Close retries them instead of claiming
joined completion; there is no unguarded fallback. Test source covers active-I/O
cancellation and joined shutdown in the mcpflow and mcphttp composition layers;
this pocket adds admission, one-shot, union-guard and retained-cleanup ownership
above that boundary, releasing the parent-cancellation callback when the launch
lifecycle action runs.

Reuse performs no second database or install unlock and no per-operation KDF;
records come from one already-authenticated session state.

Startup prepares this bounded launch only after the actual terminal selector
confirms a non-empty choice and encrypted preference persistence is flushed and
receipted. The launch and its authentication-literal guard stay owned by the
startup credentials through shutdown; the supervised bridge runtime consumes
the one-shot upstream handles through Take and the guard through an explicit
close callback, so exactly one consumer exists. Empty confirmed choices persist
without a launch. Platform-neutral startup and connected native acceptance is
authored for Linux, Windows and macOS, but actual three-OS runtime acceptance and
exact-SHA public CI receipts are pending owner CI. Historical runtime receipt
`6913e5f` and archive receipt `07290ca` are verified CI evidence for distinct
earlier sources; dedicated task #359 remains pending.

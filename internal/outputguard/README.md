# Known-literal stream matcher

This package implements the known-literal matcher for the MCP-only output guard.
Full-mode keeper startup supplies retained private snapshots to guarded remote and
registered-application job capture before model text/base64 serialization.
Human SSH/PTY/editor streams and private delivery protocols are outside its
integration surface.

`New` builds an immutable sparse byte trie with Aho-Corasick failure/output links.
It retains no caller buffers and offers no pattern or stored-value getter. Empty
literals are ignored. Duplicate literals have the same matching effect; all
supplied bytes still count against construction limits. Zero snapshots refuse.

Each `Writer` has its own bounded decision window. Matches are leftmost-longest,
byte-exact across writes, and nonrecursive: `[REDACTED]` is never matched again.
The maximum literal length determines how long safe output can be delayed. A
possible prefix is never released merely because a timer expired. Explicit stream
close resolves the final incomplete prefix; partial or unknown secrets are not a
protection claim. Independent streams do not match across stdout/stderr boundaries.

Limits are 1024 supplied patterns, 1 MiB of supplied pattern bytes, 64 KiB per
literal and 131072 trie nodes. Exceeding any limit refuses the entire construction;
there is no truncation or implicit unguarded fallback. Each stream retains at most
one maximum-length byte window plus one match-length slot per byte and a bounded
emission buffer. Sink writes are at most 32 KiB plus one marker. Replacement
expands output by at most the marker length per input byte. Failure-link traversal
is linear in input plus discovered matches, not a rescan of every buffered prefix.

A sink error or short write poisons the stream, clears its pending buffers and
returns only the fixed `ErrGuard`, not private downstream diagnostics. Neither
writing again nor closing reports success afterward. Close is otherwise idempotent
and never closes the borrowed sink. Successful close clears pending byte buffers.
Snapshots remain immutable RAM capabilities; Go memory erasure is best effort and
this package is not a same-user debugger or process-memory sandbox.

`Union` merges two validated immutable capabilities without pattern getters.
It preserves old and new literals, deduplicates identical literals and refuses the
whole union if unique-pattern, total-byte or trie-node limits would be exceeded.
Repeated unchanged refresh does not accumulate duplicates. Neither input changes;
existing streams continue to own their previously captured snapshot. Retention
policy and publication remain the runtime owner's responsibility, not this helper.

`vault.Session.OutputGuardAt` privately captures database credentials only at an
exact saved revision and nonzero saved-ciphertext digest. It includes SSH passwords,
private keys, proxy passwords, remote MCP authentication/header values and the linked
installation master, including credentials not currently enabled. It refuses
pending persistence, save errors, closing sessions and unresolved owner intents.
It does not collect linked application values or retain the startup database password.
`appstorecrypto.OwnerEditor.OutputGuard` separately captures selected exact committed
bindings after clean-editor, reference, writer-history and current-state checks.
Neither seam returns values or performs another unlock; errors are fixed `ErrGuard`.

Runtime integration must compose both capabilities, refresh only from confirmed
owner state, preserve old literals needed by frozen consumers and filter before any
original-byte base64 or textual result can reach a model. A saved revision is not
consumer adoption. Control fields, private hydration, signed/binary protocols and
human streams must remain unchanged. These private construction seams alone do not
route model output through filtering.

`remote.NewGuardedManager` is an explicit model-job construction path. It obtains
one capability before runner effects, uses independent stdout/stderr writers and
captures only filtered bytes. Read offsets, retained-buffer loss and chunking refer
to that filtered view; rereading at arbitrary offsets cannot recover original
bytes. Both streams finish before a job becomes done. Provider/guard failures use
fixed `ErrGuard`; runner failures use fixed `ErrJob`, without formatting private
errors. Known cancellation/deadline failures retain their fixed context sentinel;
private error strings are never formatted. Full-mode keeper and registered
application jobs use this constructor by default. A missing provider refuses jobs.
The unguarded manager remains a separate primitive; private stream/human paths are
unchanged and do not obtain this additional output filter.

`ownerdb.Manager.OutputGuard` composes both private snapshots under owner admission,
checks the exact saved ciphertext before and after construction and retains a bounded
union of previously admitted literals. Busy/pending/import/recovery states refuse;
construction failure never returns the old capability as a stale fallback. Linked
state uses the retained installation/editor instead of another Store lease or KDF.
Each admission validates the latest confirmed state and current linked history;
there is no per-packet unlock and no raw-value RPC. Manager close drops its history
reference after consumer shutdown; captured immutable capabilities remain usable
by their existing holders. This is admission-time refresh, not automatic live-stream
adoption. Startup must seed before exposing frozen runners or admitting private
consumers. The real agent credential loader now seeds before starting the owner
service, then retains the manager provider for subsequent confirmed-state admission.
If that first seed fails, its provider remains refusing for that startup; later
success must not silently omit credentials already frozen without initial coverage.
Legacy version-1 startup instead captures a fixed credential snapshot from an
unchanged authenticated Vault before closing it. It checks the retained authentication,
canonical payload and saved ciphertext without repeating KDF, and cannot substitute
for version-2 linked-value admission. Main startup passes the same provider to
remote and application model-job managers, not to their private StreamRunner or
application-transport streams. Registered-application bootstrap-token masking
remains in place inside the known-literal guard.

Native acceptance drives separate actual keeper and harness processes in PTY/ConPTY.
The harness authenticates to the real broker, calls MCP tools through the SDK and
checks guarded SSH output in both text and decoded base64. A second job after an
actual owner-helper credential addition must pick up the new known literal without
restarting the keeper. Both edit and restart cycles require explicit PASS receipts
on Windows/Linux/macOS; the synthetic SSH fixture accepts only its exact finite
probe command, never a general shell command executor.

`--no-output-filter` is a root startup option for one explicit full-mode `run`.
It requires input and warning terminals outside existing broker sessions, then
normal database authorization. A conspicuous fixed warning must be written before
launch; failure to write it refuses. The choice uses a deliberately validated
empty snapshot only for this additional literal guard, never as a construction
failure fallback. It is not persisted, read from environment, forwarded to the
harness or exposed as a runtime MCP toggle. Cryptography, permissions, grants,
private delivery, fixed diagnostics and application bootstrap-token masking stay
enabled. Human streams remain unfiltered regardless of this option. Terminal
presence is a necessary boundary check, not proof of a distinct human identity;
the password holder and trusted startup process retain the existing owner trust.

The independent native bypass profile checks the warning, exact unfiltered model
text/base64 bytes, non-forwarding of the root flag, continued human SSH echo and
legacy-writer refusal, and authenticated encrypted database readback. Application
child tests separately retain bootstrap-token masking under a deliberately empty
literal snapshot. SSH stream regression tests pass fullscreen/ANSI sequences,
NUL and invalid UTF-8 through stdin and echoed stdout byte-for-byte; this is not
an assertion that a particular external editor was installed or driven.

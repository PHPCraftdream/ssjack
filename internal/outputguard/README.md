# Known-literal stream matcher

This package is a foundation for the MCP-only output guard. It is not yet wired
to keeper snapshots or MCP capture/serialization and does not enable filtering by
itself. Human SSH/PTY/editor streams and private delivery protocols are outside
its intended integration surface.

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

Actual integration must obtain authorized known values privately, refresh only
from confirmed owner state, keep old snapshots alive for their captured streams,
and filter before any original-byte base64 or textual result can reach a model.
It must preserve control fields, private hydration, signed/binary protocols and
human streams rather than applying this writer indiscriminately.

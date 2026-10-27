# Wire format and catalog

All integers are unsigned big-endian; no optional fields, implicit padding, or trailing bytes. Catalog is exactly 1MiB, zero-padded. Reject malformed public framing, overflow and inconsistent lengths before allocation/KDF. See [FORMAT](FORMAT.md) for caps.

## Snapshot bytes

| Offset | Size | Field |
|---:|---:|---|
|0|8|ASCII `SSAPP001`|
|8|2|version 1|
|10|2|flags zero|
|12|16|random store_id|
|28|16|random snapshot_id|
|44|16|parent_snapshot_id; zero only for genesis|
|60|4|chunk_size=1,048,576|
|64|8|total plaintext including catalog, 1MiB..2^40|
|72|4|chunk_count=ceil(total/chunk_size), 1..1,048,576|
|76|4|reserved zero|
|80|128|four distinct 32-byte KDF salts|
|208|12|random nonce_base|

Then exactly `chunk_count` ordered records: `u32 index || u32 plaintext_len || u32 ciphertext_len || ciphertext`. Index starts zero; `ciphertext_len=plaintext_len+16000`; chunks except final are 1MiB, final is residual. Then exactly `FIN1 || u64 ciphertext_len=16048 || 16048 ciphertext bytes`. Exact file length is `220 + sum(12 + plaintext_len_i + 16000) + 12 + 16048`, with checked arithmetic. Total equals sum of chunk plaintext lengths.

## Catalog and objects

Chunk 0 is always exactly 1MiB. Bytes 0..7 are `SSCAT001`; 8..23 store_id; 24..39 snapshot_id; 40..43 `u32 object_count` (0..16,383); followed by exactly that many 64-byte entries sorted lexicographically by `(object_id,version_id)`: `object_id[16] || version_id[16] || u64 length || u64 first_chunk_offset || media_type[16]`. Offset is the first payload byte's absolute offset within concatenated chunk-plaintext payload after the catalog, so chunks may span object boundaries. Media type is a zero-padded lowercase ASCII token: 1..15 bytes from `[a-z0-9.+-]`, optionally one `/` separating nonempty components, no parameters; remaining bytes zero. Reuse an exact `(object_id,version_id)` only when the pair is in the authenticated immediate parent and bounded byte-for-byte comparison confirms identical bytes. Otherwise generate a fresh random nonzero version ID and reject collision with every known retained/anchored pair. A removed historical pair cannot be proven absent without complete history: do not claim a global no-resurrection guarantee; fail closed if history is incomplete and strict non-reuse is required. There is no content-hash field. References remain pinned to exact snapshot; retention must preserve referenced snapshots or fail resolution. Tail bytes must be zero. Object and version IDs are nonzero; reject duplicate `(object_id,version_id)` pairs and duplicate version IDs for an object in a catalog. Empty objects have length zero and offset equal to the current payload cursor at their catalog position (no bytes consumed), including zero when they precede all payload. Nonempty entries follow catalog order and their byte ranges exactly partition payload bytes with no gaps/overlap. Lengths may be arbitrary; chunk boundaries do not imply object boundaries. Aggregate object bytes <=2^40; total includes catalog 1MiB and is <=2^40. Zero objects is valid. No object bytes are released before full snapshot and full object verification.

`SecretRef=(store_id,object_id,version_id,snapshot_id)`, not a bearer capability. Resolve exact versions only; absent exact-snapshot references fail.

## Finalization

Final plaintext is exactly `ASCII("FIN1") || u64 total_plaintext || u32 chunk_count || SHA256(all complete encoded chunk records including each 12-byte prefix, in order)`. Encrypt with same 1000-layer construction, reserved index `0xffffffff`, plaintext length 48/ciphertext length 16048, AAD `SSAPP final layer`. It is physically last and excluded from its own hash. Verify final tag, transcript, all chunk tags, canonical catalog and exact spans before release.

Known exact lengths are required before header serialization. Unknown/non-repeatable sources are refused. Repeatable immutable sources provide stable revision and exact length; size first, stream second, compare revision/length after, discard candidate on mismatch. No plaintext staging. These are proposals, not implemented behavior.

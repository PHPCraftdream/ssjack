# Independent synthetic vector recipe

Recipe only: no KDF/test run and no output claimed. Test-only injection replaces only Argon: `A_r=SHA256(ASCII("test-kdf")||passphrase_bytes||salt_r)`, 32 bytes; retain all other steps. Production is fixed profile in [CRYPTO](CRYPTO.md). Synthetic data only.

Use passphrase ASCII `vector-passphrase`; salts `00..1f`, `20..3f`, `40..5f`, `60..7f`; store_id `00..0f`, snapshot_id `10..1f`, parent zero, nonce_base `a0..ab`. Four sorted catalog entries (sorting by object_id then version_id):

1. object_id `20..2f`, version `30..3f`, length 6, offset 0, media `text/plain` padded with six zero bytes; payload `vector`.
2. same object_id `20..2f`, version `31..40`, length 3, offset 6, media `text/plain` padded with zeros; payload `new`.
3. object_id `40..4f`, version `50..5f`, length 0, offset 9, media `text/plain` padded with zeros.
4. object_id `60..6f`, version `70..7f`, length 1,048,579, offset 9, media `text/plain` padded with zeros; payload bytes repeat `00,01,...,ff`.

All entries are exactly 64 bytes: 16+16+8+8+16. Offset is payload cursor after catalog: second version starts at 6, empty entry and final object start at 9; total payload is 6+3+1,048,579=1,048,588. Empty entry consumes no space and has current cursor offset. Catalog is 1MiB, header/catalog IDs match, count=4, entries sorted, remainder zero. Payload total is exactly 1,048,588 bytes; snapshot total is 2,097,164 bytes; `chunk_count=ceil(2,097,164/1,048,576)=3`. Chunk 1 contains the first 1MiB of concatenated payload, crossing object boundaries; chunk 2 contains residual. Derive injected outputs/HKDF and all keys/nonces/AAD; seal 1000 layers per chunk and final; digest complete encoded chunk records. No computed bytes are claimed.

Two independent implementations must reproduce exact bytes and reverse-open; assert final hash excludes final record and includes complete encoded chunk-record prefixes; verify whole object before release. Also cover zero entries, multiple empty objects, multiple short objects and versions, boundary-spanning objects, chunk boundary shared across object boundaries, exact multiples, max 16,383 entries, invalid offsets/lengths, and mutations. Inject reservation/journal-cap failure; crash before/after each CAS; lost reply; extra local journal suffix; missing/changed anchored prefix; anchor offline/mismatch; candidate durability failure; stale pointer; spool mutation; and interrupted second pass. Before successful commit CAS, the prior committed tuple remains authoritative; after successful CAS, the new tuple is authoritative even if the local pointer lags. Never reuse reserved IDs. Production-profile CI is separate; recipe is not evidence of execution or production Argon behavior.

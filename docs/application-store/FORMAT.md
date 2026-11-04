# Application store design (proposed)

**Design baseline; unaudited, not production approval.** This page retains the broader format proposal; it is not the current runtime inventory. Implemented encryption, installation, owner CRUD/export/import and finite delivery/text paths are documented in [CLI entry](ENTRY.md), [crypto runtime](CRYPTO-RUNTIME.md) and [the capability map](../README.md), with exact-source CI receipts. Human enrollment, an actual recovery-anchor service and platform durability remain separately controlled boundaries. The design chooses a dedicated app-store master rather than reusing the SSH master; the owner session can retain a linked installation unlock under database encryption. Master input stays in trusted hidden terminal/owner-session boundaries, never model tools, argv, logs or network. [IO](IO.md) specifies the anchor state machine; specifying it does not provision a service.

- [Wire format, catalog and identities](WIRE.md)
- [KDF, layers and uniqueness](CRYPTO.md)
- [Streaming, publication and recovery](IO.md)
- [Synthetic vector recipe](VECTOR.md)
- [Adversarial failure matrix](FAILURES.md)
- [Source compatibility](COMPAT.md)

Proposed limits: chunks 1MiB; catalog exactly 1MiB; aggregate object bytes and total plaintext <=2^40; <=1,048,576 chunks; <=16,383 catalog entries; <=32MiB non-KDF working set/operation; <=2 active store operations and at most one KDF operation process-wide (Argon workspace ~1GiB, excluded from 32MiB). One active chunk/writer per store. Checked arithmetic and bounded backpressure mandatory.

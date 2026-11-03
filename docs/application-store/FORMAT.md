# Application store design (proposed)

**Proposal; unimplemented and unaudited; not approved for production.** Dedicated human app-store master is chosen; SSH master is not reused. No secrets accessed. Human enrollment, authorization, recovery-anchor service and platform durability require review. Passphrase must be entered only through trusted human terminal input and never sent to tools, argv, environment, pipes, files, logs or network. The concrete anchor state machine and byte encodings are specified in [IO](IO.md), as a proposal, not a claim about an existing service.

- [Wire format, catalog and identities](WIRE.md)
- [KDF, layers and uniqueness](CRYPTO.md)
- [Streaming, publication and recovery](IO.md)
- [Synthetic vector recipe](VECTOR.md)
- [Adversarial failure matrix](FAILURES.md)
- [Source compatibility](COMPAT.md)

Proposed limits: chunks 1MiB; catalog exactly 1MiB; aggregate object bytes and total plaintext <=2^40; <=1,048,576 chunks; <=16,383 catalog entries; <=32MiB non-KDF working set/operation; <=2 active store operations and at most one KDF operation process-wide (Argon workspace ~1GiB, excluded from 32MiB). One active chunk/writer per store. Checked arithmetic and bounded backpressure mandatory.

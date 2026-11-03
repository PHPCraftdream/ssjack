# Fixed native consumer: internal delivery development

## Status and trust

This is a CI-first internal delivery path, not production enrollment, a user-facing secret-get command or a model tool. `Master.deliverCurrent` is private. Its only initial callers are composed synthetic tests. No exported Master release operation or production keeper dispatch is added.

A supplied `appstoresink.Config` is a trusted-caller declaration, **not evidence of human identity, approval, enrollment or backend ownership**. Code hashes, filesystem owners, reference tuples and terminal access do not establish those properties. An authenticated enrollment/policy owner must exist before any production launcher can connect this configuration to the private delivery path. Declarative MCP remains deny-only. The existing full CLI/application surfaces retain their previous broad authority and are not relabeled as confidential delivery.

## Current-reference transaction

The private coordinator holds one application operation lease and the exclusive store transaction lock throughout authentication, pinning, streaming, acknowledgement and cleanup. It uses the concrete read-only mTLS anchor Client, requires the exact current snapshot/hash and local snapshot/hash/transaction pointer, then verifies the complete anonymous ciphertext spool. It selects the exact catalog object/version; it never substitutes a current version for a missing reference.

Only current references are supported here. A historical reference is refused, not compared to a convenient replacement snapshot. Independently trusted historical expectation capture and authorization remain separate work.

Before handoff, the coordinator rechecks the spool's identity and full encoded hash and the fixed consumer binding. It rereads the same private spool sequentially, authenticates all 1000 layers of every intersecting data chunk before releasing that chunk's selected object range, and clears each plaintext chunk after use. It rechecks the complete spool hash and binding after streaming. A later failure cannot retract a prefix already handed off: results retain possible-delivery and byte-count information and never fabricate completion.

## Native endpoint boundary

The initial endpoint is Linux amd64/arm64 static ELF, not a shell, interpreter, Node entry, arbitrary callback or caller-selected `io.Writer`. Other platforms and dynamic/interpreted images fail closed. This intentionally limits the development slice; it is not arbitrary-application support or the Nix/Clawwright adapter implementation.

A configured program descriptor is duplicated and retained. At the single-use handoff, the implementation bounds the image at 16 MiB, compares its complete SHA-256 and revision, rejects dynamic interpreter/program headers, copies it into a private memfd, removes write permission and requires write/growth/shrink/seal seals. It executes that exact image through an inherited descriptor, not by reopening a mutable program path. Kernel `/proc` observations verify the running image identity and UID/GID values. No alternate executable or shell fallback exists.

The process receives an empty environment and no secret arguments. Anonymous private pipes carry bounded input and binary acknowledgements. Neither stream is forwarded to model-visible output or a captured-log manager; stderr is discarded. The registered trusted program reports its own target/revision/purpose digests during readiness, independently of the caller's opaque binding digest. They must exactly match the configured binding before any secret byte. This is a statement from the checked trusted program, **not remote attestation or proof of arbitrary backend permissions**. The trusted adapter must enforce its actual backend/dependency/configuration policy.

This is not a sandbox. The process retains its operating-system principal and ambient filesystem/network rights. Native code can perform actions its principal permits; code provenance is essential. Compromised trusted code, hostile same-UID/root access and complete descendant containment are not solved here. Revocation cancels the owned process and interrupts parent pipe IO; it does not claim to recall consumed bytes or prove that arbitrary descendants stopped.

## Binding, lifetime and frames

A configured binding fixes the complete SecretRef, encoded snapshot hash, artifact hash, target/revision/purpose digests and expiry. There are no wildcard/latest selectors or request-selected destinations. Configuration validity is at most 24 hours; each finite delivery requires a deadline at most one hour away and is additionally bounded by expiry. Copies share one consumed/revoked state. The runtime captures a monotonic expiry cutoff at construction, in addition to checking the declared wall-clock expiry. A failed start consumes the grant rather than permitting an implicit retry. This consumption is process-local runtime state, not durable human-approval replay protection.

The binding digest is SHA-256 over ASCII `SSAPP-FIXED-CONSUMER-v1`, the four 16-byte reference IDs in store/object/version/snapshot order, the five 32-byte hashes in encoded/artifact/target/revision/purpose order and the big-endian 8-byte expiry Unix nanoseconds. This digest correlates a fixed runtime declaration; it is not a signature or authority token.

All frames are private pipe bytes, not a network service. The parent sends exactly 64 bytes: `SSINK001`[8], fresh random nonce[16], binding digest[32], big-endian object length[8]. Readiness is 160 bytes: `SSRDY001`[8], the same nonce/digest/length[56], then the consumer's target/revision/purpose digests[96]. Payload follows only after exact readiness and peer checks. Individual writes are at most 16384 bytes and cannot exceed the declared length.

After exact payload EOF, the consumer returns exactly 96 bytes: `SSACK001`[8], the same nonce/digest/length[56], SHA-256 of received payload[32], then stdout EOF and successful exit. The parent checks this privately and exposes only completion/possible-delivery/byte-count status, never the payload or payload digest. A receipt establishes transport receipt by this trusted consumer, **not application adoption, reload or deployment success**. Missing, extra, malformed or mismatched output fails without echoing its contents.

## Authored verification

Synthetic tests build a static fixture only during public CI. The fixture requires an empty environment, reports independent scope digests, checks each received byte against an independent generated pattern, and emits only the bounded acknowledgement. Tests compose the actual snapshot writer, real durable mTLS anchor, read-only Client, protected spool, exact multi-object selection and native process handoff. They also cover missing versions, historical/current mismatch, code/scope mismatch, one-use consumption, cancellation, revocation and consumer refusal. A second-pass corruption test requires delivery to stop before the affected chunk and report the earlier prefix as possible delivery.

No local tests, builds, native launches, credentials or production services are needed or authorized by this document. Public scoped CI supplies execution evidence. Full production KDF verification remains the separate explicit sprint gate. Real enrollment, restricted host/guest rights, external adapters, placeholder serialization and observed application adoption remain unfinished.

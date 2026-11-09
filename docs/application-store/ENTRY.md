# Application-store CLI and owner entry points

These installation/delivery commands are Linux-only; root-granted synthetic and
text-adapter runtimes additionally require Linux/amd64. Core SSH and the credential
menu have separate cross-platform support.

```text
ssjack appstore setup DIR
ssjack appstore put DIR
ssjack appstore inspect DIR
ssjack appstore unlock HARNESS [ARGS...]
```

## Existing installation, not automatic enrollment

`DIR` is an existing absolute private (`0700`) directory. `setup` records a locally
encrypted installation binding after the operator independently verifies and
reconfirms the store ID, HTTPS endpoint, CA, service signing key and preprovisioned
TLS writer certificate/key. Private DER material is entered through hidden prompts,
not a key file, argv, environment or model tooling. Store/writer role/genesis must
already exist. Setup does not provision a service role, enroll a backend, contact
the service or authenticate the identity of the person doing the ceremony.

The binding is separate from snapshots and bound to the directory device/inode.
Copying it to another directory identity invalidates it; renaming the same
directory alone need not. Trusted OS/runtime/same-UID boundaries still apply.

`put` authenticates the installation and authoritative empty state before prompting
for one hidden secret (at most 16 KiB), then rechecks before publication. It is
**first-entry only**, not general CRUD or merging. Success emits an exact reference,
sequence and revision. Uncertain output is not permission to replay the write.

`inspect DIR` is a non-root terminal operation: hidden installation unlock, trusted
anchor metadata only, no secret delivery.

## Fixed synthetic delivery

`unlock HARNESS [ARGS...]` requires a non-root terminal, canonical reference and
separate active finite root-installed delivery grant. Root independently manages
these through `declarative register-delivery` / `revoke-delivery`; a metadata grant
is not a release grant. Store identity/digests, reference, fixed driver/consumer,
recipient UID and expiry are bound before the hidden master unlock launches the
fixed synthetic consumer. Model tools expose no arbitrary sink or secret getter.

Optional `--text-mode hydrate|reverse --text-fd FD` on `appstore unlock` reads a
bounded selection from an explicitly inherited trusted descriptor. This is the
single-selection fixed-sink handoff, **not** the multi-reference text-adapter or
large-text protocol. EOF may block on an uncooperative writer. Plaintext stays in
the trusted pipe boundary, not argv/environment/tool requests or replies.

A delivery receipt is not application adoption or crash durability. Adoption can
be unknown; do not automatically retry a possibly dispatched operation. See
[delivery runtime](DELIVERY-RUNTIME.md).

## Owner administration and selected text

Use `ssjack --interactive` for the one-unlock owner console. **Link secret store**
connects an existing authenticated installation; it does not create one. Global
and server-local secrets have names and exact immutable references, with private
value CRUD through the [owner coordinator](OWNER-COORDINATOR.md). The current
owner editor supports at most 128 objects and 16 KiB per value.

The owner menu also exports selected credentials/settings/actual values and
imports encrypted or deliberate plaintext owner ZIPs. Inspection/preview stays
in RAM, import requires `IMPORT`, and collisions refuse without overwrite.
Partial import uses explicit recovery/abort; remaining plan values are lost on
exit, while per-secret queued intents remain encrypted. See [menu](OWNER-TUI.md)
and [archive format](OWNER-EXPORT-FORMAT.md).

For general selected-text deploy/reference-only backup, use the separately
registered [text-adapter](TEXT-ADAPTER.md). Forward/reverse and v1/v2 grants are
separate. [V2 streaming](TEXT-STREAM-HTTP.md) supports bounded larger text without
raising v1 limits. These are not raw unlock getters or universal secret discovery.

## Verification and cryptographic profile

Four independent sequential 1-GiB Argon2id derivations and 1000 AES-256-GCM data
layers remain unchanged. Production and cached-key paths do not replace those
layers with key wrapping or weaker encryption. The custom design is unaudited.

Ordinary scoped CLI CI uses a private source overlay at the existing KDF test seam;
AES still uses 1000 real layers and no weak runtime selector is added to the binary.
Full CI requires explicit production-profile PASS, including
`TestAppstoreFullProfileCLI` and the owner terminal/import/recovery composition.
[Full run 41796602948](https://github.com/PHPCraftdream/ssjack/actions/runs/41796602948)
passed on source `0576409`; that receipt does not authorize live user operations.
Tests/builds/KDF run in GitHub CI, never implicitly on a contributor's workstation.

For an explicitly authorized CI-only focused production run:

```sh
SSJACK_TEST_FULL_KDF=1 go test -mod=readonly -p 1 -run '^TestAppstoreFullProfileCLI$' -count=1 -timeout 1200s ./cmd/ssjack
```

[Capability map](../README.md) · [format/design baseline](FORMAT.md) ·
[crypto runtime](CRYPTO-RUNTIME.md) · [failure boundaries](FAILURES.md)

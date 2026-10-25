# Memory-only bootstrap and unlocked storage contexts

## Status and compatibility

The current source replaces the former environment/file capability pair with a single environment-only capability. This is an intentional security-model change, not the same two-channel protection implemented differently. It requires matching keeper and bridge binaries. Authentication frames have protocol version 2; old or missing versions fail closed. Database v1/v2 formats remain readable and are not implicitly upgraded by this change.

A running older keeper/bridge pair can continue until the session ends. After installing a new executable, start a new launcher session; an old keeper and newly started bridge cannot attach to each other. Old runtime directories are not read, reused, or automatically deleted.

## Transport and credential handoff

The channel is the existing framed Ktav protocol over pinned TLS 1.3 on literal IPv4 loopback, not an HTTP REST API. Each launch creates one random 256-bit token, a random session identifier, and an ephemeral TLS identity. Only the launched harness receives:

- `SSJACK_ENV_TOKEN`: the single-use capability;
- `SSJACK_SESSION`: the session identifier;
- `SSJACK_ENDPOINT`: the canonical loopback endpoint;
- `SSJACK_CERTIFICATE_SHA256`: the pinned TLS certificate digest.

No bootstrap file or `.ssh/runtime` directory is created. Legacy `SSJACK_BOOTSTRAP_FILE` and inherited bootstrap fields are scrubbed before setting child values. The parent shell is not modified. The bridge removes bootstrap fields from its own environment after reading them, but cannot remove inherited copies from the parent harness or other children.

The bridge validates inputs and the loopback endpoint, checks the TLS pin, and sends the versioned token authentication frame. The keeper atomically consumes the token and binds access to that one established connection. The listener closes after attachment. A lost acknowledgement, replay, disconnect, or expiry does not permit another attachment with the same token. Disconnect still cancels remote jobs.

The database password, private key, Argon2id outputs, and database master never become bootstrap fields or MCP results. Persistent MCP/plugin registration remains secret-free. The protocol removes application-authored plaintext bootstrap writes; it does not make process environment theft impossible.

## Single-channel threat model

The old guarantee that stealing only the environment capability is insufficient no longer applies. Anyone obtaining the child's full bootstrap environment before attachment can race the intended bridge. TLS pinning protects transport identity, not against an attacker who has stolen the endpoint, pin, session ID, and bearer token together. Processes sharing the same harness connection are not distinguished as individual models.

Loopback is not OS-user isolation. Same-user inspection, administrators, debuggers, dumps, environment snapshots, swap, hibernation, and OS-generated copies are not prevented by keeping application buffers in RAM. Disabling or encrypting those OS facilities is a separate host policy. Do not promise that RAM-only application behavior implies no physical storage copy anywhere.

## Cached storage encryption

`vault.Load` now retains an owned memory-only `keyfile.Unlocked` context after authenticating the complete container. Four independent sequential production Argon2id calls still use 1 GiB each; their outputs are combined through the existing HKDF. Raw intermediate outputs are cleared as before. Only the resulting master and public parameters are retained, not a plaintext password cache or a serialized password verifier.

Normal record/pin/policy/key updates use `SaveUnlocked`, avoiding another password derivation within the same unlocked CLI invocation. Every write still performs all 1000 nested AES-256-GCM data encryptions before the encrypted same-directory staging file is opened. Authenticated salts and master are reused within that invocation, but each seal generates a fresh random 96-bit nonce base. Per-purpose/per-layer key derivation, version-bound AAD, payload bounds, and reverse authentication remain unchanged. Fresh random nonces provide probabilistic uniqueness; they are not a guarantee of collision-free unbounded reuse.

`Vault.Close` clears the accessible owned master buffer and private payload buffers. Repeated close is safe, and closed contexts refuse encryption. No master is stored in the container, temporary file, environment, or bootstrap. Ordinary CLI secret prompts remain per invocation, not a persistent service-wide password cache.

Changing the database password is different from an ordinary update: it derives a fresh master with fresh salts, writes under the new secret, and replaces the retained context only after successful revision-checked publication. Failure/cancellation retains the previous context and working file. Subsequent cached writes use the new context, never the old password. Standalone key generation and explicit format upgrade retain their own fresh derivation boundaries.

The container composition remains custom and independently unaudited. Reusing a cached master does not increase password entropy, make 1000 layers imply 1000-fold security, or prevent the outer GCM tag from checking a candidate master. Clearing Go-owned byte slices does not guarantee clearing every runtime or cipher-schedule copy.

## Verification requirements

Regressions cover child-only environment handoff and stale-variable scrubbing, absence of runtime directories on success/failure, version/token/session rejection, pinned-loopback TLS, one concurrent winner, replay and disconnect, cached KDF call counts, fresh nonces, retained format/salts, all data layers, close-buffer clearing, wrong-password failure, and explicit password-change context replacement. Tests and builds run only in authorized GitHub CI; writing these checks is not evidence of a passed run.

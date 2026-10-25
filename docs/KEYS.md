# Protected SSH keys

ssjack can store SSH private keys in its own versioned Ktav container and derive a new Ed25519 key from a secret typed at the terminal. It remains its own SSH client: neither operation requires an external `ssh` or `ssh-keygen` process.

The container is a custom composition of established primitives, not an independently audited standard key format. Do not interpret its layer count as a quantified security guarantee.

## Generate a derived Ed25519 key

From the application working directory, using an executable built from the updated source:

```text
ssjack --generate-key .ssh/derived-key.ssjack.ktav
```

The command asks for the new secret twice, without echo. The secret is used both to derive the key bytes and to protect the resulting container. It writes:

- `.ssh/derived-key.ssjack.ktav`: encrypted private container;
- `.ssh/derived-key.ssjack.ktav.pub`: public key in OpenSSH `authorized_keys` format.

Both output paths must be new, and their parent directory must already exist. Existing files and symlinks are not overwritten. The private file is created with mode `0600`; on Windows, protect its directory with appropriate ACLs because Unix mode bits do not establish a private Windows ACL. If writing the public file fails after the private container is saved, the command reports the partial outcome and retains the private container. The pair is not a filesystem transaction. An I/O failure can leave an incomplete output; it is never silently replaced on retry.

The typed secret is not replaced by a randomly generated Ed25519 seed. Instead:

1. Four independently salted Argon2id results produce a master secret as described below.
2. A fixed, versioned domain message is encrypted through 1000 AES-256-GCM layers using the `keygen` key domain.
3. SHA-256 of the final ciphertext supplies the 32-byte Ed25519 seed.
4. The private key is marshaled in memory and protected with 1000 additional AES-256-GCM layers using the distinct `storage` key domain. Argon2id is not repeated for this step.

Fresh random public salts and a nonce base are generated for each container. **The secret alone is not a password-only recovery mechanism.** The same secret and the same public parameters reproduce the same Ed25519 key bytes; a new generation with fresh parameters produces a different key even for the same secret. Keep the container and its public parameters backed up. There is currently no separate recovery CLI.

A human-chosen phrase does not acquire 256 bits of entropy just because it produces a 256-bit seed. Anyone with the public key and the derivation parameters can test candidate phrases offline. Use a strong, preferably randomly selected passphrase, not a quotation, username, predictable suffix, or reused password. Input is used as exact bytes, without trimming or Unicode normalization.

Install only the `.pub` file on the intended server through a trusted connection. The command does not change `authorized_keys`, remote accounts, or host trust.

## Protect an existing encrypted SSH key

```text
ssjack --protect-key .ssh/existing-key --key-output .ssh/protected-key.ssjack.ktav
```

Without `--key-output`, the output defaults to the input path plus `.ssjack.ktav`. The command asks for the existing passphrase only when the source is encrypted, then asks for the new container secret twice. It accepts supported standard OpenSSH/PEM private keys (encrypted or plaintext), or an existing ssjack container. Plaintext input is an explicit import source, not an allowed stored credential: its unchanged source file remains unencrypted until separately retired.

The key identity is preserved. No decrypted key is written to disk. The input is not overwritten, removed, or re-encrypted in place, and SSH configuration is not changed automatically. Older copies and backups retain their original, potentially weaker protection. Strengthening one copy does not strengthen the others; any retirement or deletion of old copies is a separate decision.

For the normal encrypted-database workflow, import the new container with `ssjack vault add <name>` and select it with `ssjack ssh <name>` or `ssjack run <name> <harness> [arguments...]`.

For explicit legacy `--config` usage only, set the configured key path after generation or conversion succeeds:

```text
keys.storage: protected-key.ssjack.ktav
```

Paths are relative to the configuration file's directory. All configured keys must unlock with the one secret entered at launcher startup. Legacy encrypted SSH keys remain supported; they retain their original KDF and are not silently upgraded.

## Standard-format interoperability

```text
ssjack vault import storage existing-key.pem
ssjack vault export storage exported-key
ssjack vault public storage
```

`vault import` replaces only the private key of an existing named credential record. For a new record, `vault add` prompts for the connection settings and imports its key. Addresses, usernames, and server pins are not changed by key replacement. Plaintext sources, encrypted OpenSSH keys, supported PEM keys, and ssjack containers are accepted; the source file is never overwritten or deleted. Unsupported PEM encryption formats fail explicitly rather than being guessed.

`vault export` asks for the vault secret and a separate confirmed OpenSSH passphrase, then creates a new encrypted OpenSSH private-key file with mode `0600`. It does not allow empty-passphrase/plaintext exports or overwrite an existing file. The exported key has the same identity, but its protection is the standard OpenSSH scheme, not the ssjack Argon2id/1000-layer profile. Treat it as a separate copy with potentially weaker password-guessing resistance. Do not reuse the vault secret for this export: guessing the weaker export's passphrase would then also reveal the vault secret.

`vault public` outputs only the OpenSSH public key and can be redirected to a `.pub` file. Private bytes are never printed. Every command still requires interactive vault authorization. Importing a different key does not update the server's `authorized_keys`; install its public key through a trusted connection before relying on it.

## Container version 1

The file starts with `# ssjack encrypted key v1` and contains a Ktav document emitted by `github.com/ktav-lang/golang/pure` v0.8.1. No private key payload is stored as JSON or unencrypted text.

The fixed profile is:

- four **sequential** Argon2id v1.3 invocations;
- four distinct random 32-byte public salts;
- **1 GiB** (`1048576 KiB`) of Argon2id memory per invocation;
- one Argon2id pass, parallelism one, 32 output bytes per invocation;
- concatenation of the four outputs, then HKDF-SHA-256 to a 32-byte master secret;
- **1000 nested AES-256-GCM encryptions of the data**, not 1000 KDF replacements;
- a distinct HKDF-derived AES key for every purpose and layer;
- a random 12-byte nonce base, XORed with the layer index in its last four bytes to obtain distinct layer nonces;
- authenticated version, fixed KDF parameters, salts, nonce base, key purpose, and layer index.

The entire previous ciphertext, including its tag, is encrypted by the next layer. Decryption removes all 1000 layers in reverse order. No private key is parsed or used before all tags verify. Each layer adds 16 bytes: ciphertext growth is exactly **16000 bytes** before base64 encoding. Metadata is outside the ciphertext but authenticated through every layer's associated data.

Generation and storage use different HKDF domains, so their AES keys differ even though they share the master secret and public parameters. Version 1 requires the exact fixed cost profile and rejects unknown fields, unsupported profiles, duplicate salts, invalid encodings, and excessive lengths before allocating the Argon2id workspace. It has no user-controlled cheap KDF flag or lower-cost runtime mode. The plaintext limit is 64 KiB; the complete document limit is 256 KiB.

The four Argon2id calls are sequential, not four simultaneous 1 GiB allocations. The implementation requests garbage collection after each call to reclaim its workspace. Actual process memory includes Go/runtime overhead and is not guaranteed to stay below exactly 1 GiB. Allocation failure or OS memory pressure can terminate the process. Unlocking may take several seconds or longer **per configured key**. A 0.5-second Argon2id operation cannot be guaranteed across hardware; no wall-clock calibration is implicit in these commands.

Although a full unlock removes all 1000 layers, an attacker can check a candidate master secret using the **outermost GCM tag** without removing the other 999 layers. Consequently, 1000 data encryptions do **not** imply a 1000-fold increase in password-guessing cost or overall security. The four memory-hard operations and the secret's entropy remain the main password-guessing barriers. Public-key-based guessing against generated keys is another relevant attack path.

## Runtime boundaries

The launcher accepts secrets only from an interactive terminal, not flags containing the secret, environment variables, stdin pipes, or MCP requests. Plaintext payloads, seeds, and derived secrets are cleared from accessible byte buffers after use. Go's internal copies, expanded cipher schedules, SSH key objects, swap, dumps, and debuggers are not guaranteed to be erased or protected. Unlocked signers remain in keeper memory for the session.

The custom container is not an OpenSSH private-key file. External SSH clients cannot load it directly. ssjack reads it in memory and authenticates through `golang.org/x/crypto/ssh`; the private key is not passed to the bridge, harness, external client, or server.

## Verification

The source includes tests for all 1000 data layers, fixed profiles, tampering, wrong secrets, fresh salts/nonces, purpose separation, derived Ed25519 identity, legacy conversion, and exclusive output creation. Unit tests inject an unexported low-memory Argon2id implementation; production functions always use the fixed 1 GiB profile. These unit tests do not constitute a measurement of full-profile RAM or latency. A separate GitHub CI job runs `TestVaultFullProfile` with the real 1 GiB KDF to exercise vault creation, loading, modification, and reloading. The test-only environment gate does not alter the application's KDF or enable a cheaper production profile. No CI result is implied merely by defining the job.

Real credentials are never needed for the tests. Heavy calibration or conversion of a real key is not performed automatically.

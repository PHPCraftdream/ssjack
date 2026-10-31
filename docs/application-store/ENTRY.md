# Application-store CLI

Linux-only commands:

```text
ssjack appstore setup DIR
ssjack appstore put DIR
```

`DIR` must be an existing absolute, private (`0700`) directory. `setup` is a local trusted-install ceremony: the operator independently verifies the existing store ID, endpoint, root CA, service signing key, and preprovisioned TLS writer certificate/key using a source outside this model, then enters and reconfirms the values at hidden prompts. It records a locally encrypted installation binding; it does not provision a production service role or perform service enrollment. The store and writer role/genesis must already exist. The ceremony cannot prove the external source or the human's identity.

No private key is read from a file; secrets and configuration are not accepted through files, environment variables, or argv. Setup runs outside a model session; independent human verification is required. There is no MCP exposure. The encrypted binding is separate from encrypted snapshots. Its directory device/inode identity is checked on use: copying to another inode invalidates it; renaming the same directory does not by itself change that identity. Go-owned RAM is cleared on a best-effort basis, but host swap, runtime, or root compromise is outside the protection claim.

`put` authenticates installation and committed snapshot state before prompting for one secret (maximum 16 KiB). It is a first-entry workflow only: it refuses any store with an existing committed snapshot. It does not support multi-object updates or merging. Success reports the exact reference, sequence, and status. If output is uncertain, do not blindly replay. It does not hydrate, grant, or deliver credentials. Production crypto profile is unchanged: four independent sequential 1-GiB Argon2id operations and 1000 data-encryption layers.

The scoped shared-helper CLI tests use a private CI Go source overlay generated in a temporary directory. It changes only `argonDerive` via the existing private seam; it adds no production runtime KDF selector or exported weak API. AES processing remains the actual 1000 layers. Feature CI runs `python3 scripts/ci/appstore_scoped.py`. The explicit CLI full-profile test regex selects `TestAppstoreFullProfileCLI`, which uses real KDF; feature CI does not run that full gate. To run the CLI full-profile test explicitly:

```sh
SSJACK_TEST_FULL_KDF=1 go test -mod=readonly -p 1 -run '^TestAppstoreFullProfileCLI$' -count=1 -timeout 600s ./cmd/ssjack
```

Acceptance tests cover named writer-error classifications, cancellation before mutation, a lost commit acknowledgement with unavailable reconciliation, and successful read-first reconciliation without blind mutation replay. These are authored assertions, not execution evidence. The crypto package retains its seven-file layout. No tests or CI scripts were run locally; public scoped CI and the final explicit real-KDF gate remain pending.

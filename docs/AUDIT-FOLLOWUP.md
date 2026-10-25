# AI review follow-up

The separately invoked read-only Claude CLI review targeted commit `0b183d6`. It was an AI source review, not an independent professional cryptographic assessment. The local report is not part of the public source tree. No code or tests were executed by that reviewer.

## F1: selected-key authentication evidence

The pinned SSH dependency tries `none` authentication before configured methods. A server accepting it can establish a session without using the selected private key. The application now requires exactly one identifiable public-key identity and constructs fresh signing evidence for every connection. Successful SSH negotiation without a successful signing operation by that selected signer is rejected before opening an application session.

`Signer`, `AlgorithmSigner`, and `MultiAlgorithmSigner` capabilities, restrictions, and preference order are preserved. Public-key lookup and algorithm enumeration are not signing evidence, failed signing is not evidence, and evidence from a previous connection is not reused. This guard is applied to all keeper SSH connection paths, not only rotation checks.

The regression fixture explicitly demonstrates dependency-level none-auth/session success, then asserts that the guarded application check rejects it, including after a previous legitimate selected-key login using the same configuration. The positive public-key path and signer capability behavior have separate tests.

This establishes participation of the selected signer in the server-accepted authentication exchange; it does not prove honest enforcement by an already malicious pinned server. Remote account restrictions and host trust remain separate requirements.

## F2: export cancellation

The CLI passes its signal-aware context into private export. It checks cancellation before prompting, before encryption, and after OpenSSH encryption immediately before exclusive file creation. An already cancelled command does not prompt or start encryption. The unit encryption seam can cancel during the operation and asserts that no output is published. Encryption failures also leave no output. Success output follows only a successful publication.

The standard OpenSSH output remains encrypted and requires a passphrase different from the database secret. Source keys, the database, and existing destinations are not overwritten.

## F3: effective usage display

`show` now uses a dedicated summary renderer and prints the effective profile usage. Missing legacy usage is rendered as `both`; explicit `both`, `human`, and `agent` are covered. The renderer never prints private-key bytes.

## Evidence boundary

Test source is not proof of a passing run. Builds and execution belong exclusively in GitHub CI, and the source commit/run URL must be recorded when verification completes. Real credentials, server authorization files, installed executables, and release tags are not changed by this remediation work. The four-Argon2id and 1000-data-encryption storage construction is unchanged, including its documented outer-tag password-checking limitation.

# Security policy

## Project status

ssjack is development-stage, security-sensitive software. Its custom encrypted container is **not independently cryptographically audited**. Test coverage, a green CI run, and an AI source review are not a substitute for that assessment. No stable-version support window or guaranteed response/fix deadline is promised.

Read [AUDIT.md](docs/AUDIT.md) for the construction and known limits, [KEYS.md](docs/KEYS.md) for derivation/storage, and [BOOTSTRAP.md](docs/BOOTSTRAP.md) for the current single-channel memory-only bootstrap and key lifetimes.

## Report a vulnerability privately

Use GitHub's **Report a vulnerability** form:

https://github.com/PHPCraftdream/ssjack/security/advisories/new

Do not disclose an unpatched vulnerability in a public issue or pull request. If private reporting is temporarily unavailable, open only a minimal issue asking for a private contact, without vulnerability details or sensitive material.

A useful report includes the source commit/build version, affected platforms, the relevant trust boundary, a minimal reproduction with synthetic data, observed impact, and any proposed mitigation. Test only systems and credentials you own or are authorized to assess. Do not access another person's data, disrupt services, or publish working secrets to demonstrate a problem.

Never send private SSH keys, vault passphrases, real encrypted vaults, bootstrap tokens, environment dumps, or unredacted user/host details. Coordinate a safe reproduction instead. Report content may remain sensitive even when a file is encrypted.

## Important limits

- The four Argon2id calls and 1000 data encryptions do not add entropy to a weak password or establish 1000-fold password-guessing resistance. The outer GCM tag checks candidate masters.
- The single-use bootstrap environment is a bearer capability. Theft before attachment can race the intended bridge. This is not strong isolation from a targeted same-user process, administrator, debugger, or compromised harness.
- RAM-only application handling does not prevent OS swap, dumps, hibernation, environment capture, or internal runtime copies.
- Usage labels are accident guards, not server-side authorization. An account with unrestricted sudo grants root-equivalent access.
- Server host keys must be verified independently. Do not bypass a mismatch, enable automatic trust, or weaken existing authorized-key options to make a test pass.
- Cooperative locks, file revision checks, and backups do not provide an atomic whole-system rollback or protection against another root process.
- SHA-256 from a publisher's release checks integrity relative to that publisher, not an independently signed trust chain. Verify source/commit and artifact provenance.

Security fixes may require a new keeper/harness session. No release, key rotation, password change, or retirement of an older copy happens merely because source was updated.

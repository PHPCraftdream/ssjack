# Contributing to ssjack

Thank you for helping improve ssjack. Keep changes focused, understandable, and supported by evidence. Read the [security boundaries](docs/BOOTSTRAP.md), [cryptographic review inventory](docs/AUDIT.md), and [Code of Conduct](CODE_OF_CONDUCT.md) first.

## Licensing

Project-owned material is offered under **MIT OR Apache-2.0**, at the recipient's option. Unless agreed otherwise before submission, contributions intentionally submitted for inclusion must be available under those same dual-license terms. Do not submit material you are not entitled to contribute. Preserve third-party copyright and license notices. See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Before opening an issue

- Search existing issues and read `ssjack help COMMAND`.
- Include `ssjack --version`, platform/architecture, the relevant command shape, expected behavior, and a minimal reproduction using disposable credentials.
- Do not post real vaults (even encrypted), private keys, passphrases, bootstrap tokens, environment dumps, or unredacted private addresses/usernames.
- Report vulnerabilities privately through [SECURITY.md](SECURITY.md), not a public bug report.

## Scope and implementation

- Keep source, comments, runtime strings, documentation, and commit messages in English.
- Match surrounding Go style and keep comments concise. Use `gofmt` and `git diff --check` for local formatting checks.
- State observable acceptance criteria and non-goals. Reproduce a defect where practical, then fix the layer that owns it.
- Preserve behavior in a refactor. Do not mix unrelated renaming, feature changes, dependency updates, or generated artifacts into a fix.
- No dependency/toolchain version changes without explicit review. The canonical module path is `github.com/PHPCraftdream/ssjack`.
- Preserve the four independent 1 GiB Argon2id operations and all 1000 full-data encryption layers. Do not substitute KDF iterations or a single encryption under the guise of cleanup.
- Changes to stored formats, key lifetimes, SSH authentication, bootstrap channels, or recovery need explicit compatibility, cancellation, rollback, and threat-model analysis.
- Never introduce plaintext private-key files, persisted bootstrap capabilities, unverified host-key acceptance, or silent deletion of recovery material.

## Verification

The project uses GitHub CI for build/test execution; do not assume an unrun test has passed. No real host, user key, vault, or global installation is a test fixture. Avoid local builds, heavy KDF calibration, or production-host tests unless separately authorized.

CI covers native Linux/macOS/Windows behavior, the race detector, installer fixtures, POSIX key-install commands, and a separate real production-KDF integration job. Pure fixture seams must stay unexported and must not create a cheaper production profile. New tests should identify the mechanism, not hide a failure with sleeps or retries. Fix failures rather than merely rerunning until green.

Keep release/tag creation and live host changes separate from a source pull request. Manual release workflows do not constitute publication approval.

## Pull requests

Explain what changes, why, and how it was verified. Link the issue where applicable, identify compatibility/security impact, and say explicitly which checks were not run. Do not include local machine paths, binaries, runtime directories, downloaded artifacts, or credentials. Private audit material and application state do not belong in this source repository.

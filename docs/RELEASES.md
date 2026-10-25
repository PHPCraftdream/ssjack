# Release assets and installation contract

The intended publisher is `PHPCraftdream/ssjack`. This document defines the contract for future GitHub Releases. It does not assert that the repository, a version tag, or downloadable binary releases already exist.

## Asset names

Each release contains these raw executables and one checksum manifest:

```text
ssjack_linux_amd64
ssjack_linux_arm64
ssjack_darwin_amd64
ssjack_darwin_arm64
ssjack_windows_amd64.exe
ssjack_windows_arm64.exe
SHA256SUMS
```

There are no archives to extract. The checksum manifest uses standard SHA-256 lines: 64 hexadecimal digits, whitespace, and the exact asset basename. Installers must find exactly one matching entry, verify it before executing any downloaded binary, and refuse missing, ambiguous, or mismatched checksums. A checksum downloaded from the same release verifies integrity relative to that publisher; it is not an independent signature or a defense against a compromised publisher account.

Version tags use `vMAJOR.MINOR.PATCH`, optionally followed by a hyphenated prerelease identifier. No installer creates tags or releases. Explicit versions resolve to `https://github.com/PHPCraftdream/ssjack/releases/download/<tag>/<asset>`. Without an explicit version, installers resolve GitHub's latest stable release first and use its concrete tag for both binary and manifest downloads.

Only HTTPS is accepted. Downloaded files go into a fresh temporary staging directory. Scripts are never launched from that directory, and no downloaded script is interpreted. CPU/OS detection rejects unsupported platforms instead of guessing or installing another architecture.

## Running the installers

Save and review the installer source before running it. Do not pipe a downloaded script directly into an interpreter.

Linux/macOS, with the default system-wide destination (requires existing write permission):

```sh
sh ./install.sh
```

Or install for the current user and add the directory to PATH yourself:

```sh
sh ./install.sh --install-dir "$HOME/.local/bin"
```

Windows, honoring the existing PowerShell execution policy:

```powershell
.\install.ps1
```

Select an explicit existing release with `--version <tag>` on Unix or `-Version <tag>` on Windows. `-InstallDir <directory>` selects the Windows destination; `-NoPathUpdate` suppresses persistent user PATH changes. Missing releases fail without replacing an installed executable. These examples do not imply that a release has been published yet.

## Release workflow

`.github/workflows/release.yml` runs only through an explicit `workflow_dispatch` action. It accepts an **existing** version tag and a `publish` boolean that defaults to `false`.

1. Validate the tag and check out the existing ref.
2. Run the reusable CI workflow against that ref: formatting, native CLI build/help, platform tests, and Linux race detection.
3. Cross-build all six executables in GitHub runners with `CGO_ENABLED=0`.
4. Verify the exact asset set and generate `SHA256SUMS`.
5. Retain the build as GitHub Actions artifacts for seven days.
6. Only when explicitly selected, publish a new GitHub Release using `--verify-tag`. Existing releases are not overwritten. Hyphenated versions are marked prerelease.

Writing the workflow does not authorize the assistant to execute publication. Tags, release creation, source commits/pushes, and a global install still require the applicable user authorization and tool permissions. Never bypass a rejected public upload with another API or a private-then-public conversion.

## Installer behavior

`install.sh` handles Linux and macOS. Its default destination is `/usr/local/bin`; users must provide the appropriate write permission themselves. A custom absolute installation directory can be selected without modifying shell profiles. A custom directory may need to be added to PATH manually.

`install.ps1` handles Windows. Its default destination is the current user's local application programs directory under `ssjack/bin`. It adds that directory to the user's PATH unless disabled explicitly. It does not change the machine-wide PATH, request elevation, bypass PowerShell execution policy, or stop processes. A different destination can be selected if the user has permission to write there.

Both installers validate SHA-256, recognize the candidate's `--help`, and install the executable under the normal `ssjack` name. Replacing an existing executable first renames it to a uniquely named backup and attempts rollback if installation verification fails. Only after successful verification may unused installer-owned previous copies be removed; an inactive old version is not guaranteed to remain available for later rollback. See [INSTALL.md](INSTALL.md) for verified-local candidates and running-image cleanup. They never kill the old process; an already running keeper keeps using its original code until restarted. New installations and updates do not create, read, migrate, or delete SSH keys, vaults, target configuration, or runtime sessions.

Installer smoke and failure-path tests belong in GitHub CI with controlled fixture responses, not live downloads or a global local-machine install. Full-profile Argon2id calibration is not an installer test.

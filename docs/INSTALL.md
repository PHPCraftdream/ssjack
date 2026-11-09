# Verified installation and live-process updates

The root `build.sh` (Linux/macOS) and `build.ps1` (Windows) build this source checkout and install the result. They delegate verified publication to the existing `install.sh` / `install.ps1`; there is one replacement/rollback implementation. The installers can also consume published releases or reviewed local artifacts directly. No script stops processes, elevates itself, changes a database or creates a release.

## Build this checkout and install globally

Requirements: a complete Git checkout, Git on PATH, the local Go toolchain required by `go.mod`, and permission to write the chosen installation directory. Linux/macOS also need `sha256sum` or `shasum`; Windows uses PowerShell. Supported native OS/CPU targets are Windows/Linux/macOS on amd64/arm64. The scripts deliberately ignore cross-compilation environment settings and use pure Go (`CGO_ENABLED=0`). They do not install or upgrade Go; module dependencies may be downloaded using Go's normal checksum verification.

Windows, from a reviewed checkout:

```powershell
.\build.ps1
```

The default is `%LOCALAPPDATA%\Programs\ssjack\bin`, added to the **current user's** persistent PATH and current session. This makes `ssjack` available from other application directories, without Administrator rights. For a different directory:

```powershell
.\build.ps1 -InstallDir 'C:\Tools\ssjack\bin'
.\build.ps1 -Help
```

`-NoPathUpdate` suppresses PATH changes (used by CI). An all-users protected destination requires an already authorized elevated terminal and separately provisioned machine PATH; the script never self-elevates or changes machine PATH.

Linux/macOS:

```sh
sh ./build.sh
sh ./build.sh --help
```

Default destination: `/usr/local/bin`, normally already on PATH. The caller needs write permission there; the script will not silently invoke sudo. Use an already authorized administrative context for a system-wide install, or choose a writable per-user bin directory:

```sh
sh ./build.sh --install-dir "$HOME/.local/bin"
```

Add that directory to PATH if necessary; the Unix installer prints guidance rather than rewriting shell startup files. The scripts locate the checkout from their own path, so invocation does not depend on your application working directory. Installation never selects or migrates that application's credential database.

Both scripts build `./cmd/ssjack` with `-mod=readonly`, trim build paths, embed the checkout commit (with `-dirty` for modified sources), compute SHA-256 and pass the local candidate plus digest to the verified installer. They do not bump the project version or fetch a release; development identity can still say `dev`. A self-computed checksum checks transfer/publication consistency, not independent publisher trust: review the source and dependencies first.

Only temporary compiled candidates are created; the scripts remove their own build staging on exit. A failed build never starts installation. Installer failure retains its normal rollback/failed-candidate evidence. Running processes keep their existing code; restart explicitly after updating. `build.sh --help` / `build.ps1 -Help` build and install nothing.

CI invokes these real entry points on Linux/macOS and both Windows PowerShell and PowerShell Core, always with isolated temporary installation directories and no PATH update. Failure-path tests use a failing synthetic Go command to assert the previous installation is untouched. No real global installation is a CI fixture.

## Local CI artifact

After independently checking the GitHub artifact digest and intended source commit, supply the verified executable's SHA-256:

```sh
sh ./install.sh --candidate /absolute/path/to/ssjack --sha256 VERIFIED_SHA256 --install-dir /usr/local/bin
```

```powershell
.\install.ps1 -CandidatePath C:\verified-artifact\ssjack.exe -SHA256 VERIFIED_SHA256
```

Local mode requires a 64-hex checksum and cannot be combined with a release version. It makes no network requests. The checksum must be anchored in a trusted artifact verification step; merely hashing an arbitrary untrusted download does not establish publisher identity. Save/review installer code separately from downloaded payloads, and do not run an interpreter from inside an untrusted extraction directory.

Release mode retains the existing HTTPS-only binary/manifest download and strict asset/checksum rules described in [RELEASES.md](RELEASES.md). Supported platforms remain Windows, Linux and macOS on amd64/arm64.

## Publication and recovery

1. Acquire the installation lock.
2. Copy/download to a new staging directory on the destination filesystem.
3. Verify SHA-256 before any candidate execution, then probe help.
4. Rename the previous executable; never overwrite a running image in place.
5. Rename the verified candidate into the normal executable path.
6. Verify the installed hash and help, then commit the update.
7. Only after success, attempt cleanup of unused previous files.

Windows keeps running processes attached to their original image. Unix rename changes directory entries while an existing process retains its original inode. New invocations use the new executable. This is replacement, not hot-patching: a running keeper/bridge continues its old protocol and behavior until restarted. Matching-version restarts are required after incompatible bootstrap changes.

A failure before successful verification attempts restoration of the previous path and retains failed candidates for diagnosis. This does not guarantee a spare inactive rollback executable after success: successful cleanup can remove it. Keep an independently verified artifact if later rollback must remain possible. Filesystem/power-loss and uncooperative concurrent-actor limits still apply.

## Removing unused renamed copies

Only strict installer-generated `ssjack.previous-*` names are eligible. Symlinks, foreign backup-like names, the current executable, and failed candidates are not removed.

- **Windows:** exclusive file access plus ordinary kernel-checked deletion retains running/mapped, locked or inaccessible images. No process-name guessing or termination is used.
- **Linux/macOS:** cleanup requires root-level process visibility and `lsof`. It checks actual file use, not a process name. Busy files, nonempty diagnostic output, inspection errors, missing `lsof`, or unprivileged inspection retain the old copy rather than guess. Incomplete process visibility can therefore leave extra backups.

Cleanup also runs on a verified no-op install, allowing a later invocation to remove a copy whose process has exited. There is no background watcher, polling loop, scheduled task, or automatic privilege escalation.

CI covers local checksum rejection/no network, inactive and inaccessible/locked copies, foreign names, Unix busy/unknown/unprivileged inspection, rollback, and a real running Windows fixture that survives rename and is removed only after exit. Unix inspector states are deterministic fixture responses; no production process or installation is a test fixture. Writing tests is not evidence that CI has passed.

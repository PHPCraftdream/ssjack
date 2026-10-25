# Verified installation and live-process updates

The official `install.sh` and `install.ps1` handle both release downloads and reviewed local candidates. Use them directly for global or explicitly selected development destinations; there is no separate local-build update wrapper or second replacement algorithm. No installer stops or restarts existing processes, elevates itself, changes vault contents, or creates a release.

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

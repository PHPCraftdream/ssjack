# File and directory transfer

Status: implemented in progress. The startup flags, the keeper job manager (internal/transfer), the single-file engine and the MCP tools below exist; directory transfers are still being completed in the engine, and all building and testing happens in CI.

## Purpose

An agent running under ssjack holds no SSH keys. Today it can move bytes only through `remote_exec`/`remote_read`, which are text-oriented, bounded, output-guarded and model-facing: file contents would pass through the model context, binary data is not preserved reliably, and secret-looking content is masked or truncated. This feature copies files and directories between an owner-approved local directory and an approved SSH target through the keeper. The model sees only a bounded status record, never content.

Copy only. The source is never modified or deleted. There is no move, sync, delta or resume.

## Authority model

`remote_exec` already grants arbitrary writes as the SSH principal, so the remote side gains no new authority. The new authority is **local filesystem access**. It is bounded by owner-registered transfer roots:

- The owner registers roots at keeper startup with repeatable `--transfer-root [NAME=]DIR`, before the vault prompt, like `--clawwright-directory`. With no root the transfer tools refuse every call (fail closed) and the refusal names `--transfer-root` so the model can tell the owner what is missing.
- A root must be an absolute existing directory with no symlink or reparse point in its resolved path, must not be a filesystem root, and must not contain the vault file or any ancestor of it. Violations fail before unlocking.
- Callers pass `root` (omitted when exactly one root exists) and a root-relative `local` path. Absolute paths, `..`, drive letters, UNC paths and alternate data streams are refused. Results never contain an absolute local path.
- Roots should be dedicated directories. Because a download can create files that other local tooling executes, download destinations and extracted entries are additionally refused when any component is `.git`, `.hg`, `.svn`, `.ssh`, `.claude`, `.vscode`, `.husky` or `.github`. This is defense in depth, not a sandbox.
- Remote paths are absolute POSIX paths with no NUL or control character. Authority is the profile's SSH principal; this is not a remote jail.

## Tools

All calls require a `target` approved by `remote_targets`.

- `remote_upload { target, root?, local, remote, overwrite?, confirm? }`
- `remote_download { target, root?, remote, local, overwrite?, confirm? }`
- `transfer_status { job_id }` and `transfer_cancel { job_id }`

The keeper handles the operations `transfer_upload`, `transfer_download`, `transfer_status` and `transfer_cancel`; the MCP bridge exposes them as `remote_upload`, `remote_download`, `transfer_status` and `transfer_cancel` with the argument sets listed above.

The kind (file or directory) is taken from the source, never from the caller. A start call returns `job_id` at once. At most two transfers run concurrently, and no two target one destination. `overwrite=true` requires `confirm=true`; the flag records caller acknowledgment only, and harness permissions still apply.

`transfer_status` returns: `state` (`running`, `done`, `failed`, `cancelled`), `phase`, `kind`, `direction`, `files`, `dirs`, `bytes`, `sha256` (file) or `manifest_sha256` (directory), `error_class` and a fixed message. Error classes: `refused_path`, `exists`, `limit`, `unsupported_remote`, `integrity`, `remote_failed`, `cancelled`, `internal`. Remote stderr is never returned; the model gets the error class and a fixed message only. `refused_path` is deliberately coarse: it covers a missing local parent directory, a path outside the root and a symlink alike, because a finer reason would disclose the structure of the owner's file system to the model. Finished records are retained in a bounded set.

### Job and status schema

A start call returns `{"job_id": "..."}` immediately. `transfer_cancel` returns `{"cancelled": true|false}`; `false` means the job had already finished.

`transfer_status` returns exactly: `job_id`, `state` (`running`, `done`, `failed`, `cancelled`), `direction` (`upload`, `download`), `phase` (`preflight`, `transfer`, `verify`, `publish`, `cleanup`), `kind` (`file`, `directory`), `files`, `dirs`, `bytes`, `sha256` (file transfers), `manifest_sha256` (directory transfers), `error_class` and `message` (fixed, content-free). Optional fields are omitted while absent.

Manager bounds: at most two concurrent jobs; a job is refused while another job targets the same destination (root and root-relative path for downloads, target and remote path for uploads); at most 64 records are retained, evicting the oldest finished first; unknown job ids refuse with a fixed message.

## Transport

The existing `remote.StreamRunner` already provides a byte-exact exec with `io.Reader` stdin and `io.Writer` stdout/stderr, host-key pinning, selected-signer checks and context cancellation. It bypasses the captured-log buffers and the output guard because bytes go to disk, not to the model. No new SSH primitive is needed and no dependency is added. SFTP is not used, so it works where the subsystem is disabled.

Each phase is a separate fixed command template over a fresh authenticated connection. Remote paths are single-quoted with `'\''` escaping and never concatenated otherwise. The model supplies no command text. Remote stderr is read into a bounded buffer (4 KiB) and discarded after classification.

Remote requirements, probed before any mutation: POSIX `sh`, `cat`, `sha256sum`, `find`, `xargs -0`, `tar`, `rm`, and `mv -T` (GNU coreutils or busybox). A missing tool yields `unsupported_remote`. Remote targets other than POSIX are non-goals.

## Atomic publication

Everything is written to a staging path in the destination's parent (`.ssjack-transfer-<random>`, mode 0700, created with a no-clobber primitive) and published by rename only after verification. A failure removes only the staging path this job created (name pattern and creation checked before removal) and publishes nothing.

- File, no overwrite: hard-link staging to the destination (atomic, fails if it exists), then unlink staging. If linking is unsupported, fall back to existence check plus `mv -T`, documented as racy.
- File, overwrite: `mv -T -f` onto a destination that is a regular file. A destination that is a symlink or directory is refused.
- Directory, no overwrite: check absence, then `mv -T`.
- Directory, overwrite: rename the old directory aside, `mv -T` the new one in, remove the old one. A short window exists between the two renames in which the destination is absent; if the second rename fails the old directory is restored. The window is documented, not hidden.
- Local publication uses the same sequence with OS rename primitives. On Windows replacing a directory follows the same rename-aside order.

A missing destination parent is refused in v1; parents are never created implicitly.

## Files

Upload: stream the local file through a counting hasher into `cat > staging` (remote umask 077, final mode `0666` or `0777` if the source had an execute bit, minus remote umask; no ownership or special bits). Then run `sha256sum` on the staging file and compare with the local hash. Download: refuse non-regular or symlink sources, run `sha256sum` and size on the remote file, stream `cat` into a local staging file while hashing and counting, compare with the pre-hash, fsync, publish. A source that changes mid-transfer yields `integrity`.

## Directories

Entries are regular files and directories only. Symlinks, hard links, devices, FIFOs, sockets and names containing control characters are refused in v1; refusal happens in preflight (before bytes move) and is re-checked while streaming. Modes are normalized as for files; ownership, timestamps and xattrs are not preserved.

Upload: walk the local tree under the root, build a manifest (relative path, size, SHA-256, sorted, bounded), stream `tar` produced by Go `archive/tar` into `tar -x --no-same-owner --no-same-permissions` in the staging directory, stream the manifest to a second command that runs `sha256sum -c`, and require that the remote file and directory counts equal the manifest and that no extra entry or non-regular type exists. Then publish.

Download: remote preflight rejects non-regular entries and over-limit trees, then returns the remote manifest (`find -print0 | xargs -0 sha256sum`). Stream `tar -c` and extract locally into staging with Go `archive/tar`, hashing while extracting, and compare with the manifest and counts. Then publish.

Safe extraction (both directions, same rules): reject absolute paths, `..`, duplicate names, entries whose type is not regular or directory, and any entry that would be written through a pre-existing link. Open with no-follow semantics. Reject names invalid on the local OS: Windows device names (`CON`, `NUL`, `COM1`...), trailing dot or space, `:`, and case-insensitive collisions on case-insensitive filesystems. Enforce byte, entry-count, path-length and depth limits while streaming; a limit hit cancels the remote command.

## Limits

Defaults: 2 GiB total bytes, 100000 entries, path length 1024, depth 64, stderr 4 KiB. Both flags are validated at keeper startup, before the vault is unlocked; the defaults come from the engine's DefaultLimits. The owner may lower or raise them at keeper startup (`--transfer-max-bytes`, `--transfer-max-entries`). Limits are checked in preflight and again on the actual stream. No resume: any failure, cancel or lost connection publishes nothing.

## Cancellation and lifetime

`transfer_cancel` cancels the job context, which closes the SSH session and aborts local I/O. Closing the connection does not prove detached remote processes stopped; the remote command is a plain `cat`/`tar` that ends on stdin or stdout closure, and staging cleanup is best-effort and reported. Closing the keeper session cancels all transfers. Records and staging state are RAM-only and not persisted.

## Threat model

- Prompt-injected agent reads local secrets: bounded by owner roots, vault exclusion and dedicated-root guidance; content still reaches the remote host, which `remote_exec` could already do for text the agent can read.
- Agent writes a file that local tooling executes: control-directory denylist, no overwrite without `overwrite`+`confirm`, dedicated roots.
- Hostile remote tree (`../`, symlink tricks, special files, huge archive, zip-bomb-like expansion): preflight plus streaming-time validation, no link creation, limits.
- Partial or corrupt data: staging, SHA-256 verification, rename-only publication.
- Remote path injection: quoting only, control characters refused, no model-supplied command text.
- Secret exposure in results: content, remote stderr and absolute local paths are never returned.

## Acceptance

1. File and directory round trip, both directions, byte-exact including binary data and names with spaces and non-ASCII characters; the tool output never contains file content.
2. Refusals before any mutation: path traversal, absolute and drive paths, symlink or reparse point in source or destination, forbidden control directory, destination exists without `overwrite`+`confirm`, missing root, root containing the vault, over-limit size or count, missing remote tool.
3. Interrupted stream, cancel, hash mismatch and limit hit publish nothing and remove only job-owned staging.
4. Overwrite replaces the destination only when requested; a failed overwrite leaves the old destination intact.
5. Behaviour is identical on Linux, macOS and Windows for the local side, verified in GitHub CI against an in-process SSH fixture (no real host, no real credentials).

## Non-goals

Move/delete/sync/delta/resume; symlink or hard-link replication; ownership, timestamp and xattr preservation; remote-to-remote copy; Windows remote targets; SFTP or rsync; a declarative or narrower authorization surface; scheduling; any change to key custody or to the output guard.

## Implementation order

1. This document.
2. Remote protocol layer: command templates, capability probe, manifest format, bounded stderr, over the existing `StreamRunner` (no change to `internal/remote`) — parallel with 3.
3. Local safety layer: roots, path resolution, staging, publication, safe extraction, per-OS code — parallel with 2.
4. Single-file engine on 2 and 3.
5. Directory engine on 4.
6. MCP tools, keeper wiring and documentation on 4.
7. Acceptance tests and CI gate on 5 and 6.
8. Exact-SHA review, CI and integration.

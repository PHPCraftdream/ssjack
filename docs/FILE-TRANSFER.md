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

Remote requirements, probed before transfer staging or payload mutation: POSIX `sh` and `cat`, `find`, `xargs`, `tar`, `rm`, `mv`, `ln`, `wc`, `mkdir` and `chmod` (`id` is not required). The probe itself creates a scratch directory under `${TMPDIR:-/tmp}` and removes it on normal/error exits and trapped signals; cleanup is not guaranteed if the remote process receives `SIGKILL`. Functional SHA-256 probes hash the bytes `abc` (known digest `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`) and select a working `sha256sum`, `shasum -a 256`, or `sha256 -q` (FreeBSD, formatted to the same `<digest><two spaces><path>` result). The probe selects a functional publication primitive: `t` is GNU/BusyBox `mv -T` with the existing publication templates byte-for-byte unchanged; `p` uses Perl's raw `rename` and `link` syscalls. Its Perl commands are fixed `-e` programs, with source and destination passed as separately shell-quoted argv after `--` (for example, `perl -e 'exit(rename($ARGV[0], $ARGV[1]) ? 0 : 1)' -- "$src" "$dst"` and `perl -e 'exit(link($ARGV[0], $ARGV[1]) ? 0 : 1)' -- "$src" "$dst"`); paths are never interpolated into Perl source. Perl is resolved through `PATH`. The long extraction flags `tar --no-same-owner --no-same-permissions` are required and functionally probed; modern bsdtar accepts them, so they are not GNU-only. If no hash, publication primitive or required tar capability passes, the transfer is refused as `unsupported_remote` (remote code 20), before staging or payload mutation. The full macOS acceptance PATH is `/usr/bin:/bin:/usr/sbin:/sbin`, selecting `/usr/bin/perl` and its built-in raw syscalls when `mv -T` is unavailable. Support is determined by probe results, not OS name; other BSD systems are supported only if they pass, and FreeBSD success is not CI-tested. The probe reports one machine-readable line.

## Atomic publication

Everything is written to a staging path in the destination's parent (`.ssjack-transfer-<random>`, mode 0700, created with a no-clobber primitive) and published by rename only after verification. A failure removes only the staging path this job created (name pattern and creation checked before removal) and publishes nothing.

- File, no overwrite: hard-link staging to the destination (atomic, fails if it exists), then unlink staging. Primitive `p` uses Perl `link()` with the paths as argv, so a destination directory or existing symlink fails without nesting; this fixes the plain-`ln` directory-nesting behavior only for the new `p` variant. Primitive `t` keeps all existing GNU/BusyBox publication templates byte-for-byte unchanged, including their `ln` behavior. If hard-link publication is unavailable, the fallback is an existence check plus the selected no-nesting rename (`mv -T` or Perl `rename()`), with the same accepted check/publish race.
- File, overwrite: `mv -T -f` or Perl `rename()` onto a destination that passed the regular-file type check. A pre-existing symlink or directory is refused. Rename replaces a destination symlink itself and does not follow it; the accepted check/publish race means a symlink introduced after the type check may be replaced.
- Directory, no overwrite: check absence, then publish with the selected primitive. Directory overwrite keeps the existing sequence: rename the old directory aside, publish the new one, remove the old one. A short window exists between the two renames in which the destination is absent; if the second rename fails the old directory is restored. The window is documented, not hidden.
- The functional publication probe requires directory-to-absent success, directory-to-empty-directory replacement (as with GNU `mv`), and failure without nesting for a nonempty directory or file targeting an existing directory. It also checks that rename replaces a destination symlink itself without following it. For `p`, `link()` onto a directory or existing symlink fails without nesting. Publication uses staging in the destination's parent, on the same filesystem; a raw `EXDEV` failure publishes nothing and never falls back to copying. The existing check/publish structure and status codes 21, 22, 24 and 25 are preserved. Existing GNU/BusyBox check-to-publish races are unchanged; the accepted type-check race is not a guarantee that a racing symlink is never replaced.
- No plain-`mv` fallback exists. The selected primitive is functionally probed before transfer staging or publication. `mv -T` prevents directory nesting; Perl `rename()` supplies the corresponding raw rename syscall on the `p` path. These checks do not protect against concurrent hostile mutation of the destination parent.
- Local publication uses the same sequence with OS rename primitives. On Windows replacing a directory follows the same rename-aside order.

A missing destination parent is refused in v1; parents are never created implicitly.

## Files

Upload: stream the local file through a counting hasher into `cat > staging` (remote umask 077, final mode `0666` or `0777` if the source had an execute bit, minus remote umask; no ownership or special bits). Then run the selected, probed SHA-256 command on the staging file and compare with the local hash. Download: refuse non-regular or symlink sources, run the selected SHA-256 command and size check on the remote file, stream `cat` into a local staging file while hashing and counting, compare with the pre-hash, fsync, publish. A source that changes mid-transfer yields `integrity`.

## Directories

Entries are regular files and directories only. Symlinks, hard links, devices, FIFOs, sockets and names containing control characters are refused in v1; refusal happens in preflight (before bytes move) and is re-checked while streaming. Modes are normalized as for files, and the published root directory gets the mode its subdirectories get (`0755`, minus the remote umask on a remote target) instead of the private staging mode. File and directory modification times are restored best effort in whole seconds after verification; times before 1980 or after 2100 are ignored, and failure to set a time never fails the transfer. The GNU full acceptance suite is configured to check directory timestamps. BusyBox tar may restore directory timestamps differently; this behavior is partial/unverified and is not covered by its subset. A single-file transfer carries no time (the copy is dated when it is written). Ownership and xattrs are not preserved.

Upload: walk the local tree under the root, build a manifest (relative path, size, SHA-256, sorted, bounded), stream `tar` produced by Go `archive/tar` into the required extraction form: `tar -x --no-same-owner --no-same-permissions -f -`. The selected remote hash command is used to list each staged file; the verifier compares those entries in Go with the expected manifest and requires matching file and directory counts, with no extra entry or non-regular type. For `shasum`, the remote script hashes file contents from stdin; `sha256 -q` already returns a digest without a filename. Both emit the original pathname from the shell; for hash commands other than `sha256sum`, it also obtains sizes with `wc` on stdin and emits the original pathname. Parsers require an exact match to the original pathname and reject control characters and backslashes; they do not normalize Unicode or decode filenames from tool output. A source represented by exactly 1024 zero bytes followed by EOF is treated by TarIn as the canonical empty/root-only archive and takes the empty-root fast path; any source read error remains a content-free failure. Then publish.

Download: remote preflight rejects non-regular entries and over-limit trees, then returns the remote manifest using the selected SHA-256 command. Stream `tar -c` and extract locally into staging with Go `archive/tar`, hashing while extracting, and compare with the manifest and counts. Then publish. Source enumeration or read failures remain failed, content-free results and are not converted to an empty manifest.

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
5. Both native Linux and native macOS CI workflows are configured to run the full real-stack acceptance suite on the same round-trip scenarios (including empty directories), overwrites, failures, refusals and injection cases, with no skips. The macOS run uses stock BSD tools and `PATH=/usr/bin:/bin:/usr/sbin:/sbin`, exercising Perl publication rather than refusal-only coverage. This documents configured coverage, not a claim that CI has already passed. Other BSD systems are supported only when the functional probe passes; FreeBSD success is not CI-tested. Linux CI also has a real BusyBox applet subset using a BusyBox-only PATH and BusyBox `sh`. That subset covers file/empty/name/overwrite/refusal/corruption behavior and nested directory content, manifests and counts both ways; BusyBox directory timestamp restoration remains unverified. The subset intentionally excludes `failure-unsupported-remote`: standalone BusyBox `sh` can resolve SHA applets independently of the restricted PATH, so its missing-tool fixture is not meaningful under that shell. The full Linux and macOS suites still cover missing-hash refusal; native BusyBox positive scenarios remain covered.

## Non-goals

Move/delete/sync/delta/resume; symlink or hard-link replication; ownership and xattr preservation, and timestamps of single files; remote-to-remote copy; Windows remote targets; remote hosts that fail the functional SHA-256, `t`/`p` publication, or required long tar extraction-flag probes; root (uid 0) remote targets whose tar only supports the short `-o` extraction form; SFTP or rsync; a declarative or narrower authorization surface; scheduling; any change to key custody or to the output guard. BusyBox directory timestamp restoration is not established by its CI subset.

## Implementation order

1. This document.
2. Remote protocol layer: command templates, capability probe, manifest format, bounded stderr, over the existing `StreamRunner` (no change to `internal/remote`) — parallel with 3.
3. Local safety layer: roots, path resolution, staging, publication, safe extraction, per-OS code — parallel with 2.
4. Single-file engine on 2 and 3.
5. Directory engine on 4.
6. MCP tools, keeper wiring and documentation on 4.
7. Acceptance tests and CI gate on 5 and 6.
8. Exact-SHA review, CI and integration.

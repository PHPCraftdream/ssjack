# Directory-capability commit-intent IO

This opt-in Linux-only prerequisite implements fixed-name publication of the
312-byte `SSAPCMT1` record from `docs/application-store/IO.md`. It stores protocol
state/hash/transaction metadata, never application secret bytes, passwords or
keys. It does not encrypt, perform CAS, connect to an anchor, deliver secrets or
enable production MCP operations.

`New` requires an already-open private directory and nonzero fixed store ID. It
opens an independent description of that same directory, checks inode/device,
current effective UID, directory type and exact 0700 mode. It never selects a
path, creates a directory, follows a model-supplied locator or establishes human
provenance. The caller must supply a trusted, already durably attached directory
on a filesystem with the required file/directory sync semantics. A descriptor
opened through a symlink by the caller is not proof of trusted path provenance.
Non-Linux platforms explicitly return `ErrUnsupported`; there is no weaker
portable fallback.

Each operation uses nonblocking in-process admission and an exclusive cooperative
directory flock, including across independently constructed handles. This lock
covers only intent IO, not the complete store transaction. Copies share Close;
Close waits for active IO and closes the owned descriptor, not the caller's FD.
No wall-clock bound or interruption of a blocked filesystem syscall is promised.

`Create` admits a canonical store-scoped Intent, derives one fixed filename from
its transaction ID, and creates with O_EXCL/O_NOFOLLOW and mode 0600. It writes
exact bytes, syncs the file and directory, then reopens and byte-compares before
returning success. Existing names, including identical records and bad records,
are never overwritten. Any failure can leave a partial or complete record; no
cleanup, deletion, silent retry, rollback or CAS permission follows from an error.
Sync/reopen success is evidence of the requested syscall sequence under the
filesystem assumptions, not a tested power-loss guarantee or candidate proof.

`Load` uses no-follow/nonblocking open, requires a regular current-UID 0600 file
with one hard link and exact size, bounds reads to 313 bytes, rechecks identity,
size, mode, link count and modification/change timestamps, and validates exact
store/transaction/intent encoding. It does not prove original publication,
durability, candidate identity, anchor state or authority to replay the restored
CAS. A readable intent is not a confirmed commit. Normal recovery must still
perform authenticated Read and all exact candidate/expected-state checks.

The directory and records must remain exclusively controlled by cooperating
trusted code. Permission/stat checks and flock are not a sandbox or protection
against hostile root, a same-UID process, a malicious filesystem or mutation
outside this protocol. Metadata checks are not atomic with concurrent hostile
mutation. No file immutability flag, full transaction fence or authenticated
root enrollment is claimed.

Synthetic CI tests cover exact publication/reopen/CAS bytes, independent flock,
shared lifecycle, duplicate refusal, scope/mode/ownership, symlinks/hardlinks,
FIFO/directory/length/corruption, file/directory sync failures, changed bytes at
reopen and unsupported platforms. Tests use disposable directories only; no real
credential files or store paths are accessed. Feature CI selects this package
and its reverse dependents; full sprint verification remains a separate gate.

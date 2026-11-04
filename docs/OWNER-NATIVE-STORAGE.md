# Native owner storage — implementation in progress

The native filesystem capability layer and installation-binding port are under
implementation. This is not acceptance of the complete application-store port:
the native record engine, provisioning CLI and live owner coordinator still need
integration and real cross-platform acceptance. The existing Linux implementation
remains unchanged.

## Protected filesystem capabilities

`ownerfs.Root` owns a directory fd/handle. Public operations accept bounded single
component names, never arbitrary paths relative to an ambient working directory.
The installation root is selected explicitly and is checked on every identity
boundary. Roots, files and temporary spools must belong to the current owner and
have private modes or protected owner-only ACLs. Files with unexpected links,
reparse points, object type or permissions refuse.

- Linux/macOS use `openat`/`O_NOFOLLOW`, owner modes, nonblocking advisory locks,
  fd-relative operations and exclusive native rename. macOS root-managed system
  aliases are restricted to the protected system prefixes needed for native paths.
- Windows uses handle-relative NT file operations with an explicit owner security
  descriptor, reparse refusal, native file identity and nonblocking byte-range
  locks. Only local fixed NTFS storage is supported by this implementation; it
  does not silently fall back to FAT, a remote share or a weaker permission model.
- Installation ownership and data transactions use separate lock names. A store
  holding its installation lock must still be able to execute one data transaction.
- Temporary files are created empty and detached before callers can write any
  ciphertext. On Windows, an independently opened handle retains the empty file;
  the POSIX-disposition handle must close before the spool is returned. Setting
  disposition alone does not remove the name. Both handles must identify the same
  file before unlinking. The original name must be absent before and after writes,
  and reusing that name must create a different file, not alias the spool.
  Failure to obtain an anonymous-before-use handle refuses; there is no named
  ciphertext-spool fallback and never plaintext staging.

Windows data handles use write-through and explicit file flushing. This is not
an assertion that Windows supplies a POSIX directory-fsync primitive. Namespace
publication is checked by native identity and the resulting file contents. The
filesystem layer makes no power-loss durability certification on any platform.
Uncertain publication must remain uncertain and must not be automatically replayed
or called application adoption.

## Installation bindings

The native `appstoreentry.Store` owns its protected root and exclusive installation
lock. It preserves bounded encrypted `binding.bin` bytes, refuses overwrite,
compares the named file to its open handle, checks before/after revisions and
reopens the original root path to detect replacement. Exported root handles are
owned duplicates; they are not master-key or plaintext-value getters.

Directory identity remains an authenticated part of the installation binding.
Moving/copying a binding does not automatically rebind it to a different root.
No container/KDF/profile/version reduction or automatic enrollment is included.

## Acceptance required before shipping

Native tests must cover protected creation, identity/adoption, exclusive locks,
no-overwrite and explicit replacement, traversal/reparse/hard-link refusal,
anonymous spools, binding preservation and root replacement. Complete acceptance
also requires real native secret add/update/readback through the private store,
owner CLI/TUI parity and live coordinator operation on Windows, Linux and macOS.
Writing these checks or passing only a primitive layer is not that acceptance.

# SSH compatibility and host trust

ssjack is its own SSH client. Use named credentials from the encrypted database:

```text
ssjack -p storage ssh
ssjack -p storage run claude -c
```

The former `ssh.sh` and `ssh.cmd` OpenSSH wrappers and their configuration template have been removed. Use the native client rather than an alternate credential path. Run the installed `ssjack` executable directly; no checkout/application wrappers are required.

## Host trust

Before importing a server public key, verify its fingerprint through a trusted console or an already trusted SSH session. On the server, for example:

```sh
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Import the corresponding server `.pub` file when adding or editing a credential record. The vault stores that public key inside its encrypted payload and checks it on every connection. A client login public key is not a server host key. Unknown or changed keys are rejected; there is no automatic acceptance or unverified network-scan shortcut.

Install only the client's public key in the intended remote account's `authorized_keys`. Never copy the private key to the server or put a passphrase in arguments, environment variables, configuration, or chat.

## Live ordinary SSH job credential refresh

In an ordinary full-mode version-2 session, new non-proxied SSH jobs can use a
persisted credential-only replacement for the selected agent account. The owner
must first arrange the replacement authentication on the server through a trusted
procedure; key credentials can refresh to key credentials, and passwords to
passwords. This slice has no server-side installation or revocation; old remote
authorization is not automatically retired and remains under the owner's separate
server-side control.

At job start, ssjack synchronously captures the host-pin-verified SSH
configuration and matching output guard from the same saved database revision and
ciphertext digest. That admitted operation and its existing connections stay
frozen; only a later ordinary job can use the persisted replacement. Human SSH,
startup stream captures, application grants, and version-1 or proxied startup paths
retain their existing frozen behavior. A changed account scope or unavailable
saved state refuses a new job rather than falling back to startup credentials.

This is credential delivery, not general reconciliation or server-side rotation.
It does not establish that every current consumer adopted an edit. Runtime status
is metadata only and held in session memory; restart loses delivery/adoption
evidence. Acceptance requires exact-source public CI, including the ordinary SSH
live lifecycle scenario; earlier frozen-runner acceptance is not sufficient.

## Keeper-backed owner rotation

For a direct public-key account, `owner rotate-key` displays the selected
server/account/profile/endpoint/user/usage, saved server-host-key fingerprints,
old/new client-key fingerprints, revision, PlanID and operation ID. Each
invocation requires a fresh hidden owner-database password and trusted terminal.
Before any remote add, the owner must enter the exact displayed ROTATE
confirmation bound to the selection, revision and operation. Preparation and
phase transitions are persisted before possible remote effects. The replacement
login is verified through the saved host pins before the selected account is
committed; this does not retire the old remote key or prove adoption by every
consumer.

An uncertain add outcome is handled only by a separate `--recover` invocation.
Its exact VERIFY-ONLY confirmation allows login verification and completion; it
never replays an uncertain add. A prepared no-effect orphan can be cancelled by
one separate `--recover --cancel-prepared` invocation after its exact
CANCEL-PREPARED confirmation; the packet recovery action alone only
inspects/claims the journal.

After completion, another rotation requires explicit preservation. Run
`owner rotate-key --server NAME --account NAME --archive-completed` as a separate
invocation. It displays the retained operation and current revision and requires
an exact ARCHIVE confirmation bound to the selected identity, revision and
operation ID. Only then does it copy the exact current
encrypted database snapshot to a random, no-overwrite recovery file, verify and
durably sync the copy, and retain an archived tombstone receipt containing its
path and ciphertext SHA-256. The snapshot preserves old and replacement private-
key recovery material under the same unchanged database encryption; there is no
plaintext export or new KDF. Archival does not retire remote authorization or
happen automatically. A subsequent rotation requires yet another separate
invocation, which prepares the next plan.

The archive command does not automatically unlock secrets found only in its
preserved snapshot for output masking. The keeper's default model-output
known-literal guard covers current database credentials and pending/recovery
new-key material plus the retained old key while that journal remains live,
within collector bounds; admitted guard history remains in keeper
memory and is lost on restart. Human SSH terminal sessions remain unfiltered, and
the mandatory token callback is unchanged. Exact-source public full-profile CI
acceptance remains pending; no pass is claimed. The
`TestVaultOwnerRotationRecoveryFullProfile` gate uses the `ownerrotationtest`
source fixtures, which emulate the SSH add-key protocol in memory rather than
executing a POSIX `authorized_keys` filesystem operation.

## Formats

The encrypted ssjack container is not directly readable by OpenSSH. Standard encrypted OpenSSH/PEM keys can be imported into the encrypted database. Interoperability exports must be explicitly requested and protected with their own passphrase; they do not retain the custom container's four Argon2id operations and 1000 AES-GCM data layers.

See [protected keys](docs/KEYS.md) and [the credential database CLI](docs/VAULT.md) for the supported commands. Source files and old backups retain their original protection until separately retired. Deleting a file is not guaranteed secure erasure of snapshots, backups, or storage blocks.

## Boundaries

- The private key remains in the ssjack process, not an external SSH client or agent.
- The remote account's permissions apply; SSH is not an application sandbox.
- Agent/X11 forwarding and arbitrary target selection are not enabled by the interactive mode.
- Ignore rules do not protect files from same-user processes, backups, synchronization, or forced Git additions.
- Remote output and intentionally displayed credential metadata may contain sensitive information.

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
evidence. Source tests for this slice have not been run, and exact-source CI
acceptance is pending.

## Formats

The encrypted ssjack container is not directly readable by OpenSSH. Standard encrypted OpenSSH/PEM keys can be imported into the encrypted database. Interoperability exports must be explicitly requested and protected with their own passphrase; they do not retain the custom container's four Argon2id operations and 1000 AES-GCM data layers.

See [protected keys](docs/KEYS.md) and [the credential database CLI](docs/VAULT.md) for the supported commands. Source files and old backups retain their original protection until separately retired. Deleting a file is not guaranteed secure erasure of snapshots, backups, or storage blocks.

## Boundaries

- The private key remains in the ssjack process, not an external SSH client or agent.
- The remote account's permissions apply; SSH is not an application sandbox.
- Agent/X11 forwarding and arbitrary target selection are not enabled by the interactive mode.
- Ignore rules do not protect files from same-user processes, backups, synchronization, or forced Git additions.
- Remote output and intentionally displayed credential metadata may contain sensitive information.

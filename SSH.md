# Manual SSH access

`ssh.sh` and `ssh.cmd` are Windows OpenSSH wrappers for manual access. They are independent of the ssjack MCP keeper described in `SSJACK.md`: they do not receive its unlocked credentials.

Both wrappers explicitly use the local `.ssh/config` and the `storagehost` alias. They change to their own directory so relative key and known-host paths do not depend on the caller's working directory.

## Setup

1. If `.ssh/config` does not exist, copy `.ssh/config.example` to it. Do not overwrite an existing configuration.
2. Replace `CHANGE_ME` with the target IP or DNS name, and verify `User` and `Port`.
3. Generate a dedicated encrypted key interactively from this directory:

   CMD:

   ```bat
   "%SystemRoot%\System32\OpenSSH\ssh-keygen.exe" -t ed25519 -a 100 -f .ssh\id_ed25519 -C storagehost-local
   ```

   Git Bash:

   ```bash
   "$(cygpath -u "$SYSTEMROOT")/System32/OpenSSH/ssh-keygen.exe" -t ed25519 -a 100 -f .ssh/id_ed25519 -C storagehost-local
   ```

   Set a strong, nonempty passphrase. Never put it in command arguments, environment variables, configuration, or chat. Stop if asked to overwrite an existing key.

4. Install only `.ssh/id_ed25519.pub` in the intended server account's `authorized_keys` through an existing trusted connection. Do not copy the private key.
5. Inspect the private key's Windows ACL before changing permissions. Do not disable OpenSSH permission checks to work around an overly permissive ACL.

## Usage

Git Bash:

```bash
./ssh.sh
./ssh.sh 'uname -a'
```

CMD/PowerShell:

```text
.\ssh.cmd
.\ssh.cmd "uname -a"
```

Arguments are a remote command, not an alternate host. Quoting rules depend on the invoking shell. Use an interactive connection for complex manual commands.

Before accepting an unknown host key, compare its fingerprint through a trusted console or existing SSH session. For example, on the server:

```sh
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Verified keys are recorded in the local `.ssh/known_hosts`.

## Boundaries

- `-F` selects the local configuration rather than the global user configuration.
- `IdentityAgent none` disables the shared SSH agent. Each new connection asks for the encrypted key's passphrase.
- Password and keyboard-interactive authentication are disabled.
- Agent forwarding, X11 forwarding, and configured port forwards are disabled.
- Ignore rules do not protect files from same-user programs, backups, synchronization, or forced Git additions.
- These wrappers do not isolate agents and do not install or administer Incus, Nix, or remote services by themselves.
- Remote commands and output may contain secrets; do not place secrets in command arguments or intentionally print them into a transcript.

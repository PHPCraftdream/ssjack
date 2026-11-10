# Existing vault startup password

Hidden terminal input remains the default. For an existing database, ssjack also
accepts the owner-authorized startup sources `SSJACK_VAULT_PASSWORD` and the global
`--vault-password VALUE` option. These are explicit exceptions to the normal rule
against placing secrets in arguments or environment variables.

## Disclosure warning

When existing-vault unlock reads a supplied startup source, ssjack emits this
fixed warning before returning the password to unlock work:

```
WARNING: vault password supplied through argv/environment; hidden terminal input is safer.
```

The warning contains no password value. If no explicit source is supplied, hidden
terminal input remains the default and this warning is not emitted.

A literal command-line password may appear in shell history, process inspection,
process creation auditing, crash dumps or terminal recording. Environment variables
are also readable to processes with sufficient access. Neither source provides the
same exposure boundary as hidden terminal input. Do not put a real password in MCP
configuration, scripts, project files, logs or a model conversation. Prefer a
trusted secret manager when environment-based startup is necessary.

Removing a variable from the ssjack process prevents ordinary child inheritance;
it does not erase the parent shell's environment, shell history, OS process argv,
other copies or prior observations. Go memory cleanup is best effort, not secure
erasure against a debugger, same-user compromise or Administrator/root.

## Precedence and behavior

1. An explicitly supplied `--vault-password VALUE` overrides the environment.
2. Otherwise, a present `SSJACK_VAULT_PASSWORD` supplies the password.
3. If neither source exists, the existing hidden terminal prompt runs.

An explicitly empty value, an oversized value (more than 16384 bytes), or repeated
`--vault-password` options refuses. There is no fallback after invalid input or
failed authentication. A valid explicit argument can override an invalid
environment value. Password bytes are not trimmed or normalized.

The global option must precede the command. In this example, the value is a
placeholder, not a real password:

```sh
ssjack --vault-password '<VAULT_PASSWORD>' --interactive
ssjack --vault-password '<VAULT_PASSWORD>' owner add-mcp-server
```

For environment startup, populate `SSJACK_VAULT_PASSWORD` through a trusted local
mechanism, then run the usual command, such as `ssjack --interactive` or
`ssjack run HARNESS`. Avoid typing literal secret assignments into shell history.
The variable is removed from ssjack's environment at entry, including on errors
and metadata-only paths. Global password arguments are not part of the harness
command. A supplied password is consumed once for existing-vault authorization;
it is not retained as a reusable password service during a long-running session.
Unused owned bytes are cleared when startup exits; unlock callers clear consumed
buffers after use. No password is included in flag defaults or diagnostic errors.

## Scope

The source applies to existing credential-database unlock paths, including owner
commands, the interactive editor, SSH/check/harness credentials, metadata listing,
existing-vault maintenance and the text adapter's credential database. Owner forms
and human SSH still require their original trusted terminals. Supplying a password
does not automatically select or confirm an SSH connection or MCP server.

New database passwords, password changes, imported-key passphrases, backup
passwords, application-store masters, SSH/MCP credentials and exact confirmations
remain separate terminal prompts. Root provisioning and `ssjack mcp` do not acquire
owner authority from this variable. The source does not change encryption, KDF
parameters, data-layer count, permissions or grant boundaries.

Unit/native CI checks precedence, single consumption, bounded input, cleanup,
non-echoing flag errors, terminal requirements and non-forwarding to the harness.
The actual-run startup regression uses a mocked credential loader and harness
launcher to verify the warning precedes synthetic unlock and harness boundary
markers, and that the startup source is stripped before the harness boundary; it
does not exercise a real child process. These authored regressions require exact-
source public CI before runtime acceptance. The mandatory full-profile startup
acceptance creates a real encrypted database, opens it through environment and
argument sources, refuses a wrong password and checks that read-only startup
preserves ciphertext. No production KDF overlay is used for that acceptance.

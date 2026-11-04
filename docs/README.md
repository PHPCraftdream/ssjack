# ssjack capability and documentation map

This index describes the current implementation, not every proposed protocol.
Start with [the README](../README.md), [installation](INSTALL.md) and
[the credential guide](VAULT.md). Built-in `ssjack help` is available without
opening a database; global flags precede commands.

## Choose the right surface

| Goal | Entry point | Guide |
| --- | --- | --- |
| Run one owner action with parameters | `owner ACTION [OPTIONS]` | [Owner CLI and shared forms](OWNER-CLI.md) |
| Choose a human SSH connection, even a single one | `ssjack --interactive` | [Owner menu](application-store/OWNER-TUI.md) |
| Manually add/edit servers, accounts and passwords | Servers → Add server / server → Add SSH account | [Directory model](application-store/NAMED-DIRECTORY.md) |
| Route a server through SOCKS5 / HTTP CONNECT | Servers → SERVER → Edit SSH proxy | [Proxy configuration and wire-auth limits](PROXY.md) |
| Select a named SSH account without menus | `--server NAME --account NAME ssh`, `check`, `rotate`, `run` | [Named startup](application-store/NAMED-STARTUP.md) |
| Use a stable credential-record ID | `-p PROFILE` / `--profile PROFILE` (default `main`) | [Credentials](VAULT.md#default-profile-selection) |
| Import old plaintext SSH metadata | `vault migrate LEGACY_FILE` | [Legacy metadata](VAULT.md#legacy-metadata-migration-boundary) |
| Upgrade the encrypted outer container | `vault upgrade` | [Container upgrade](VAULT.md#explicit-container-format-upgrade) |
| Back up/verify/restore the entire database | `vault backup FILE`, `vault check FILE`, `vault restore FILE` | [Recovery](VAULT.md#backup-verification-and-restore) |
| Change the database password | `vault passwd` | [Credential guide](VAULT.md) |
| Generate/protect standalone key containers | `--generate-key FILE`, `--protect-key FILE --key-output NEW_FILE` | [Keys](KEYS.md) |
| Generate a key inside a profile | `vault init --generate-key`, `add --generate-key` | [In-database generation](VAULT.md#generate-a-key-while-creating-a-profile) |
| Print/import/export an SSH key | `key public`, `key import FILE`, `key export FILE` | [Key interoperability](VAULT.md#keys-and-interoperability) |
| Inspect/change SSH negotiation settings | `policy show`, `policy edit` | [SSH policy](VAULT.md#encrypted-ssh-policy) |
| Inspect/replace verified host keys | `hostkey show`, `hostkey replace FILE` | [Server pins](VAULT.md#server-identity-pins) |
| Rotate a key through verified remote installation | `rotate` | [Two-phase rotation](VAULT.md#two-phase-key-rotation) |
| Diagnose local setup / test SSH authentication | `doctor` / `check` | [Diagnostics](VAULT.md#diagnostics) |
| Launch a coding harness with one selected credential | `run HARNESS [ARGS...]` | [Bootstrap](BOOTSTRAP.md), [architecture](../SSJACK.md) |
| Register finite Clawwright operations | `--clawwright-directory DIR [route options] run HARNESS` | [Application transport](APP-TRANSPORT.md) |
| Provision/unlock a separate secret-store installation | `appstore setup`, `put`, `inspect`, `unlock` | [Store entry](application-store/ENTRY.md) |
| Edit named application-secret values | Link secret store, then Global secrets / Server secrets | [Owner editor](application-store/OWNER-EDITOR.md), [coordinator](application-store/OWNER-COORDINATOR.md) |
| Export selected credentials/settings/actual values | Export menu: all/server/account/global scope | [Archive format](application-store/OWNER-EXPORT-FORMAT.md) |
| Import an owner export without overwriting entries | Import menu → inspect → preview → exact `IMPORT` | [Import lifecycle](application-store/OWNER-TUI.md#owner-import) |
| Hydrate bounded selected text | Root `text-adapter register`, non-root `serve` | [Text adapter v1](application-store/TEXT-ADAPTER.md) |
| Back up a reference-only selected copy | Root `register-reverse`, non-root `serve` | [Reverse copy v1](application-store/TEXT-REVERSE-COPY.md) |
| Deploy/back up larger text through streaming | Root `register-stream` / `register-reverse-stream`, non-root `serve-stream` | [Streaming HTTP](application-store/TEXT-STREAM-HTTP.md), [framing](application-store/TEXT-STREAM-FRAMING.md) |
| Bind/revoke an adapter credential/grant | `text-adapter identity`, `revoke ID`, `revoke-stream ID` | [Text adapter](application-store/TEXT-ADAPTER.md) |
| Use the narrow synthetic declarative metadata path | `declarative setup|register|revoke|run` | [Authority](declarative/authority.md) |
| Approve/revoke fixed synthetic confidential delivery | `declarative register-delivery|revoke-delivery`, then `appstore unlock` | [Delivery runtime](application-store/DELIVERY-RUNTIME.md) |
| Build this checkout and install globally | Root `sh ./build.sh` (Linux/macOS), `.\build.ps1` (Windows) | [Build/install permissions](INSTALL.md#build-this-checkout-and-install-globally) |
| Inspect build provenance and license notices | `--version`, `--licenses` | [Releases](RELEASES.md), [licenses](LICENSE-COMPLIANCE.md) |

`mcp`, `hook` and `install-hooks` are bridge/compatibility endpoints, not ways to
supply database passwords or grant access. Ordinary launches install the embedded
project-local UI plugin when supported. [UI source and compatibility](../plugins/ssjack-ui/README.md).

## What the boundaries mean

- **Owner administration:** the database-password holder owns the directory and
  linked owner operations. No multi-owner RBAC or automatic user provisioning.
- **Platform:** core SSH/credential/menu functionality targets Linux, macOS and
  Windows. Linked private app-store values are Linux-only; root-granted delivery
  and text-adapter CLI runtimes are Linux/amd64. A Windows VT console that cannot
  release SSH stdin fails closed and requires a restart rather than menu resume.
- **Persistence:** one unlocked owner RAM session, ordered encrypted autosave and
  explicit pending-intent recovery. The full remaining import plan is RAM-only;
  abort does not undo published entries, and full-plan resume after restart is
  not provided. See [coordinator](application-store/OWNER-COORDINATOR.md).
- **Import:** existing encrypted or deliberate plaintext export ZIPs; strict
  bounds; metadata-only preview; no silent merge/overwrite; fresh destination refs.
  Unlinked stores and unsupported values refuse instead of dropping selected data.
- **MCP:** full `remote_*` / registered `app_*` can expose command output. They are
  not restricted declarative execution or universal secret redaction.
- **Delivery:** exact refs and finite grants, separate direction/version scopes,
  status-only results, no automatic uncertain retry. A receipt is not adoption.
- **Text:** v1 hydrate input ≤32 KiB; v1 reverse text ≤1 MiB. Separate v2 decoded
  input/output ≤64 MiB, 32 KiB chunks, ≤16 refs and ≤1 MiB selected values.
  Representation, escaping and mapping completeness remain operator responsibilities.
- **Crypto:** four independent sequential Argon2id derivations, each 1 GiB/t1/p1,
  and 1000 actual AES-256-GCM data layers; no independent audit or 1000-fold
  password-strength claim. [Audit scope](AUDIT.md), [crypto runtime](application-store/CRYPTO-RUNTIME.md).

## Protocol and design references

[Application-store format](application-store/FORMAT.md), [wire](application-store/WIRE.md),
[crypto](application-store/CRYPTO.md), [I/O](application-store/IO.md),
[failures](application-store/FAILURES.md), [vectors](application-store/VECTOR.md),
[compatibility](application-store/COMPAT.md) and [placeholders](application-store/PLACEHOLDERS.md)
describe the format and security contracts. They are not automatic service enrollment.

[Declarative specifications](declarative/README.md) describe a broader proposed
contract than the implemented synthetic slice. The enrollment/policy/identity flags
load partial metadata descriptors; they do not enable a general driver or secret
resolver. [Lifecycle](declarative/lifecycle.md) and [driver](declarative/driver.md)
requirements must not be advertised as complete runtime behavior.

Documents named `TASK…`, `…DRAFT…`, review packages, proposal documents and checkpoints
retain historical or design context. Prefer current operator guides and exact-source
CI receipts when deciding what is available. No automatic OpenClaw/provider adoption,
continuous synchronization, server hardening or discovery of unknown secrets is supplied.

## Verification and distribution

[CI policy](CI.md) separates ordinary scoped checks from the full sprint gate.
Tests/builds/application smoke belong in GitHub CI, not an implicit local command.
The accepted feature baseline is source `0576409`,
[full run 41796602948](https://github.com/PHPCraftdream/ssjack/actions/runs/41796602948),
all nine jobs successful. Production owner acceptance includes actual tmux import,
empty-database and partial-recovery paths; the paired Clawwright source is
`053655da09086986a23f66efe42dd5e8a2907f70`. This does not publish a release or migrate
an operator's data. [Install](INSTALL.md), [release trust](RELEASES.md), [security reporting](../SECURITY.md).

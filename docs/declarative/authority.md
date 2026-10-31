# Declarative authority boundary

## Status

The source contains an isolated Linux/amd64 synthetic-metadata slice and a privileged CLI path. **It is not production-ready and has not been executed or acceptance-tested.** Public CI acceptance code is authored, but no passing CI run is claimed. Static fixture drivers are test-only; no production driver artifact or installation mechanism is supplied here.

## Fixed authority

`internal/declarativeauthority` uses fixed paths: registry `/etc/ssjack/declarative`, executable `/usr/libexec/ssjack-synthetic-driver`, and synthetic metadata state `/var/lib/ssjack/synthetic`. These paths are not caller-configurable. The authority marker explicitly scopes grants to synthetic metadata and says no secret release. Grants bind an exact canonical app-store placeholder, recipient effective UID, installed executable SHA-256, fixed target and schema IDs/digests, purpose, policy revision, and finite RFC3339 expiry (at most 30 days).

On Linux/amd64, `ssjack declarative setup`, `register`, and `revoke` are root-only interactive operations. They refuse inherited broker/bootstrap credentials. Setup requires a typed scope phrase; registration asks the administrator to inspect and confirm the exact reference and independently compare the installed executable digest, fixed schema contract, recipient UID, expiry, and final scope phrase. Revoke requires the exact reference twice. These prompts are source behavior, not proof that the operator is an independently authenticated person or that a trusted installation channel exists. Do not launch these administrative commands from a model-controlled session. No installation, enrollment, schema distribution, or production trust bootstrap is implemented by these commands.

Registration prepares fixed-path metadata state for the selected non-root recipient. The recipient UID is part of the grant and `New` requires an active grant matching the process effective UID. Existing state is preserved rather than reset. Authority state creation uses descriptor-relative no-follow traversal and exclusive file creation. The driver checks fixed ancestors and file owner/type/mode/link-count/size on each access. These checks assume trusted root-owned ancestors and do not make the recipient process a sandbox.

## Runtime scope and lifecycle

`ssjack declarative run HARNESS [ARGUMENTS...]` starts the restricted launcher path through `declarativeslice.New`. The bridge descriptor is `ssjack-synthetic-metadata-1`, incomplete, and advertises exactly `resource_plan` and `plan_apply`. Existing full mode remains separate; this descriptor is not a secret-safe relabeling of the full toolset. Unsupported operations fail closed.

Desired metadata is a closed object containing only `enabled` and the exact grant-bound placeholder `ref`. Planning observes the fixed synthetic cache metadata without mutation, returns a session-local plan and binds session, plan ID, entire grant, desired state, resource, observed revision, and expiry. Plans live in memory, are bounded to 128 per session, and expire at the earlier of one minute or grant expiry. A plan is not reusable after consumption with a different request ID. Apply rechecks the grant and installed executable digest, observes the revision before invoking, and the static fixture demonstrates revision-checked persistence and operation-ID/digest reconciliation. A lost or timed-out reply can leave the outcome unknown; a same-request retry attempts reconciliation and never invents rollback or claims a detached process stopped. Session-local plans and operation bookkeeping are not durable across keeper restart, so this is not general restart-safe exactly-once execution.

The fixture's metadata file has a lock and atomic replacement, but it is writable by the selected recipient UID so the driver can persist updates. A process with that same UID can alter the metadata directory/files; this is an explicit same-UID trust boundary, not OS isolation, a sandbox, or protection from a compromised recipient account. Immutable executable binding in source checks a fixed executable digest and seals a copy, but does not establish provenance, process identity, privilege isolation, dependency closure, filesystem/network containment, or production readiness.

## Secret and trust non-goals

Placeholder bytes are metadata references only. There is no resolver, secret hydration, credential release, Nix/OpenClaw/Clawwright integration, native configuration update, argv/environment injection, or proof that consuming applications receive a secret. Secret release remains unimplemented and must not be inferred from a successful metadata operation. Human verification of driver provenance and intended resource behavior must occur outside any model-controlled session.

## Authored public acceptance

The scoped Linux CI job uses a disposable root container to compile static synthetic fixtures, install only the fixed test path, perform setup/register/revoke through the interactive CLI, and run the broker/MCP tests as a non-root recipient. Authored cases cover the two-tool descriptor, planning without mutation, apply/replay/stale revision behavior, denied full operations, separate-session plan rejection, malformed input refusal, output-schema rejection, expiry/revocation/executable-digest rechecks, and a delayed lost-reply reconciliation fixture. These are intended checks only: they have not been run in this work session, and no CI result is claimed. Test fixtures are not supported production drivers.

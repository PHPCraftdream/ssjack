# Trusted selected-text adapters

The Linux/amd64 text-adapter CLI supports separately approved forward hydration
and reverse selected-copy contexts. It is not the general `app_*` transport or
the fixed synthetic confidential-delivery route. Actual v1/v2 Clawwright
CLI/root-keeper/SSH pairs passed in
[full CI 41796602948](https://github.com/PHPCraftdream/ssjack/actions/runs/41796602948)
on ssjack `0576409` and Clawwright `053655da09086986a23f66efe42dd5e8a2907f70`.
This does not prove production enrollment, interactive grant/unlock prompts,
consumer adoption, crash durability or unknown-secret detection.

## Human setup and CLI entry

The application-store installation, authority setup and verified SSH credentials
must already exist. There is no automatic enrollment or permission inferred from
paths, hashes, references or CLI options.

```sh
ssjack --vault DATABASE --server production --account automation text-adapter identity
```

Identity inspection unlocks the database in a non-root terminal outside a broker
session and prints only the selected opaque credential binding. Keys bind the
public SSH identity; password accounts use a domain-separated private keyed
binding, not a public password hash. A change to credentials/connection identity
requires an appropriate new grant; an ID is not authorization.

Root independently verifies and confirms the finite exact grant interactively:

| Direction / version | Register | Revoke | Non-root serving command |
| --- | --- | --- | --- |
| Forward v1 | `text-adapter register` | `text-adapter revoke GRANT_ID` | `text-adapter serve GRANT_ID HARNESS [ARGS...]` |
| Reverse v1 | `text-adapter register-reverse` | `text-adapter revoke GRANT_ID` | `text-adapter serve GRANT_ID HARNESS [ARGS...]` |
| Forward v2 | `text-adapter register-stream` | `text-adapter revoke-stream GRANT_ID` | `text-adapter serve-stream GRANT_ID HARNESS [ARGS...]` |
| Reverse v2 | `text-adapter register-reverse-stream` | `text-adapter revoke-stream GRANT_ID` | `text-adapter serve-stream GRANT_ID HARNESS [ARGS...]` |

The grant binds recipient UID, store directory identity and path, installation
and encoded snapshot hashes, resolved credential-record ID/binding, exact absolute
file, command, direction, UTC expiry and 1–16 canonical refs from one store/snapshot.
The human must verify what the command does: exact file metadata is not a shell
substitution or proof that effects are limited to that file. Registration fields
and approval are read interactively, not accepted as model-supplied authority.

Serve prompts privately for the credential database and installation unlock,
validates the grant and launches the harness with only temporary endpoint/token/pin
bootstrap. It exposes exactly one direction. Forward grants do not permit reads;
v2 has a separate registry and never falls back to v1 or raw execution tools.
Named startup selectors resolve stable credential IDs inside the authenticated
load. Keep credentials out of argv, environment, tool calls and logs.

## Forward v1 transport

The dedicated pinned-HTTPS MCP listener advertises `transport_info` and only
`text_hydrate`; no generic `transport_start/input/read/cancel` tools are exposed.
The request has exactly this shape:

```json
{"operation_id":"AAECAwQFBgcICQoLDA0ODw","file":"/approved/config","mode":"hydrate-v1","template":"caller-selected text with approved exact canonical references"}
```

`operation_id` is canonical unpadded base64url for 16 bytes. The file must equal
the grant. Template input is valid UTF-8, at most 32 KiB; mappings come from the
grant, not from caller authority. At most one valid operation is attempted per
capability. There is no durable cross-process retry ledger.

Bounds: ≤16 refs, ≤1 MiB aggregate selected values, ≤1 MiB hydrated output, and
a maximum 60-second operation lifetime bounded by grant expiry/caller deadline.
SSH consumes transformed stdin; stdout/stderr are discarded.

The response is status-only: `withheld`, `received` or `unknown`. `withheld`
means no runner invocation. `received` requires complete input, successful remote
exit and final checks; it is not adoption or storage-durability evidence.
`unknown` includes effects followed by cancellation, a late failure or a lost
reply. Never automatically retry or restart an uncertain operation.

## Reverse copy and large-text streaming

[Reverse v1](TEXT-REVERSE-COPY.md) runs only its independently approved read
command, keeps raw stdout private, and returns a validated reference-only copy
bounded to 1 MiB. It does not rewrite the source. The complete encoded reverse
response has an independent 25,231,360-byte limit; clients validate the full body
before exclusive publication.

[V2 streaming](TEXT-STREAM-HTTP.md) uses Prepare/Execute source binding for forward
delivery and a distinct reverse-copy listener. Bounded 32 KiB chunks, ≤64 MiB
decoded input/output, ≤4096 data frames, ≤96 MiB wire, ≤16 refs and ≤1 MiB selected
values are separate from v1's limits. Reverse output remains tentative until the
complete counters, final checks and EOF permit exclusive local publication.
Clawwright opts in through `--stream-references PATH`, one valued option on
`deploy-text` or `backup-text`; no split flag pair or automatic protocol fallback.
Restore uses a separate forward grant and captured exact reference-only text.

## Literal mapping and trust

Replacement is literal, leftmost-longest, nonoverlapping, single-pass and
nonrecursive. Inserted output is not rescanned. Equal/ambiguous mappings, empty
mapped values and unsupported marker-bearing values refuse. It is not automatic
JSON/YAML quoting, URL decoding, a template language or a detector of unknown or
derived secrets. Scope, mapping completeness, escaping, consumer compatibility
and approved final target plaintext storage remain operator responsibilities.

Root, recipient/same-UID processes, trusted runtime and kernel are trusted
boundaries. Captured external refs retain exact versions; owner snapshot updates
do not reinterpret them as latest. New snapshots do not extend old grants.
See [paired acceptance](CLAWWRIGHT-TEXT-PAIR.md), [framing](TEXT-STREAM-FRAMING.md)
and [HTTP APIs](TEXT-STREAM-HTTP.md) for source-specific evidence and exact limits.

# Consumer conformance kit

The selected-text adapters ([v1](application-store/TEXT-ADAPTER.md),
[reverse copy](application-store/TEXT-REVERSE-COPY.md),
[v2 streaming](application-store/TEXT-STREAM-HTTP.md)) are used by external
consumer programs: a deployment CLI that hydrates exact secret references into
a remote file, or backs a remote file up as a reference-only copy. The kit
verifies the real end-to-end path for any such consumer, supplied from outside:

```text
consumer CLI -> pinned HTTPS adapter listener -> root-granted adapter
             -> encrypted application-store fixture -> authenticated SSH target
```

ssjack's own CI runs the kit against an in-repository **synthetic consumer**
(`internal/syntheticconsumer`), so no external repository is checked out. An
external project runs the same kit in its own CI against its own CLI and a
pinned ssjack commit.

The kit proves the composition of the actual keeper grants, adapter
constructors, listener, SSH runner and a real consumer process. It does not
prove production enrollment, interactive approval/unlock prompts, crash
durability, application adoption or detection of unknown secrets.

## Running the kit against a consumer

Requirements: Linux amd64, root (the kit registers root-owned grants and runs
the consumer as UID/GID 65534), a Go toolchain matching `go.mod` of the pinned
ssjack revision, and Python 3 for the runner. The consumer executable and
everything it needs (interpreter, libraries, modules, fixtures) must be
readable and executable by UID 65534. The consumer runs with that identity and
a minimal environment.

GitHub Actions example, in the consumer's own workflow:

```yaml
jobs:
  ssjack-conformance:
    runs-on: ubuntu-latest
    container: golang:1.26.0
    steps:
      - uses: actions/checkout@v5
      - uses: actions/checkout@v5
        with:
          repository: PHPCraftdream/ssjack
          ref: 0123456789abcdef0123456789abcdef01234567   # pinned full SHA
          path: ssjack-kit
          persist-credentials: false
      - name: Prepare
        run: |
          apt-get update
          apt-get install -y --no-install-recommends python3
          git config --global --add safe.directory "$GITHUB_WORKSPACE/ssjack-kit"
          test "$(git -C ssjack-kit rev-parse HEAD)" = 0123456789abcdef0123456789abcdef01234567
          # build the consumer here and make it reachable by UID 65534
      - name: Conformance
        env:
          SSJACK_CONSUMER_COMMAND: /opt/consumer/bin/consumer
          SSJACK_CONSUMER_ARGS: '["--some-fixed-flag","value"]'
          SSJACK_CONSUMER_REVISION: ${{ github.sha }}
        run: python3 ssjack-kit/scripts/ci/consumer_conformance.py
```

The runner builds the kit's test binary, runs only the two conformance tests as
root and fails unless **both** report PASS with no SKIP. It prints
`Conformance source: ssjack=<sha> consumer=<command> revision=<label>`.

Without Python, the equivalent direct commands from the ssjack checkout are:

```sh
install -d -m 0755 /tmp/ssjack-kit
go test -c -mod=readonly -o /tmp/ssjack-kit/appstorecrypto.test ./internal/appstorecrypto
chmod 0755 /tmp/ssjack-kit/appstorecrypto.test
SSJACK_CONSUMER_CONFORMANCE=1 SSJACK_CONSUMER_COMMAND=/opt/consumer/bin/consumer \
  /tmp/ssjack-kit/appstorecrypto.test -test.v \
  -test.run '^(TestConsumerConformance|TestConsumerStreamConformance)$' -test.timeout=300s
```

Required markers on the output, exit status 0, and no `--- SKIP:` line for
either test:

```text
--- PASS: TestConsumerConformance
--- PASS: TestConsumerStreamConformance
```

Pin the ssjack revision by full 40-character SHA and bump it deliberately; a
contract change shows up as a diff of this document and of the kit.

For ssjack's own CI: `python3 scripts/ci/consumer_conformance.py --synthetic`
builds the synthetic consumer and runs the same kit. Feature and full workflows
both call `.github/workflows/consumer-conformance.yml`; the job is mandatory.

## Configuration

All settings are environment variables with the prefix `SSJACK_CONSUMER_`.
`SSJACK_CONSUMER_CONFORMANCE=1` (set by the runner) requests the kit. When it is
set, a missing or malformed setting fails the test; the kit never skips on
configuration. Without it both tests skip.

| Variable | Required | Meaning |
| --- | --- | --- |
| `SSJACK_CONSUMER_COMMAND` | yes | Absolute path of an executable regular file. |
| `SSJACK_CONSUMER_ARGS` | no | JSON array of strings placed before the subcommand on every call (for example a registration or application selector). Default none. |
| `SSJACK_CONSUMER_DEPLOY_NAME` | no | Forward subcommand name. Default `deploy-text`. |
| `SSJACK_CONSUMER_BACKUP_NAME` | no | Reverse subcommand name. Default `backup-text`. The two names must differ. |
| `SSJACK_CONSUMER_WORKDIR` | no | Absolute directory used as the consumer's working directory. Default: the per-case temporary directory. |
| `SSJACK_CONSUMER_ENV` | no | JSON object of extra environment variables for the consumer. Names must match `[A-Za-z_][A-Za-z0-9_]*`, must not start with `SSJACK_` and must not be `PATH`, `HOME`, `TMPDIR` or `LANG`. |
| `SSJACK_CONSUMER_REVISION` | no | Free label echoed by the runner for audit; not used by the tests. |

Subcommand names must match `[A-Za-z0-9][A-Za-z0-9_.:-]*`.

## The consumer contract

### Invocation

```text
COMMAND [ARGS...] DEPLOY --file FILE --template TEMPLATE --profile PROFILE [--stream-references REFS]
COMMAND [ARGS...] BACKUP --file FILE --output OUTPUT   --profile PROFILE [--stream-references REFS]
```

`ARGS` is `SSJACK_CONSUMER_ARGS`; `DEPLOY` and `BACKUP` are the configured
subcommand names. Flags may be given in any order. Absolute paths only.

- `FILE`: the exact remote file the grant approves (opaque to the consumer).
- `TEMPLATE`: local UTF-8 text containing canonical exact references.
- `OUTPUT`: local path of the reference-only copy; it must not exist.
- `PROFILE`: the profile the consumer expects.
- `REFS`: local file holding a UTF-8 JSON array of 1-16 exact canonical
  reference strings (at most 1024 bytes each) from the grant; never values.
  Its presence selects v2 streaming; there is no fallback between versions.

### Environment

The consumer process receives only `PATH`, `HOME` (a fresh empty directory owned
by UID 65534, which the kit later scans for leaked values), `TMPDIR=/tmp`,
`LANG=C.UTF-8` and `SSJACK_CONSUMER_ENV`. When an adapter context exists it also
receives the launcher bootstrap:

| Variable | Value |
| --- | --- |
| `SSJACK_TEXT_LAUNCH` | `1` |
| `SSJACK_TEXT_PROFILE` | the expected profile |
| `SSJACK_APP_ENDPOINT` | `https://127.0.0.1:PORT/mcp` |
| `SSJACK_APP_TOKEN` | bearer capability |
| `SSJACK_APP_CERTIFICATE_SHA256` | lowercase hex SHA-256 of the listener's single leaf certificate |

The consumer must require all of them, require `--profile` to equal
`SSJACK_TEXT_PROFILE`, and refuse before any network call otherwise. It must
pin the certificate by that digest (TLS 1.3, no system trust), send the bearer
token only to that endpoint, and follow no redirects or proxies.

### Wire behavior

- **v1 forward**: JSON-RPC `tools/call` of `text_hydrate` at `/mcp` with
  `{"operation_id","file","mode":"hydrate-v1","template"}`; template at most
  32 KiB, valid UTF-8, no NUL. `operation_id` is 16 random bytes in unpadded
  base64url. Headers `Authorization: Bearer ...`, `Content-Type:
  application/json`, `Accept: application/json, text/event-stream`,
  `MCP-Protocol-Version: 2025-06-18`; no `Origin`.
- **v1 reverse**: `tools/call` of `text_reverse_copy` with
  `{"operation_id","file","mode":"reverse-copy-v1"}`. Read the complete reply
  bounded to 25,231,360 bytes with a cap+1 read; require HTTP 200, JSON-RPC id,
  status and, for `received`, text that is UTF-8, NUL-free and at most 1 MiB.
- **v2 forward**: `POST /text-stream-v2/prepare`, then
  `POST /text-stream-v2/execute`, both `Content-Type: application/x-ndjson`:
  one closed header record (`format` `ssjack-text-stream-v2`, `operation_id`,
  `profile`, `file`, `references`; execute adds the `ticket` from prepare)
  followed by the template in bounded data/complete frames. The template file
  is held open and identity-checked across both passes.
- **v2 reverse**: `POST /text-stream-v2/reverse-copy` with the header record and
  body EOF. Publish only after the terminal frame, exact counters, complete body
  EOF and a clean UTF-8/NUL-free check; a JSON reply carries `withheld` or
  `unknown`.

Exact framing, limits and replies are defined in
[TEXT-ADAPTER.md](application-store/TEXT-ADAPTER.md),
[TEXT-REVERSE-COPY.md](application-store/TEXT-REVERSE-COPY.md),
[TEXT-STREAM-HTTP.md](application-store/TEXT-STREAM-HTTP.md) and
[TEXT-STREAM-FRAMING.md](application-store/TEXT-STREAM-FRAMING.md).

### Result

- Print exactly one JSON object `{"status":"received"}`, `{"status":"withheld"}`
  or `{"status":"unknown"}` to stdout or stderr. `withheld` means nothing was
  dispatched to the target; `unknown` means the outcome after dispatch cannot
  be established (lost or malformed reply, failed publication). Never retry.
- Exit 0 if and only if the status is `received`.
- Output (stdout and stderr together) is at most 16 KiB and contains no hydrated
  value. The target's SSH stderr carries an injected secret that must be
  discarded.
- A backup never overwrites an existing `OUTPUT` and never leaves a partial one.
  The existing file must stay byte-for-byte intact and the call must exit
  non-zero. The kit allows exactly two outcomes, and does not prescribe when the
  consumer notices the existing file:
  - the consumer refuses before any remote read: status `withheld`, zero remote
    reads;
  - the consumer dispatches the read and exclusive publication then fails:
    status `unknown`, exactly one remote read.

  More than one read, `withheld` after a read, `unknown` without one, or
  `received` is a violation.
- Forward calls whose request the consumer can refuse locally (no adapter
  context, profile mismatch, oversize template, malformed references) must exit
  non-zero before any network call.

## Scenarios

Each scenario runs in an unprivileged child (UID 65534) of a root parent that
registers finite grants and counts connections, reads and writes on a loopback
SSH target which allows only its fixed read and write commands.

### `TestConsumerConformance` (v1, bounded text)

| Scenario | Asserts |
| --- | --- |
| Duplicate approved references (parent) | The grant registry refuses a grant with a repeated reference. |
| Six finite grants (parent) | Distinct forward, reverse, restore and refusal grants for one subject, all for UID 65534. |
| Absent adapter context | Exit non-zero with no bootstrap environment. |
| Wrong expected profile | Exit non-zero when `--profile` differs from `SSJACK_TEXT_PROFILE`. |
| Wrong selected file | Exactly one `withheld` status, non-zero exit. |
| Oversize template (32 KiB + 1) | Exit non-zero. |
| After the refusals above | The SSH target saw zero connections, writes and reads: refusals never dispatch. |
| Deploy | `received`, exit 0, target holds the exact hydrated bytes, exactly one SSH write. |
| Private backup | `received`; `OUTPUT` equals the exact reference-only template; the source is unchanged; one SSH read, no extra write. |
| Exact-version restore | After the target is altered, deploying the captured copy under a separate forward grant restores the original bytes with exactly one more write; the copy is unchanged. |
| Missing version, missing object, equal mapping values | `withheld`, non-zero, target unchanged, no new SSH connection or write. |
| Whole run | No synthetic value in any file under the consumer's `HOME` or in its bounded output. |

### `TestConsumerStreamConformance` (v2, documents above 1 MiB)

| Scenario | Asserts |
| --- | --- |
| Absent adapter context with REFS | Exit non-zero. |
| No REFS against a v2 listener | Exit non-zero: no v1 fallback. |
| Wrong expected profile | Exit non-zero. |
| REFS differing from the grant | Exit non-zero before dispatch. |
| Malformed marker in the template | `withheld`, non-zero. |
| After the refusals above | Zero SSH connections, writes and reads. |
| Large deploy (over 1 MiB) | `received`; exact hydrated bytes; exactly one SSH write. |
| Large reference-only backup | `received`; exact reference-only copy; source unchanged; one read. |
| Large exact-version restore | Original bytes restored with exactly one more write; copy unchanged. |
| Existing output | Non-zero; existing copy byte-for-byte intact and source unchanged; either `withheld` with no new SSH read or `unknown` with exactly one (see Result). |
| Missing exact version | `withheld`, non-zero, no new SSH connection or write. |
| Whole run | The copy and `HOME` contain no synthetic value. |

## The synthetic consumer

`internal/syntheticconsumer` implements this contract exactly as written above,
using only the pinned transport, the frame codec and the standard library; its
program is `internal/syntheticconsumer/cmd/syntheticconsumer`. It requires the
fixed leading arguments `--consumer synthetic` (set through
`SSJACK_CONSUMER_ARGS`, which exercises that plumbing) and the default
subcommand names. It is test infrastructure and is not part of any shipped
binary. It is the reference for new consumers, but its passing run is evidence
about ssjack's side of the contract only: an external consumer's own run is what
establishes the consumer's conformance.

## Negative controls

A kit that cannot fail proves nothing. `TestConsumerKitNegativeControls` (in the
ordinary Linux test suite; no root, no SSH) re-executes the test binary as the
synthetic consumer over the real pinned listener with in-memory adapters and
runs the kit's own helpers against it, capturing failures instead of failing the
test:

| Consumer | Kit must |
| --- | --- |
| Correct (deploy, existing output) | Pass. |
| Leaks a value into its output (`--fault leak=VALUE`) | Fail with "consumer output disclosed private data". |
| Overwrites an existing output and reports `received` (`--fault overwrite-output`) | Fail with "consumer completion mismatch". |
| Overwrites an existing output but reports `unknown` (`--fault clobber-output`) | Fail with "existing output was modified". |

The `--fault` leading argument exists only in this test-only program and is
never reachable from a shipped binary.

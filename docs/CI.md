# Feature checks and sprint verification

## Feature CI

Pushes and pull requests run `.github/workflows/feature.yml`, not the full suite.
For each native platform (Linux, Windows, macOS), `scripts/ci/plan.py` obtains the
current Go package graph and compares the push's previous commit, or the pull
request's base SHA, with the checked-out revision. It selects changed packages
and all transitive reverse dependencies, including `TestImports` and
`XTestImports`. The selected packages alone receive formatting checks and Go
tests; Linux uses the race detector. Normal package edits do not run unrelated
packages, CLI packaging/install checks or the production 1-GiB KDF profile.

Embedded resources select their owning packages. Deleted/renamed paths are not
hidden by rename detection. Missing/deleted package ownership, unknown inputs,
module/workspace changes and CI configuration changes conservatively select all
Go packages, with the reason printed in the job log. An unavailable diff or
invalid Go graph fails the job rather than claiming no affected tests. A new
branch without a previous SHA also selects all packages. This broad fallback is
Go regression coverage, not the complete sprint gate: it still does not run the
production KDF, full CLI install checks or release artifact production.

Installer scripts and their fixture trigger their installer checks on all three
platforms; unrelated package edits do not. Selection regressions and the cheap
license consistency/rejection gate run on every feature revision. License
checks are not complete legal clearance. JSON selection evidence is retained as
a CI artifact. Newer runs cancel obsolete feature runs for the same event ref;
full sprint/release checks are not cancelled by this feature concurrency group.

Package/test import and embed graphs cannot infer arbitrary cross-package runtime
file/process dependencies. Unknown non-document inputs broaden selection; any
new runtime relationship not represented by these edges must be added explicitly
or conservatively broadened. Feature checks are not a claim of full readiness.

## End of sprint / release

At sprint completion, include `[ci:full]` in the pushed HEAD commit message.
GitHub's `contains` comparison is case-insensitive; use the lowercase spelling consistently. For example, add a separate message paragraph:

```sh
git commit -m "feat: complete the sprint" -m "[ci:full]"
```

The token may be in the subject or body. Only a push event evaluates its HEAD
commit message; PR checks remain diff-scoped. The explicit full run calls
`ci.yml` at that exact pushed SHA and skips duplicate scoped feature jobs.
Branch names, including `sprint/...`, do not request a full run. Do not mention
the token incidentally in an ordinary commit message: its presence is the opt-in.
A normal feature push cannot cancel a marked full run's separate concurrency group.

Manual full verification is also available through **Actions -> Full sprint CI ->
Run workflow**, selecting the branch/ref, or through the CLI:

```sh
gh workflow run ci.yml --ref <branch> -f source_ref=<exact-commit-sha>
```

Use background `gh run watch <run-id> --exit-status` for its result. GitHub may
require the manual trigger to be registered on the default branch first; the
explicit commit-token route works from the feature branch without a main merge.
No schedule or automatic unmarked per-feature full run is installed. `Full sprint CI` retains the complete native
Go matrix, separate full race suite, repeated SSH cancellation regression,
CLI/help/version/licenses/source-install checks, installer matrix, actual
production KDF profile and license policy gate. Its native CLI artifacts and
`workflow_call(source_ref)` interface remain available to the release workflow;
release still requires the full gate. This change does not approve a release.

A successful feature run is not a substitute for that full sprint/release result.
If branch protection requires the old full-job names, they remain sprint/release
requirements; do not silently mark them satisfied with scoped jobs or remove
required checks. Private infrastructure verification remains local.

Feature CI and the full workflow's native test matrix run the remote-MCP startup
and connected-bridge gates on Linux, Windows and macOS when relevant CLI sources
are selected (and unconditionally in the full workflow). The full workflow's
separate production-KDF full-profile job runs the same startup and connected
gates on Linux. Startup covers selector/refusal and prepared-launch cases;
connected acceptance uses a temporary private local TLS route overlay and
exercises the real launched stdio bridge. The source runner verifies complete
PASS and observed evidence and rejects top-level or scenario SKIP records.
Artifacts retain runner logs. These gates are source-authored; actual public
exact-SHA three-OS runtime receipts remain pending owner CI. Historical receipts
at `6913e5f` (runtime) and `07290ca` (archives) refer to distinct earlier
sources, not acceptance of a current revision. Dedicated task #359 remains
pending.

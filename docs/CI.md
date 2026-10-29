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

Run the existing `ci.yml` explicitly at sprint completion:

```sh
gh workflow run ci.yml --ref <branch> -f source_ref=<exact-commit-sha>
```

Use `gh run watch <run-id> --exit-status` for its result. GitHub may require the
manual trigger to be registered on the default branch first. Until then, an
explicit push of the completed revision to a `sprint/<name>` branch triggers the
same full gate from that revision, without a release, tag or default-branch
merge. Ordinary feature pushes exclude this sprint namespace. Do not create or
push such a branch until the sprint is actually ready for full verification.
No schedule or automatic per-feature full run is installed. `Full sprint CI` retains the complete native
Go matrix, separate full race suite, repeated SSH cancellation regression,
CLI/help/version/licenses/source-install checks, installer matrix, actual
production KDF profile and license policy gate. Its native CLI artifacts and
`workflow_call(source_ref)` interface remain available to the release workflow;
release still requires the full gate. This change does not approve a release.

A successful feature run is not a substitute for that full sprint/release result.
If branch protection requires the old full-job names, they remain sprint/release
requirements; do not silently mark them satisfied with scoped jobs or remove
required checks. Private infrastructure verification remains local.

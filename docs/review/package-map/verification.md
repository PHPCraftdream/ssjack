# Verification and claim boundaries

## Repository-defined CI (inspected, not run here)

- `.github/workflows/feature.yml:14-44` is the push/PR scoped workflow: tests selection regressions, calls `scripts/ci/plan.py plan` then `test`, and may build installer fixture when relevant (`:45-64`). License audit is separate (`:81-94`). A push commit containing `[ci:full]` skips scoped job and calls reusable `ci.yml` (`feature.yml:15-16,74-79`).
- `.github/workflows/ci.yml:22-29` defines full Go test jobs on Ubuntu, Windows, and macOS. Formatting checks target named Go trees (`:40-47`); CLI build/help/install checks are `:48-67`; test command is `:68-71`; installer fixture build/use is `:72-89`; Bash syntax check is `:90-92`.
- The full workflow's Go test command targets root, CLI, all internal packages, and `plugins/ssjack-ui` (`ci.yml:68-71`); race job repeats these (`:119-133`). Full-profile job opts into `SSJACK_TEST_FULL_KDF=1` and selects named vault/keyfile/app-store master profile tests (`:135-151`). Presence of workflow commands does not prove they ran.
- `scripts/ci/plan.py:15-58` maps changed inputs and computes reverse dependency closure; edges include `Imports`, `TestImports`, and `XTestImports` (`:44-56`). `plan.py:73-89` obtains graph through `go list`; it was not invoked. Plan/test modes can invoke git/subprocess, gofmt, and Go tests (`:92-139`); none were invoked in this review.

## Parent-supplied executed evidence (authoritative scope only)

Parent supplied four scoped public-CI evidence records, each with four successful jobs and the full gate skipped:

| Slice | Commit | Run | Permitted statement |
|---|---|---|---|
| Writer | `cd3697941913f63c850dfc3df92cf729ee5cb6b1` | `41040507916` | Scoped writer CI run passed its four jobs. |
| Pinning | `16e06ee646c723343763198a48b05bbed4563fc4` | `41042416835` | Scoped pinning CI run passed its four jobs. |
| Composed native synthetic delivery | `5d128dfce2782f80b7d44a217c7fd69171686ec1` | `41049932116` | Scoped composed native synthetic-delivery CI run passed its four jobs. |
| Placeholder | `4d76375ce8f7877b37644f90bf7c36c5681fcab3` | `41053650995` | Scoped placeholder CI run passed its four jobs. |

The inventory's per-package U status remains unknown; none of these four slice reports is attributed to an individual package. Parent reports the composed native synthetic test path executed, so a native consumer did receive synthetic data in that scoped run. Do not infer `TestAppstoreMasterFullProfile`/`TestSnapshotWriterFullKDF` real production KDF execution, package-wide gate coverage, product route completeness, human authorization, or full gate success.

## Review performed in this worktree

Read-only inspection covered local `CLAUDE.md`, `.github/workflows/ci.yml`, `scripts/ci/plan.py`, `go.mod`, package declarations/files, and relevant app-store, sink, placeholder, driver, plan-binding/admission source/tests. New material is confined to Markdown under `docs/review/package-map/`. No tests, builds, lint, typecheck, `go list`, Python scripts, formatter, or executable verification were run. No credential or `.rush/secrets` content was inspected.

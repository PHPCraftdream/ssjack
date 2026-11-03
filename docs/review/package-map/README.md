# Package map and evidence review

This review maps the Go package surface and identifies the smallest existing route toward a synthetic app-store-to-native-consumer vertical slice. It is static research, not an implementation or a security/production-readiness claim.

## Evidence discipline

- Source links below use repository-relative `path:line` notation and refer to this worktree's inspected files. Package inventory is based on source directories/package declarations and CI scope, not `go list` (not run).
- **Static wiring** means imports/calls visible in production source. **Authored test** means test code exists; it does not claim execution.
- **Parent-verified executed evidence** is only the explicitly supplied public-CI evidence listed in [verification](verification.md). It does not imply full-gate completion.
- **U** in inventory means package-level execution or selection is unknown. Parent evidence W/P/N/H applies only to writer/pinning/native/placeholder slices and is not attributed to packages.
- `feature.yml` is the normal push/PR workflow: scoped package selection/test matrix and a separate license job (`.github/workflows/feature.yml:14-44,81-94`). A push-only `[ci:full]` token dispatches reusable `ci.yml` instead (`feature.yml:74-79`); CI full/race/profile definitions in `ci.yml` describe gates, not proof they ran.
- **Unknown** means no conclusion is made from the available source or supplied evidence. No secrets/credentials or `.rush/secrets` content was inspected; no remote material was fetched.
- Inspected source baseline is full `HEAD` `4d76375ce8f7877b37644f90bf7c36c5681fcab3`, dated `2026-10-30 13:12:33 +0100` (read-only git show).
- `.github/workflows/feature.yml:14-44` provides scoped tests for push/PR; `.github/workflows/ci.yml` is the reusable full gate, and neither command definition proves execution. `tests/fixtures/installbinary` falls under `./...` test package expansion even though not separately named, and is also explicitly built by CI (`ci.yml:68-77`). `internal/appstoresink/testdata/consumer` is testdata, excluded from package traversal; its test builds it explicitly (`internal/appstorecrypto/record_edges_test.go:31-37`).

## Inventory convention

Inventory classifies 67 Go-containing directories by proposed-slice relevance and lists direct production and test import wiring. Counts: 60 regular packages with non-test Go source, five test-only packages, and two fixture-main packages (62 non-test-source directories including fixtures). All package-level execution status is U/unknown; slice evidence is not attributed to packages. See [product/app-store inventory](package-inventory.md), [continuation](package-inventory-2.md), and [package evidence](package-evidence.md).

## Findings

The existing app-store pipeline has substantial encrypted storage and pinned delivery code. `appstorecrypto.Master` derives via four sequential Argon2id calls with 1,048,576 KiB each (`internal/appstorecrypto/master.go:37-45,86-112`); `record.go:24,424-489` sets 1000 layers and loops over AES-GCM sealing/opening. `deliverCurrent` authenticates anchor state, checks exact store/snapshot/hash and pointer, pins/rechecks the snapshot, finds exact object metadata, checks consumer binding, streams, and finishes (`internal/appstorecrypto/delivery.go:30-101`); `streamPinnedObject` is `internal/appstorecrypto/record.go:41-121`. These operations are not evidence of human authorization.

A closed placeholder encoder/parser references only store/object/version/snapshot IDs and expressly resolves neither versions nor permissions (`internal/appstoreplaceholder/placeholder.go:18-42`). Fixed consumer configuration binds an exact reference, encoded/artifact/target/revision/purpose digests and expiry; source explicitly says supplied config is not proof of human enrollment or production authorization (`internal/appstoresink/sink.go:1-3,27-53`).

The CLI registers an existing native Node.js Clawwright app route and validates declared transport metadata (`cmd/ssjack/application.go:15-82`; `application_package.go:16-76`). That Node.js application subprocess route is distinct from the fixed native executable consumer sink in `internal/appstoresink`; neither is evidence of artifact provenance, human approval, enrollment, or authorization. The current `main.go` command parser (`cmd/ssjack/main.go:43-45,67-83,145-180`) and MCP bridge expose existing remote/app tools, not `resource_plan` or `plan_apply` tools. `NewDeclarativeServer` creates a server with no registered tools (`internal/bridge/mcp.go:51-53`); declarative identity dispatch answers only `session.describe` and otherwise denies (`internal/broker/declarative.go:86-100`).

Declarative building blocks are not all disconnected: `planadmission` imports `planbinding` directly (`internal/planadmission/checker.go:10-13`), and the checker delegates structural/freshness validation then checks a fixed schema (`checker.go:47-74`). But this helper chain has no demonstrated CLI/tool execution path; plan admission returns a digest, not an executable plan/freshness capability. `broker.DispatchIdentity` is descriptor-only; the declarative bridge registry is empty. Recommendations favor preserving unrelated schema, anchor, journal, crypto, adapter, and platform foundations from unrelated deepening; allow only minimal changes demonstrated necessary to unblock the vertical slice. These are recommendations, not approved decisions or broad platform expansion. Human decisions remain distinct from model recommendations.

## Local verification restriction

This review intentionally ran no tests, builds, lint, typecheck, `go list`, Python scripts, formatting executable, or other code verification. CI workflow definitions are inspected as source only. See [verification](verification.md).

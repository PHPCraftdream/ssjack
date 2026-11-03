# Go package inventory — remaining packages

Continuation of `package-inventory.md`. Status definitions: **supporting/frozen** and **disconnected/frozen** recommend preserving adjacent infrastructure without unrelated expansion; they are not approved decisions or unconditional bans. Permit only minimal changes demonstrated necessary to unblock the vertical slice, not broad platform expansion. All package-level execution/selection is **U** (unknown). Direct production wiring and test-only wiring are explicitly distinguished. Parent run IDs do not attach to packages.

| Package | Slice relevance and direct production wiring | Test-only wiring / representative authored test | Status |
|---|---|---|---|
| `internal/bridge` | Supporting/frozen existing MCP; imports application/broker/buildinfo/remote (`mcp.go:11-14`); CLI imports it (`cmd/ssjack/main.go:19`) | `mcp_test.go:18`; `declarative_test.go:34` tests empty registry | supporting/frozen; U |
| `internal/broker` | Supporting/frozen session broker; imports wire/enrollment (`broker.go:13`, `declarative.go:9-10`); CLI, bridge, application, apptransport, launch import it | `broker_test.go:26`, `declarative_test.go:18`; bridge declarative tests | supporting/frozen; U |
| `internal/buildinfo` | Supporting build identity; imported by CLI, bridge, and apptransport (not diagnostic) | `info_test.go:1` | supporting; U |
| `internal/canonicaljson` | Slice-critical canonicalizer; imported by placeholder, planbinding, planadmission, driverprotocol and enrollment/schema helpers | `canonical_test.go:1`; consumers have tests | slice-critical; U |
| `internal/declarativedescriptor` | Disconnected/frozen descriptor helper; imports canonicaljson/declarativeschemas (`descriptor.go:9-10`); no CLI/bridge production import found | descriptor/fixture tests | disconnected/frozen; U |
| `internal/declarativeschemas` | Disconnected/frozen schema/catalog; imports canonicaljson/domain digest (`schema.go:7`, `catalog.go:7`); descriptor imports it | `catalog_test.go:1`, fixtures | disconnected/frozen; U |
| `internal/diagnostic` | Supporting diagnostics; imports uiplugin (`local.go:11`); CLI imports diagnostic (`cmd/ssjack/diagnostic.go:11`) | `local_test.go:1` | supporting; U |
| `internal/domaindigest` | Supporting domain digest; imports canonicaljson (`digest.go:10`); enrollmentvalidator, planbinding, declarativeschemas import it | `digest_test.go:1` | supporting; U |
| `internal/driverframe` | Disconnected/frozen frame primitive; imported by driverprotocol, driverprocess, immutableexec | `frame_test.go:1`; protocol tests import it | disconnected/frozen; U |
| `internal/driverprocess` | Disconnected/frozen process protocol; imports frame/protocol (`process.go:13-14`); no CLI/bridge importer found | `process_test.go:1`, `process_extra_test.go:1` | disconnected/frozen; U |
| `internal/driverprotocol` | Disconnected/frozen bounded driver/schema protocol; imports canonicaljson/frame/text; enrollmentrecord, driverprocess, immutableexec, planadmission import it | `protocol_test.go:1`, schema tests; externalconformance/observepositive tests import it | disconnected/frozen; U |
| `internal/drivertext` | Supporting/frozen text parser; imported by canonicaljson and driverprotocol (`canonical.go:14`, `protocol.go:13`) | no package test file listed | supporting/frozen; U |
| `internal/enrollment` | Disconnected/frozen metadata/policy/snapshot; imported by broker, enrollmentrecord, launch | enrollment and platform FIFO tests; broker tests import it | disconnected/frozen; U |
| `internal/enrollmentauth` | Disconnected/frozen auth prerequisite; canonical prerequisite imports canonicaljson; enrollmentsigned imports it (`signed.go:9`) | `auth_test.go:1`, canonical prerequisite tests | disconnected/frozen; U |
| `internal/enrollmentrecord` | Disconnected/frozen record codec; imports driverprotocol/enrollment (`record.go:10-11`); no CLI importer found | `record_test.go:1`, `bounds_test.go:1` | disconnected/frozen; U |
| `internal/enrollmentsigned` | Disconnected/frozen signed record; imports enrollmentauth/enrollmentvalidator (`signed.go:9-10`); no CLI importer found | `signed_test.go:1`, `acceptance_test.go:1` | disconnected/frozen; U |
| `internal/enrollmentvalidator` | Disconnected/frozen ref/network validation; imports canonicaljson/domaindigest/externalschemasubset | `validator_test.go:1`, regression test; signed package imports it | disconnected/frozen; U |
| `internal/externalconformance` | Disconnected test support only; no non-test source | test files import driverframe/protocol | test-only; U |
| `internal/externalschemasubset` | Disconnected/frozen schema subset; imports canonicaljson (`schema.go:12`, `helpers.go:6`); enrollmentvalidator imports it | schema/equality/extended tests | disconnected/frozen; U |
| `internal/hooks` | Supporting existing hooks; imported by CLI and launch (`cmd/ssjack/main.go:23`, `launch.go:17`) | `install_test.go:1`, `remove_test.go:1` | supporting; U |
| `internal/immutableexec` | Disconnected/frozen execution primitive; imports driverprotocol/frame; no CLI/bridge importer found | Linux/unsupported implementation tests | disconnected/frozen; U |
| `internal/immutableexectest` | Disconnected test helper only; no non-test source | only Linux `paths_linux_test.go:1` | test-only; U |
| `internal/kdfgate` | Slice-critical KDF gate; imported by appstorecrypto/keyfile (`master.go:16`, `keyfile/crypto.go:14`) | `gate_test.go:1`; master tests import it | slice-critical; U |
| `internal/keyfile` | Supporting existing encrypted key formats; imports kdfgate; vault/rotation/CLI import it | `container_test.go:1`, full-profile test | supporting; U |
| `internal/launch` | Supporting command launch; imports broker/enrollment/hooks/uiplugin/wire (`launch.go:15-19`); CLI imports it | launch/identity/platform tests | supporting; U |
| `internal/legacy` | Supporting legacy pins; CLI migrate imports it (`cmd/ssjack/migrate.go:11`) | `pins_test.go:1` | supporting; U |
| `internal/observepositive` | Disconnected Linux test assertions only; no non-test source | three Linux tests; imports driverprotocol in test source | test-only; U |
| `internal/operationstore` | Disconnected/frozen operation persistence; no CLI/bridge importer found | store/parse/io tests | disconnected/frozen; U |
| `internal/planadmission` | Disconnected/frozen fixed schema checker; imports canonicaljson/driverprotocol/planbinding (`checker.go:10-12`); no CLI/bridge production importer found | `checker_test.go:51`; test also directly imports planbinding (`:13-15`) | disconnected/frozen; U |
| `internal/planbinding` | Disconnected/frozen structural binding helper; imports canonicaljson/domain digest (`binding.go:14-15`); production importer is planadmission only | `binding_test.go:55`, `window_test.go:13`; planadmission test also imports it | disconnected/frozen; U |
| `internal/recovery` | Supporting/frozen recovery machine; imported by recoveryjournal and recoverybinding | machine/edge/synthetic tests | supporting/frozen; U |
| `internal/recoverybinding` | Supporting/frozen recovery binding; imports recovery (`binding.go:11`) | binding/recover tests | supporting/frozen; U |
| `internal/recoveryintegration` | Supporting recovery tests only; no non-test source | Linux/unsupported integration tests | test-only; U |
| `internal/recoveryjournal` | Supporting/frozen recovery journal; imports recovery (`journal.go:9`, `quarantine.go:6`); no CLI app-store route found | journal/fault/unsupported tests; recoveryintegration tests | supporting/frozen; U |
| `internal/remote` | Supporting existing SSH; imports broker/wire/sshauth/keyfile; CLI/application/bridge import it | broad SSH/job/config tests | supporting; U |
| `internal/rotation` | Supporting existing vault/key rotation; imports keyfile/vault (`rotation.go:9-10`); CLI rotate imports it | rotation/integration tests | supporting; U |
| `internal/sshauth` | Supporting existing SSH auth; imported by remote/vault | `publickey_test.go:1` | supporting; U |
| `internal/uiplugin` | Supporting plugin installer; imports embedded `plugins/ssjack-ui` (`install.go:15`); launch and diagnostic import it | install/check tests (`install_test.go:1`, `check_test.go:1`) | supporting; U |
| `internal/vault` | Supporting existing encrypted credential vault; imports keyfile/sshauth; CLI and rotation import it | vault/policy/backup/upgrade/full-profile tests | supporting; U |
| `internal/wire` | Supporting Ktav wire protocol; imported by broker/application/apptransport/launch/remote | `wire_test.go:1`, Ktav tests | supporting; U |
| `plugins/ssjack-ui` (`ssjackui`) | Supporting embedded UI assets; imported by `internal/uiplugin/install.go:15` | no Go package test source listed; full CI includes package | supporting; U |
| `tests/fixtures/installbinary` (`main`) | Installer fixture, not slice; standalone `main.go:11`; under `./...` expansion and explicitly built by CI (`ci.yml:72-77`) | external installer scripts, no Go `_test.go` | fixture main; U |
| `internal/appstoresink/testdata/consumer` (`main`) | Native synthetic consumer fixture; referenced via explicit test build path (`record_edges_test.go:34`), no production importer | built by `nativeConsumerFixture` in test | fixture main; U |

## Reachability interpretation

The full CLI imports and registers the packages actually used by its command/tool paths (`cmd/ssjack/main.go:17-28`; `internal/bridge/mcp.go:51-119`). `planadmission` → `planbinding` is a real production helper edge, but neither is imported by CLI/bridge production sources; that is not an executable `resource_plan`/`plan_apply` route. `declarativedescriptor`, schemas, enrollment and driver layers have internal helper/test relationships but no command-reachable authorized apply path established by inspected imports.

## Recommendation boundary

Preserve unrelated schema, anchor, journal, crypto, adapter, and platform foundations from unrelated deepening. Permit only minimal changes demonstrated necessary to unblock the vertical slice; this recommendation is not an approved decision or broad platform expansion.

# Code layout rules

`tools/layoutlint` checks the shape of tracked code. Run it from anywhere inside
the checkout:

```sh
go run ./tools/layoutlint -report   # print every violation, exit 0
go run ./tools/layoutlint -strict   # print every violation, exit 1 if any
```

Exactly one mode is required. Linter failures (git unavailable, unreadable file,
bad flags) exit 2 in both modes. CI runs `-strict` in Feature CI and Full CI: a
violation fails the build. There is no baseline file and no list of allowed offenders.

## Rules

1. A code file has at most 1000 physical lines (`wc -l`: the number of `\n`; an
   unterminated last line counts; an empty file is 0).
2. A folder has at most 7 code files directly inside it. Subfolders are not
   counted. Test files (`_test.go`, `test_*.py`) are code files.

## What is code

- Extensions: `go py ps1 sh ts mts cts tsx js mjs cjs jsx rs`. Everything else
  (docs, md, json, yaml, txt, ...) is neither checked nor counted.
- Directories named `node_modules`, `dist`, `vendor`, `golden`, `testdata` are
  skipped at any depth.
- Directories named `fixtures` are not skipped: fixture code is code, and
  violations there are reported like any other.
- The file list is `git ls-files`: only tracked files. Tracked files missing from
  the working copy are skipped.

## CLI layout

`cmd/ssjack` is the single CLI facade (`package main`): the binary builds with
`go build ./cmd/ssjack` and tests with `go test ./cmd/ssjack/...`, and the facade holds only signal handling, exit
status and thin command entry points. All CLI implementation and CLI test code lives in
`cmd/ssjack/internal/*` subpackages, for example `agent`, `appstore`, `cli`,
`clitest`, `credential`, `declarative`, `help`, `helpsuite`, `keys`,
`launchguard`, `ownercmd`, `ownertest`, `shell`, `startup`,
`terminal`, `testsupport`,
`textadapter`, `transfercmd`, `transfertest` and `vaultcmd`. New CLI code goes
into the matching subpackage, not the facade. The scoped/full-profile CLI acceptance suites live in
`cmd/ssjack/internal/appstore`: the `package appstore_test` external test files,
including replay and owner tests, share the appstore test binary for self-exec
child tests; the Linux-only delivery suite lives in the separate
`cmd/ssjack/internal/appstore/delivery` test binary. remote-MCP acceptance is exercised by the
external tests in `cmd/ssjack/internal/agent` (files in `package agent_test`,
e.g. the connected-acceptance harness and full-profile remote startup tests);
the file and folder-count rules above apply to
the facade and every subpackage alike.

## Output

One line per violation, sorted by path, then the summary:

```text
<path>: <N> lines (limit 1000)
<folder>: <N> code files (limit 7)
layoutlint: <V> violations (<A> oversized files, <B> crowded folders) in <M> code files
```

The repository root folder is printed as `.`. All settings (extensions, skipped
directories, limits) are in `tools/layoutlint/config.go`; the pure logic is in
`layout.go` and is covered by table tests in `tools/layoutlint`.

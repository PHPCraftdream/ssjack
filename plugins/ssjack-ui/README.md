# ssjack-ui

Display-only Claude Code plugin for separate ssjack SSH command and result cards. Runtime assets are embedded into the ssjack Go executable. Normal users launch `ssjack claude -c`; the launcher installs and enables the local plugin automatically for its child harness.

## Runtime

The plugin unfolds `ToolGroup` rows containing ssjack calls, renders `ToolUse` as bordered command/result/cancellation cards, and suppresses duplicate `ToolResult` blocks because the complete result is already drawn in `ToolUse`.

It does not intercept tool execution or change tool inputs, stored output, permissions, the model's context, or SSH authentication. It uses no Node APIs, network requests, credential access, or background timers. MCP output is decoded from structured objects, text content blocks, JSON strings, and result wrappers. Control characters are escaped before display.

The Go launcher installs content-addressed copies under the project's ignored `.claude/ssjack-ui` directory. Managed source assets are verified before reuse; engine-generated type metadata may coexist with them. Old runtime copies are not deleted automatically.

## Compatibility

Requires Claude Code's function-hook plugin API with `ui.render`, `ToolGroup`, `ToolUse`, `ToolResult`, and `CLAUDE_CODE_PLUGIN_DIRS`. The authoring environment uses build 2.1.304. Other MCP clients do not automatically gain this interface.

Plugin manifests and registration metadata remain JSON because they are Claude Code interfaces, not ssjack-owned configuration formats.

## Development checks

Static validation:

```text
claude plugin validate ./plugins/ssjack-ui
```

Plugin tests, when explicitly authorized:

```text
claude plugin test ./plugins/ssjack-ui
```

Go installer, launcher, and legacy-hook cleanup tests, when explicitly authorized:

```text
go test ./internal/uiplugin ./internal/hooks ./internal/launch
```

The plugin tests exercise terminal and desktop rendering without opening real SSH connections. Runtime asset installation is tested separately from UI painting. Source changes reach embedded runtime copies only after rebuilding the Go executable.

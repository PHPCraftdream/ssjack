# ssjack-ui

Display-only Claude Code plugin for separate ssjack SSH command and result cards. Runtime assets are embedded into the ssjack Go executable. Normal users launch `ssjack claude -c`; the launcher installs and enables the local plugin automatically for its child harness.

## Runtime

The plugin unfolds `ToolGroup` rows containing ssjack calls, renders `ToolUse` as bordered command/result/cancellation cards, and suppresses duplicate `ToolResult` blocks because the complete result is already drawn in `ToolUse`.

It does not intercept tool execution or change tool inputs, stored output, permissions, the model's context, or SSH authentication. It uses no network requests, credential access, or background timers. Its only file access is a read of the single lifecycle log file described below, through the plugin file API. MCP output is decoded from structured objects, text content blocks, JSON strings, and result wrappers. Control characters are escaped before display.

## Bridge drop frame

The plugin reads `.claude/ssjack/lifecycle.log` in the session's working directory (files above 2 MiB are ignored; only the last 64 KiB is examined) and, in the band above the prompt, shows a red frame only after an attached connection has ended: a keeper `connection-end` with `attached=true`, a keeper `shutdown`, or a bridge `exit`. The frame stays until a new launch writes lines for a new session id.

The frame is display-only: nothing reads or acts on the log beyond this read, and editing it grants nothing. The plugin reads nothing else: no environment variables, tokens, session ids, or other paths.

Status: the parsing and frame text are covered by unit tests; the band wiring (`AbovePrompt`, `$.fs` read) follows the Claude Code plugin API but is not exercised by CI, which does not run the plugin's own tests.

# Claude Code mods, plugins, and the hook layer: security review

Question: can Claude Code mods/plugins (UI panels, status line, toasts, slash
commands, hooks on `PreToolUse`/`PostToolUse`/`PostToolUseFailure`) raise the
security of the agent–ssjack interaction? Answer in one line: they can raise
visibility and add client-side guard rails, but only keeper/server-side checks
are security boundaries. Details and ranking follow.

Sources: this repository's source and docs as cited per claim, plus public
Claude Code documentation (hooks and status line pages) as it read at the time
of writing; that documentation changes and was not re-verified when this file
was merged. Claims not grounded are marked **unknown**. Nothing was built, run,
or tested for this review.

## 1. What ssjack already does with hooks today

`ssjack install-hooks` writes hook entries into the project's
`.claude/settings.local.json` (`internal/hooks/install.go`). Installed rules:

| Event | Matcher | Action |
| --- | --- | --- |
| `PreToolUse` | `^mcp__ssjack__remote_exec$` | `pre` |
| `PostToolUse` | `^mcp__ssjack__(remote_exec\|remote_read\|remote_cancel)$` | `post` |
| `PostToolUseFailure` | `^mcp__ssjack__.*$` | `failure` |

Each rule invokes `ssjack hook <action>` with a 5-second timeout
(`install.go` `commandHook` with `Timeout: 5`). The installer refuses to write
when `.claude` is a symlink, `settings.local.json` is not a regular file, the
file is larger than 2 MiB, or the JSON does not parse; it merges idempotently
and replaces prior ssjack-owned entries pointing at a different executable
path. `ssjack hook` itself is described in `docs/README.md` as a
"bridge/compatibility endpoint, not a way to supply database passwords or grant
access."

`internal/hooks/remove.go` removes only these display hooks, matching the same
matchers and only entries run as `<executable> hook <action>` whose executable
base name is `ssjack`, `ssjack.exe` or `ssjack-next.exe` (`ownedDisplay`). It
leaves foreign hook groups intact.

What `ssjack hook pre|post|failure` actually enforces
(`internal/hooks/output.go`):

- **Nothing is blocked or allowed.** `Run` always returns
  `{"systemMessage": ...}` (or an empty one). There is no exit-code-2 deny
  path and no `permissionDecision`. The hooks are display-only.
- `pre`: for `mcp__ssjack__remote_exec`, formats `ssjack -> <target>` plus the
  command text as a `systemMessage`. Non-ssjack tools return empty output.
- `post`: extracts scalar fields (`job_id`, `stdout`, `stderr`, exit codes,
  eviction flags) from the tool response (`extract`, depth limit 8) and
  formats a human-readable summary for `remote_exec`, `remote_read`, and
  `remote_cancel`.
- `failure`: for any `mcp__ssjack__*` tool, surfaces the error text.
- Input is capped at 1 MiB; output is stripped of control/Unicode-format
  characters (`printable`) and truncated at 7000 runes.

There is **no secret-shaped-text screening anywhere in this path**. The keeper
performs its own server-side guards; what those are beyond "the database
password, private key, Argon2id outputs, and database master never become
bootstrap fields or MCP results" (`docs/BOOTSTRAP.md`, transport section) is
not enumerated in the files read and is **unknown** from this review. The
MCP boundary statement in `docs/README.md` is explicit: "`remote_*` ...
can expose command output. They are not restricted declarative execution or
universal secret redaction."

`plugins/ssjack-ui/` is a display-only plugin: it unfolds `ToolGroup` rows and
renders bordered command/result/cancel cards (`plugins/ssjack-ui/hooks/
register.tsx`), with control-character escaping before display
(`plugins/ssjack-ui/hooks/format.ts` `printable`). Its README states it "does
not intercept tool execution or change tool inputs, stored output,
permissions, the model's context, or SSH authentication." It is installed
automatically by the launcher into the project's ignored `.claude/ssjack-ui`
directory with content-addressed, verified copies (plugin README, Runtime
section). The embedded assets ship in the Go binary (`plugins/ssjack-ui/
assets.go`).

The bridge-drop diagnostic channel is
`<project>/.claude/ssjack/lifecycle.log` (owner-only, rotated at 1 MiB),
written by keeper and bridge (`docs/BOOTSTRAP.md`, "When the bridge drops").
The doc states: "The file is diagnostic only: nothing reads it back to make a
decision, so editing it grants nothing."

## 2. Threat model for a mod/plugin/hook

A hook, mod, or plugin runs inside the same Claude Code process tree, under
the same OS user, with the same environment as the agent. Per the public
hooks documentation: hooks are configured in `.claude/settings.json` /
`settings.local.json` / user settings / plugin `hooks.json`; the docs also
document `disableAllHooks` (any non-managed level can disable all
non-managed hooks), `--settings '{"disableAllHooks": true}'`, and that hook
config in project files "can be committed to the repo". A status line is
likewise a user-editable settings entry.

Concrete ways an evasive agent defeats a client-side mod/hook:

1. Edit `.claude/settings.local.json` (it is a plain JSON file the agent can
   write with the Edit/Write tools) to delete the ssjack hook entries.
2. Set `disableAllHooks: true` in project or local settings (public docs:
   project/local `disableAllHooks` overrides user-level `true`).
3. Edit or replace the hook script/executable path; ssjack's hooks point at
   the `ssjack` binary, but any installed hook or plugin script living in the
   repo is writable by the agent.
4. Invoke the risky action through a path the matcher does not match: ssjack's
   `PreToolUse` matcher covers only `mcp__ssjack__remote_exec`; nothing fires
   for `Bash`, direct `ssh` invocations the agent might make if it had
   credentials, or other MCP servers.
5. Read the process environment. Per `docs/BOOTSTRAP.md`: the child harness
   receives `SSJACK_ENV_TOKEN`, `SSJACK_SESSION`, `SSJACK_ENDPOINT`,
   `SSJACK_CERTIFICATE_SHA256`; "The bridge removes bootstrap fields from its
   own environment after reading them, but cannot remove inherited copies
   from the parent harness or other children", and "it does not make process
   environment theft impossible". A hook or mod, as a child of the harness,
   can inherit and exfiltrate the same material. (The hooks doc notes Claude
   Code removes `OTEL_*` variables from subprocesses and can scrub others
   under `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB`; whether ssjack's variables are
   covered is **unknown**.)
6. Spawn processes directly (the Bash tool), impersonate a hook, or run
   another `ssjack hook`-shaped process; nothing authenticates the hook
   caller to the keeper via this path.
7. Disable or remove the plugin (plugin enablement is settings state the
   agent can influence), or edit the unfolded runtime copies under
   `.claude/ssjack-ui` — the plugin README notes "Old runtime copies are not
   deleted automatically," so a stale copy could persist; whether the
   launcher re-verifies copies on every launch is **unknown** from the files
   read.
8. Race or spoof the single channel. `docs/BOOTSTRAP.md` single-channel
   threat model: "Anyone obtaining the child's full bootstrap environment
   before attachment can race the intended bridge", and "Processes sharing
   the same harness connection are not distinguished as individual models."
   A same-user mod cannot distinguish itself from the agent, and the keeper
   cannot tell them apart.

Conclusion: **the only real security boundaries are server/keeper-side
checks** — token single-use consumption at attachment, TLS pinning, loopback
binding, and whatever per-operation checks the keeper applies (the specifics
of the latter are **unknown** from the files read). Everything installable in
`settings.local.json` or the repo — hooks, mods, plugins, status line, slash
commands — is a guard rail or a visibility aid. `docs/AUDIT.md` states the
same principle generically: "Client usage labels are not remote
authorization."

## 3. Candidate uses, judged

| Candidate | Value | Cost | Failure mode |
| --- | --- | --- | --- |
| Trust indicator for channel state (bridge dropped) | High. Per `docs/BOOTSTRAP.md`, after the `ssjack mcp` child restarts the new one cannot re-attach (single-use token, closed listener); the harness reports the MCP server as disconnected. A persistent band/statusline line reading the state would stop the agent and user from treating ssjack calls as protected when they are going nowhere or to a different path. | Low: status line scripts get JSON session data on stdin (public statusline doc) and can shell out to check `lifecycle.log` or MCP server state. Exact programmatic bridge-state source: **unknown** (lifecycle.log is documented as diagnostic-only; nothing reads it back). | False confidence if the indicator is stale or editable in-repo; the agent can also edit a statusline script. Fail state must be "unknown", not "secure". |
| `PreToolUse` guard refusing commands that expose a secret path | Low as a boundary (Section 2: agent deletes the hook). Moderate as a guard rail for accidental — not adversarial — exfiltration. | Low. | **False sense of security** — the worst failure mode. Must be documented as advisory. |
| `PostToolUse` screening of tool output for secret-shaped text as a second layer behind the keeper | Marginal. The existing `post` hook already formats full output (`internal/hooks/output.go`); adding regex screening there is cheap. But `docs/README.md` says MCP tools are "not ... universal secret redaction" — screening heuristics produce false negatives for adversarial output and false positives for normal output. | Low implementation, ongoing false-positive cost. | Both false security (missed secret) and noise. A screen that "usually catches" secrets invites reduced keeper-side investment. |
| Show which host/account a command will run as before approval | Real visibility value; the existing `pre` hook already prints the target (`output.go`), and `plugins/ssjack-ui` renders `SSH COMMAND -> <target>`. Extending to account/policy metadata would need keeper-provided fields; whether such fields exist in the tool input is **unknown**. | Low. | Minimal; display can be wrong only if its source is wrong. |
| Surfacing keeper refusals (`failure` hook) | Real. Already implemented: `output.go` `failure` action prints `ssjack: <tool> failed` plus error class. Repeated refusals are a signal the agent is probing; a counter/band could surface that to the user. | None (exists); counting is small. | None significant, provided it stays display-only. |
| Detecting an unexpected second harness | Speculative. `docs/BOOTSTRAP.md` documents keeper events (`accept-refused`, `already-attached-or-stopped`) in lifecycle.log that would indicate attachment races. A hook could watch this log. But the log is explicitly not a decision input, and a same-user attacker can write it. | Medium. | Detects only honest accidents; adversarial reuse of the stolen environment is invisible to client-side detection. **Unknown** whether lifecycle.log content is sufficient to distinguish races from restarts. |
| Anything else grounded in reading | `plugins/ssjack-ui` already covers the main gap: separating ssjack command/result cards from ordinary agent output, with control-character escaping, so the user sees what was actually run remotely. Additional mod value would mostly duplicate this. | — | — |

## 4. What would NOT help or would widen attack surface

- **A hook that reads secrets.** A hook process inherits the harness
  environment (public hooks doc: "A hook process inherits the parent
  environment"). Building anything that reads or passes secret material into
  hooks hands the single-channel capability to another same-user process.
- **A plugin that talks to the keeper directly.** `docs/BOOTSTRAP.md`: the
  keeper binds access to the one connection that consumed the token and the
  listener closes; "A re-attach path would widen the trust boundary and is
  not implemented." A plugin-side keeper connection would require exactly
  that re-attach path, or a second credential channel — both rejected by the
  documented design.
- **Auto-approval of tool calls.** A `PreToolUse` hook that returns `allow`
  (or sets permission rules) removes the human from the loop that ssjack's
  whole model depends on; the public hooks doc shows hooks can return allow
  decisions, so this is technically possible and categorically wrong here.
- **Any mechanism giving the plugin secret material or network authority.**
  Follows from Sections 2 and 4 above: same-user code with secrets or network
  credentials is indistinguishable from a compromised agent.

## 5. Ranked recommendation

1. **Bridge/channel-state trust indicator** (visibility; highest ratio of
   value to risk). A statusline entry or mod band that surfaces "ssjack
   channel: attached / dropped / unknown", sourced from a keeper-provided
   state channel — not from editable repo files alone. Fail to "unknown",
   never to "secure". This directly serves `docs/BOOTSTRAP.md`'s warning that
   a dropped bridge is by design and non-recoverable mid-session.
2. **Counter for keeper refusals / repeated `failure` hook hits** (visibility;
   build on the existing `failure` path in `internal/hooks/output.go`).
   Low cost, no boundary claim.
3. **Keep and document the existing `pre`/`post` display hooks and
   `plugins/ssjack-ui` cards as advisory only.** Add one sentence to the
   install-hooks output or docs stating these are display guard rails, not
   enforcement, so the false-security failure mode is preempted.
4. **Leave alone:** secret-shaped-text screening in the `post` hook (marginal
   value, real false-confidence cost), second-harness detection (speculative,
   spoofable), any PreToolUse deny guard (delusory boundary).
5. **Never build:** plugin-to-keeper connectivity, hooks with access to
   secrets, hook-based auto-approval.

Ranking rationale: items 1–2 improve visibility; none of the client-side
items raise the security boundary, which remains keeper-side token
consumption, TLS pinning, loopback binding, and keeper-side per-operation
checks (specifics of the latter: **unknown** from the files read).

## Claim-to-source index

- Hook install rules, refusal conditions, 5 s timeout: `internal/hooks/install.go`.
- Display-only nature, message formats, 1 MiB input cap, 7000-rune truncation: `internal/hooks/output.go`.
- Removal scope and ownership match: `internal/hooks/remove.go`.
- Plugin display-only behavior, escaping, installation: `plugins/ssjack-ui/README.md`, `plugins/ssjack-ui/hooks/register.tsx`, `plugins/ssjack-ui/hooks/format.ts`, `plugins/ssjack-ui/assets.go`.
- Single-use token, bridge-drop behavior, lifecycle.log, single-channel threat model, environment inheritance limits: `docs/BOOTSTRAP.md`.
- "Client usage labels are not remote authorization"; MCP redaction limits: `docs/AUDIT.md`, `docs/README.md`.
- Hook configuration locations, `disableAllHooks`, `--settings`, exit codes, environment inheritance, allow decisions: public Claude Code hooks reference (docs.anthropic.com/en/docs/claude-code/hooks).
- Status line configuration and data: public Claude Code statusline doc (docs.anthropic.com/en/docs/claude-code/statusline).
- Marked **unknown**: exact keeper-side per-operation checks; programmatic bridge-state source suitable for an indicator; whether launcher re-verifies `.claude/ssjack-ui` runtime copies on every launch; whether keeper provides account/policy fields in tool input; whether `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB` covers ssjack's variables.

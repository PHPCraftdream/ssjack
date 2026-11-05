package main

import (
	"sort"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/ownercommand"
)

func init() { commands = append(commands, ownerHelpEntries()...) }

func ownerHelpEntries() []commandHelp {
	boundary := "Trusted input/output terminal required. Unlocks the database once, opens the same Bubble Tea form as the owner menu, applies one action and exits only after encrypted persistence. Supplied metadata fields are read-only; missing fields remain editable. Stored credentials, values and exact confirmations are terminal-only, never argv/environment. Existing database unlock alone also accepts the explicit --vault-password or SSJACK_VAULT_PASSWORD startup sources; see their disclosure warning. Escape, Ctrl+C or Cancel exits without applying an unsubmitted form. Failures may follow effects; inspect pending recovery before retrying. Global --vault/--server/--account/--vault-password precede owner; action options follow ACTION. No --interactive, profile, harness or mode options."
	result := []commandHelp{{"owner", "ssjack [--vault FILE] owner ACTION [OPTIONS]", "Run one owner-menu action with metadata parameters and secret prompts.", boundary + " Actions cover server/account/proxy edits, scoped secret changes, export/import, store linking and pending recovery. Existing ssh/check/rotate and root provisioning commands retain their separate authority boundaries.", []string{"ssjack owner add-server --name production --address host.example:22 --login operator --auth password", "ssjack owner edit-proxy --server production --type socks5 --address proxy.example:1080", "ssjack owner add-secret --scope global --name token", "ssjack owner import --file owner.zip"}}}
	for _, spec := range ownercommand.Specs() {
		var options []string
		for option := range spec.Options {
			options = append(options, "--"+option+" VALUE")
		}
		sort.Strings(options)
		scope := "No server selector."
		switch spec.Scope {
		case "server":
			scope = "Requires --server NAME. --account NAME supplies the new account for add-account only."
		case "account":
			scope = "Requires --server NAME --account NAME."
		case "mcp-server":
			scope = "Requires --server NAME from the remote MCP directory, not SSH. For add-mcp-account, --account names the new MCP account."
		case "mcp-account":
			scope = "Requires --server NAME --account NAME from the remote MCP directory, not SSH."
		case "secrets":
			scope = "Requires --scope global, or --scope server --server NAME. No scope fallback."
		case "secret":
			scope = "Requires --secret NAME and --scope global, or --scope server --server NAME. No scope fallback."
		case "export":
			scope = "--scope all (default), global, server or account; server/account scopes require --server NAME, account also requires --account NAME. Server/account exports include server-local values, never global fallback. Plaintext requires EXPORT PLAINTEXT in the form."
		}
		details := boundary + " " + scope + " Metadata options: " + strings.Join(options, ", ") + "."
		if strings.HasPrefix(spec.Scope, "mcp-") {
			details += " MCP tokens/passwords/header values are hidden terminal-only input. Primary credential decisions are keep (unchanged authentication/username), replace (new secret), or clear (none with empty username/secret). Remove requires REMOVE. No network requests, session launch or active-session adoption. MCP records are not included in owner ZIP exports/imports yet."
		}
		if spec.Action == "import" {
			details += " Archive password is hidden. Inspection always precedes metadata preview and exact IMPORT confirmation. A partial import is not success. Remaining plans are RAM-only; restart does not restore them."
		}
		if spec.Action == "pending" {
			details += " --action accepts retry-db, reconcile, resume-draft, cancel-draft, resume-import or abort-import. A new process cannot resume a lost RAM-only import plan."
		}
		if spec.Action == "edit-proxy" {
			details += " --type direct|socks5|http; address is host:port, not a URL. Proxy password is hidden; proxy-hop authentication is unencrypted. No direct fallback."
		}
		result = append(result, commandHelp{"owner " + spec.Action, "ssjack [--vault FILE] owner " + spec.Action + " [OPTIONS]", "Run " + spec.Action + " through the shared owner form.", details, []string{"ssjack help owner " + spec.Action}})
	}
	return result
}

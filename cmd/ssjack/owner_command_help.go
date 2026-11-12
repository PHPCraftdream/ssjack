package main

import (
	"sort"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/ownercommand"
)

func init() { commands = append(commands, ownerHelpEntries()...) }

func ownerHelpEntries() []commandHelp {
	boundary := "Trusted input/output terminal required. Unlocks the database once, opens the same Bubble Tea form as the owner menu, applies one action and exits only after encrypted persistence. Attaches to a live keeper through authenticated native IPC; only a proven absent endpoint permits standalone control. Busy, unsafe, authentication or transport failures never trigger standalone fallback. Helper exit detaches without closing the keeper. Supplied metadata fields are read-only; missing fields remain editable. Stored credentials, values and exact confirmations are terminal-only, never argv/environment. Existing database unlock alone also accepts the explicit --vault-password or SSJACK_VAULT_PASSWORD startup sources; see their disclosure warning. Escape, Ctrl+C or Cancel exits without applying an unsubmitted form. Failures may follow effects; inspect pending recovery before retrying. Global --vault/--server/--account/--vault-password precede owner; action options follow ACTION. No --interactive, profile, harness or mode options."
	result := []commandHelp{{"owner", "ssjack [--vault FILE] owner ACTION [OPTIONS]", "Run one owner-menu action with metadata parameters and secret prompts.", boundary + " Actions cover server/account/proxy edits, scoped secret changes, export/import, store linking and pending recovery. Existing ssh/check/rotate and root provisioning commands retain their separate authority boundaries.", []string{"ssjack owner add-server --name production --address host.example:22 --login operator --auth password", "ssjack owner edit-proxy --server production --type socks5 --address proxy.example:1080", "ssjack owner add-secret --scope global --name token", "ssjack owner import --file owner.zip"}}, {"owner rotate-key", "ssjack [--vault FILE] owner rotate-key --server NAME --account NAME [--recover [--cancel-prepared] | --archive-completed]", "Rotate one selected owner SSH account through keeper-backed control.", "Separate trusted-terminal route, excluded from owner-menu parity. Requires a hidden owner database unlock independent of startup password options/environment, exact selected server/account, displayed metadata and a hidden exact confirmation before remote addition. --recover for an unknown add outcome displays the exact verify-only confirmation and, on acceptance, verifies with the pending key and commits in the same invocation; it never re-adds an unknown key. --recover --cancel-prepared displays the exact CANCEL-PREPARED phrase and, on acceptance, claims and cancels a prepared no-effect orphan in the same invocation, with no remote effects; no earlier claim invocation is required. Repeated inherited root --server/--account selectors remain last-wins; duplicate action-local selectors are rejected. Strict duplicate detection of inherited selectors requires the original raw argv at the root FlagSet.Parse seam in main.go. The old remote key remains. Completed rotation journals require an explicit --archive-completed action before another prepare. It displays and binds the retained operation, plan, selected server/account/profile, base and commit revisions, commit digest, endpoints, key fingerprints, pins and saved revision in the hidden exact ARCHIVE confirmation; after success it reports the encrypted recovery path and digest. The archived receipt retains selected identity and immutable commit proof while releasing endpoint and key material; the archived ciphertext digest may differ from the historical commit digest. Archiving never retires a key or prepares another rotation; invoke rotate-key separately. Completion verifies selected login and persistence, not adoption by every agent; no sessions/jobs restart or terminate. Exact-source public CI acceptance pending.", []string{"ssjack owner rotate-key --server production --account deploy", "ssjack owner rotate-key --server production --account deploy --recover"}}}
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
			scope = "--scope all (default), global, server, account or mcp; server/account scopes require --server NAME, account also requires --account NAME. --scope mcp requires explicit --mcp-accounts ID[,ID...]. MCP account IDs are listed in the shared form with names, authentication types and endpoints. Other scopes can combine their SSH/app selection with --mcp-accounts; blank excludes MCP. Server/account exports include server-local values, never global fallback. Plaintext requires EXPORT PLAINTEXT in the form."
		}
		details := boundary + " " + scope + " Metadata options: " + strings.Join(options, ", ") + "."
		if strings.HasPrefix(spec.Scope, "mcp-") {
			details += " MCP tokens/passwords/header values are hidden terminal-only input. Primary credential decisions are keep (unchanged authentication/username), replace (new secret), or clear (none with empty username/secret). Remove requires REMOVE. No network requests, session launch or active-session adoption. Explicit MCP account selections are included in archive preview/export; no implicit all-MCP selection."
		}
		if spec.Action == "import" {
			details += " Archive password is hidden. Inspection always precedes metadata preview and exact IMPORT confirmation. A partial import is not success. Remaining plans are RAM-only in the coordinator; coordinator restart does not restore them. Helper disconnect drops only no-effect state; retained partial effects require explicit recovery against the displayed revision and PlanID."
		}
		if spec.Action == "pending" {
			details += " --action accepts retry-db, reconcile, resume-draft, cancel-draft, resume-import or abort-import. An attached helper can explicitly recover a retained partial plan after reading its current revision and PlanID. A coordinator restart loses its RAM-only import plan; a new process cannot reconstruct that lost plan."
		}
		if spec.Action == "edit-proxy" {
			details += " --type direct|socks5|http; address is host:port, not a URL. Proxy password is hidden; proxy-hop authentication is unencrypted. No direct fallback."
		}
		examples := []string{"ssjack help owner " + spec.Action}
		if spec.Action == "export" {
			examples = append(examples, "ssjack owner export --scope mcp --mcp-accounts ACCOUNT_ID[,ACCOUNT_ID...] --destination mcp.zip")
		}
		result = append(result, commandHelp{"owner " + spec.Action, "ssjack [--vault FILE] owner " + spec.Action + " [OPTIONS]", "Run " + spec.Action + " through the shared owner form.", details, examples})
	}
	return result
}

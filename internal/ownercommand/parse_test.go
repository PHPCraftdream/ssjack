package ownercommand

import (
	"errors"
	"strings"
	"testing"
)

func TestParseAcceptsMetadataAndExplicitScopes(t *testing.T) {
	for _, args := range [][]string{
		{"add-server", "--name=production", "--address", "example.invalid:22", "--account", "main", "--auth", "password"},
		{"add-account", "--server", "production", "--account", "second", "--key-file", "synthetic-key.pem"},
		{"edit-secret", "--scope", "server", "--server", "production", "--secret", "token"},
		{"export", "--scope", "global", "--destination", "synthetic.zip"},
		{"export"}, {"import", "--file", "synthetic.zip"}, {"pending", "--action", "resume-import"},
		{"add-mcp-server", "--name", "docs", "--url", "https://docs.invalid/mcp"},
		{"add-mcp-account", "--server", "docs", "--account", "work", "--auth", "bearer", "--credential-action", "replace"},
		{"edit-mcp-account", "--server", "docs", "--account", "work", "--auth", "basic", "--login", "operator", "--enabled", "false", "--credential-action", "keep"},
		{"edit-mcp-header", "--server", "docs", "--account", "work", "--header", "X-Api-Key", "--header-action", "clear"},
	} {
		request, err := Parse(args, "", "")
		if err != nil || request.Action != args[0] {
			t.Fatalf("metadata command rejected: %s", args[0])
		}
		if strings.Contains(strings.Join(args, " "), "--key-file") && request.Fields["Authentication"] != "key" {
			t.Fatal("key-file did not bind key authentication")
		}
	}
	if _, err := Parse([]string{"edit-account"}, "production", "main"); err != nil {
		t.Fatal(err)
	}
}

func TestParseRejectsAmbiguitySecretInputsAndConfirmationBypass(t *testing.T) {
	for _, args := range [][]string{
		nil, {"unknown"}, {"add-server", "--password", "synthetic"},
		{"add-secret", "--scope", "global", "--value", "synthetic"},
		{"import", "--archive-password", "synthetic"}, {"link", "--master", "synthetic"},
		{"remove-secret", "--scope", "global", "--secret", "token", "--confirmation", "REMOVE"},
		{"export", "--yes"}, {"export", "--format", "plaintext", "--confirmation", "EXPORT PLAINTEXT"},
		{"edit-server"}, {"edit-account", "--server", "production"},
		{"edit-secret", "--secret", "token"}, {"add-secret", "--scope", "server"},
		{"add-secret", "--scope", "global", "--server", "production"},
		{"export", "--scope", "all", "--server", "production"},
		{"edit-proxy", "--server", "production", "--type", "https"},
		{"pending", "--action", "automatic-replay"},
		{"add-server", "--auth", "password", "--key-file", "synthetic.pem"},
		{"add-server", "--name", "first", "--name", "second"},
		{"add-server", "--name", "first\x1b[31m"},
		{"import", "--file"}, {"import", "--file", strings.Repeat("x", 16385)},
		{"edit-mcp-server"}, {"edit-mcp-account", "--server", "docs"},
		{"add-mcp-account", "--server", "docs", "--auth", "oauth"},
		{"edit-mcp-server", "--server", "docs", "--enabled", "yes"},
		{"edit-mcp-account", "--server", "docs", "--account", "work", "--credential", "synthetic"},
		{"edit-mcp-header", "--server", "docs", "--account", "work", "--header-value", "synthetic"},
		{"edit-mcp-header", "--server", "docs", "--account", "work", "--header-action", "keep"},
		{"remove-mcp-server", "--server", "docs", "--confirmation", "REMOVE"},
	} {
		_, err := Parse(args, "", "")
		if !errors.Is(err, ErrArguments) {
			t.Fatalf("unsafe or ambiguous input was accepted: action=%q", args)
		}
		if err.Error() != ErrArguments.Error() {
			t.Fatal("parser echoed an argument value")
		}
	}
	if _, err := Parse([]string{"edit-account", "--server", "production"}, "production", "main"); !errors.Is(err, ErrArguments) {
		t.Fatal("duplicate global and local selection accepted")
	}
}

func TestPublicOptionsCannotSupplySecretsOrApproval(t *testing.T) {
	seen := make(map[string]bool)
	for _, spec := range Specs() {
		if seen[spec.Action] {
			t.Fatal("duplicate owner action")
		}
		seen[spec.Action] = true
		for option, label := range spec.Options {
			if label == "Confirmation" || label == "MCP credential" || label == "Header credential" || label == "Value" || label == "Archive password" || label == "Proxy password" || label == "Store unlock secret" || (label == "Credential" && option != "key-file") {
				t.Fatalf("secret or approval has an argv option: %s", option)
			}
		}
	}
}

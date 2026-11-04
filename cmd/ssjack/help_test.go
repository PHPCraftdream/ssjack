package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEveryCommandHasDetailedHelpAndExamples(t *testing.T) {
	seen := make(map[string]bool)
	for _, entry := range commands {
		if seen[entry.Name] || entry.Name == "" || entry.Usage == "" || entry.Summary == "" || entry.Details == "" || len(entry.Examples) == 0 {
			t.Fatalf("incomplete or duplicate command documentation: %q", entry.Name)
		}
		seen[entry.Name] = true
		var output bytes.Buffer
		args := append([]string{"help"}, strings.Fields(entry.Name)...)
		if handled, err := handleHelp(args, &output); !handled || err != nil {
			t.Fatalf("help %s: %t %v", entry.Name, handled, err)
		}
		for _, fragment := range []string{"Usage: " + entry.Usage, entry.Summary, "Examples:", entry.Examples[0]} {
			if !strings.Contains(output.String(), fragment) {
				t.Fatalf("help %s is missing %q", entry.Name, fragment)
			}
		}
	}
}

func TestHelpDoesNotConsumeHarnessArguments(t *testing.T) {
	for _, args := range [][]string{
		{"run", "claude", "--help"},
		{"run", "program", "key", "--help"},
		{"claude", "--help"},
		{"text-adapter", "serve", "grant", "program", "--help"},
		{"text-adapter", "serve-stream", "grant", "program", "--help"},
	} {
		if handled, err := handleHelp(args, &bytes.Buffer{}); handled || err != nil {
			t.Fatalf("harness help was intercepted: %v", args)
		}
	}
	for _, args := range [][]string{{"ssh", "--help"}, {"run", "--help"}, {"key", "export", "--help"}, {"vault", "restore", "--help"}, {"mcp", "--help"}} {
		if handled, err := handleHelp(args, &bytes.Buffer{}); !handled || err != nil {
			t.Fatalf("command help was not recognized: %v", args)
		}
	}
	if handled, err := handleHelp([]string{"help", "unknown"}, &bytes.Buffer{}); !handled || err == nil {
		t.Fatal("unknown help topic was accepted")
	}
}

func TestHelpAndVersionNeverOpenVault(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.ssjack.ktav")
	for _, entry := range commands {
		args := []string{"--vault", missing, "help"}
		args = append(args, strings.Fields(entry.Name)...)
		if code, err := run(context.Background(), args); code != 0 || err != nil {
			t.Fatalf("authenticated help or invalid routing for %s: %d %v", entry.Name, code, err)
		}
	}
	if code, err := run(context.Background(), []string{"--vault", missing, "--version"}); code != 0 || err != nil {
		t.Fatalf("version tried to open credentials: %d %v", code, err)
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatal("informational commands created credentials")
	}
}

func TestOwnerAndTextHelpStateActualBoundaries(t *testing.T) {
	for topic, fragments := range map[string][]string{
		"--interactive":                {"even for one point", "key-file", "hidden-password", "EXPORT PLAINTEXT", "IMPORT", "RAM-only", "Windows", "SOCKS5", "HTTP CONNECT", "no environment proxy", "unencrypted"},
		"--server":                     {"conflicts with -p", "exactly one account", "never connect automatically"},
		"text-adapter":                 {"Linux/amd64", "separate registry", "unknown", "not adoption"},
		"text-adapter serve-stream":    {"--stream-references PATH", "never both", "EOF", "no raw tools"},
		"vault migrate-directory":      {"MIGRATE DIRECTORY", "never switches the default path", "unchanged SOURCE"},
		"text-adapter register-stream": {"64 MiB", "32 KiB", "16", "separate"},
	} {
		entry := findHelp(topic)
		if entry == nil {
			t.Fatalf("missing current help topic %q", topic)
		}
		text := strings.ToLower(entry.Details)
		for _, fragment := range fragments {
			if !strings.Contains(text, strings.ToLower(fragment)) {
				t.Fatalf("help %s omits boundary %q", topic, fragment)
			}
		}
	}
	for _, mode := range []string{"serve", "serve-stream"} {
		var out bytes.Buffer
		if ok, err := handleHelp([]string{"text-adapter", mode, "--help"}, &out); !ok || err != nil || !strings.Contains(out.String(), "Usage:") {
			t.Fatalf("text-adapter %s help failed: %v", mode, err)
		}
	}
}

func TestRootHelpListsPrimaryWorkflows(t *testing.T) {
	var output bytes.Buffer
	printRootHelp(&output)
	for _, fragment := range []string{"ssjack ssh", "ssjack run claude -c", "ssjack add", "--vault FILE", "--version", "doctor", "rotate", "hostkey", "ssjack --interactive", "--server NAME", "--account NAME", "--mode full|declarative", "--enrollment-metadata", "--policy-snapshot", "--enrollment-identity", "text-adapter", "IMPORT"} {
		if !strings.Contains(output.String(), fragment) {
			t.Fatalf("root help is missing %q", fragment)
		}
	}
}

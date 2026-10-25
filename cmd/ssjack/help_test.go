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
		{"run", "home", "claude", "--help"},
		{"run", "home", "program", "key", "--help"},
		{"claude", "--help"},
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

func TestRootHelpListsPrimaryWorkflows(t *testing.T) {
	var output bytes.Buffer
	printRootHelp(&output)
	for _, fragment := range []string{"ssjack ssh home", "ssjack run home claude -c", "ssjack add home", "--vault FILE", "--version", "doctor", "rotate", "hostkey"} {
		if !strings.Contains(output.String(), fragment) {
			t.Fatalf("root help is missing %q", fragment)
		}
	}
}

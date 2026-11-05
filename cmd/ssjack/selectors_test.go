package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"io"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/application"
	"github.com/PHPCraftdream/ssjack/internal/launch"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func TestStartupSelectorsRejectConflictsBeforeUnlock(t *testing.T) {
	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"--account", "deploy", "ssh"}, "--account requires --server"},
		{[]string{"--server", "production", "-p", "main", "ssh"}, "conflicts with --profile/-p"},
		{[]string{"--server", "", "ssh"}, "target name must"},
		{[]string{"--server", "production", "--account", "", "ssh"}, "target name must"},
		{[]string{"--server", "../invalid", "ssh"}, "target name must"},
		{[]string{"--server", "production", "list"}, "use --interactive for directory editing"},
		{[]string{"--server", "production", "text-adapter", "register"}, "use --interactive for directory editing"},
		{[]string{"--server", "production", "appstore", "put"}, "use --interactive for directory editing"},
		{[]string{"--server", "production", "--generate-key", "unused"}, "use --interactive for directory editing"},
		{[]string{"--server", "production", "--mode", "declarative", "run", "claude"}, "use --interactive for directory editing"},
		{[]string{"--profile", "@production/deploy", "ssh"}, "target name must"},
		{[]string{"--server", "production"}, "specify a command"},
	} {
		if code, err := run(context.Background(), test.args); code != 1 || err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("selector rejection did not occur before unlock: %v", test.args)
		}
	}
	flags := flag.NewFlagSet("selection", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	profile := "main"
	server := flags.String("server", "", "")
	account := flags.String("account", "", "")
	flags.StringVar(&profile, "p", "main", "")
	if err := flags.Parse([]string{"--server", "production", "--account", "deploy"}); err != nil {
		t.Fatal(err)
	}
	selector, named, err := startupSelection(flags, profile, *server, *account)
	if err != nil || !named || selector != "@production/deploy" {
		t.Fatal("explicit named selectors lost their exact selection")
	}
}

func TestNamedCheckReachesCredentialUnlockWithoutLegacyNameRejection(t *testing.T) {
	input, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	previous := os.Stdin
	os.Stdin = input
	defer func() { os.Stdin = previous }()
	code, err := run(context.Background(), []string{"--server", "production", "--account", "deploy", "check"})
	if code != 1 || err == nil || !strings.Contains(err.Error(), "an interactive terminal is required") {
		t.Fatal("named check was rejected as a legacy profile or bypassed trusted-terminal unlock")
	}
}

func TestNamedCredentialSelectionNeverFallsBackAcrossAccounts(t *testing.T) {
	key, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public())
	if err != nil {
		t.Fatal(err)
	}
	v := vault.New()
	defer v.Close()
	v.Version, v.Servers, v.Secrets = 2, make(map[string]vault.Server), make(map[string]vault.SecretBinding)
	target := vault.Target{Address: "example.invalid:22", User: "deploy", Password: []byte("synthetic-deploy-password"), HostKeys: []string{string(ssh.MarshalAuthorizedKey(key))}}
	server, err := v.AddServer("production", "deploy", target)
	if err != nil {
		t.Fatal(err)
	}
	first, err := chooseCredential(v, "@production")
	if err != nil || first != v.Servers[server].Accounts["deploy"] {
		t.Fatal("single-account server did not resolve exactly")
	}
	target.User, target.Password = "maintenance", []byte("synthetic-maintenance-password")
	if err := v.SetAccount(server, "maintenance", target); err != nil {
		t.Fatal(err)
	}
	if _, err := chooseCredential(v, "@production"); err == nil || !strings.Contains(err.Error(), "--account") {
		t.Fatal("ambiguous server silently chose an account")
	}
	for _, account := range []string{"deploy", "maintenance"} {
		selected, err := chooseCredential(v, "@production/"+account)
		if err != nil || selected != v.Servers[server].Accounts[account] {
			t.Fatal("named account resolved another credential identity")
		}
	}
	for _, selector := range []string{"@missing", "@Production/deploy", "@production/missing", "@production/", "@production/deploy/extra"} {
		if _, err := chooseCredential(v, selector); err == nil {
			t.Fatal("unknown or malformed selection fell back")
		}
	}
	legacy := vault.New()
	defer legacy.Close()
	if _, err := chooseCredential(legacy, "@production/deploy"); err == nil || !strings.Contains(err.Error(), "directory payload schema v2") {
		t.Fatal("legacy database silently acquired directory semantics")
	}
}

func TestNamedClawwrightBindingUsesExactlyTheResolvedCredential(t *testing.T) {
	options := &application.Options{Profile: "@production/deploy"}
	if err := bindNamedApplication(options, []string{"resolved-credential"}); err != nil || options.Profile != "resolved-credential" {
		t.Fatal("application retained a server label instead of the authenticated credential identity")
	}
	for _, targets := range [][]string{nil, {"first", "second"}, {"@production/deploy"}} {
		if err := bindNamedApplication(options, targets); err == nil {
			t.Fatal("application accepted an ambiguous or unresolved credential scope")
		}
	}
}

func TestNamedHarnessUsesResolvedCredentialScope(t *testing.T) {
	previousLoad, previousLaunch := cliLoadAgentCredentials, cliLaunchRun
	defer func() { cliLoadAgentCredentials, cliLaunchRun = previousLoad, previousLaunch }()
	loaded, launched := false, false
	cliLoadAgentCredentials = func(_ context.Context, path, selector string) (remote.Runner, remote.StreamRunner, []string, error) {
		if selector != "@production/deploy" {
			t.Fatal("harness lost named selectors")
		}
		loaded = true
		return func(context.Context, string, string, io.Writer, io.Writer) (int, error) {
			t.Fatal("selector test unexpectedly ran SSH")
			return 1, nil
		}, nil, []string{"resolved-credential"}, nil
	}
	cliLaunchRun = func(_ context.Context, options launch.Options) (int, error) {
		launched = true
		if len(options.Command) != 1 || options.Command[0] != "synthetic-harness" {
			t.Fatal("named selection changed harness arguments")
		}
		return 0, nil
	}
	code, err := run(context.Background(), []string{"--server", "production", "--account", "deploy", "run", "synthetic-harness"})
	if code != 0 || err != nil || !loaded || !launched {
		t.Fatal("explicit named harness dispatch failed")
	}
}

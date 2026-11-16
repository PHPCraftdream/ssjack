package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/application"
)

// syntheticApp creates a registered-application directory whose executable is
// a never-executed fixture.
func syntheticApp(t *testing.T, name string) string {
	t.Helper()
	dir := t.TempDir()
	executable := "synthetic-app"
	if runtime.GOOS == "windows" {
		executable += ".exe"
	}
	if err := os.WriteFile(filepath.Join(dir, executable), []byte("fixture, never executed"), 0o700); err != nil {
		t.Fatal(err)
	}
	descriptor := `{"format":"ssjack-app-v1","name":"` + name + `","launch":{"executable":"` + executable + `","args":["entry"]},"commands":{"observational":["status"]}}`
	if err := os.WriteFile(filepath.Join(dir, application.DescriptorFile), []byte(descriptor), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestApplicationRegistrationWithoutUnlock(t *testing.T) {
	if options, err := registeredApplications(nil, "", "main", nil); err != nil || options != nil {
		t.Fatal("standalone keeper unexpectedly registered an application")
	}
	first := syntheticApp(t, "first")
	if _, err := registeredApplications(nil, "incus:guest:operator", "main", nil); err == nil {
		t.Fatal("route without an application accepted")
	}
	for _, route := range []string{"incus", "incus:guest", "ssh:guest:operator", "incus::operator", "incus:guest:", "incus:guest;id:operator", "incus:guest:--root", "incus:guest:operator:extra"} {
		if _, err := registeredApplications([]string{first}, route, "main", nil); err == nil {
			t.Fatalf("invalid route accepted: %q", route)
		}
	}
	options, err := registeredApplications([]string{first}, "incus:guest:operator", "fixed", nil)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := filepath.EvalSymlinks(first)
	if err != nil {
		t.Fatal(err)
	}
	if options.Profile != "fixed" || options.Container != "guest" || options.User != "operator" || len(options.Apps) != 1 {
		t.Fatalf("registration changed fixed inputs: %+v", options)
	}
	app := options.Apps[0]
	if app.Name != "first" || app.Directory != canonical || !filepath.IsAbs(app.Executable) || !filepath.IsAbs(app.Workdir) || len(app.Args) != 1 || app.Args[0] != "entry" || len(app.Observational) != 1 || app.Observational[0] != "status" {
		t.Fatalf("descriptor was not resolved: %+v", app)
	}
	plain, err := registeredApplications([]string{first}, "", "main", nil)
	if err != nil || plain.Container != "" || plain.User != "" {
		t.Fatal("registration without a route gained one")
	}
	second := syntheticApp(t, "second")
	several, err := registeredApplications([]string{first, second}, "", "main", nil)
	if err != nil || len(several.Apps) != 2 || several.Apps[0].Name != "first" || several.Apps[1].Name != "second" {
		t.Fatalf("several applications were not registered in order: %+v %v", several, err)
	}
}

func TestApplicationRegistrationRefusals(t *testing.T) {
	first := syntheticApp(t, "same")
	if _, err := registeredApplications([]string{first, syntheticApp(t, "same")}, "", "main", nil); err == nil || !strings.Contains(err.Error(), "same application name") {
		t.Fatalf("duplicate application name accepted: %v", err)
	}
	if _, err := registeredApplications([]string{first, first}, "", "main", nil); err == nil {
		t.Fatal("one directory registered twice")
	}
	if _, err := registeredApplications([]string{t.TempDir()}, "", "main", nil); err == nil {
		t.Fatal("directory without a descriptor accepted")
	}
	if _, err := registeredApplications([]string{""}, "", "main", nil); err == nil {
		t.Fatal("empty directory registered the working directory")
	}
	if _, err := registeredApplications([]string{filepath.Join(first, "missing")}, "", "main", nil); err == nil {
		t.Fatal("missing directory accepted")
	}
	many := make([]string, application.MaxApplications+1)
	for i := range many {
		many[i] = first
	}
	if _, err := registeredApplications(many, "", "main", nil); err == nil {
		t.Fatal("unbounded registration accepted")
	}
	var flags appDirectoryFlags
	if flags.Set("") == nil {
		t.Fatal("empty --app accepted")
	}
	if err := flags.Set("one"); err != nil {
		t.Fatal(err)
	}
	if err := flags.Set("two"); err != nil || len(flags) != 2 || flags.String() != "one two" {
		t.Fatal("--app is not repeatable")
	}
}

func TestApplicationStartupValidationPrecedesCredentials(t *testing.T) {
	old := cliLoadAgentCredentials
	defer func() { cliLoadAgentCredentials = old }()
	called := false
	cliLoadAgentCredentials = func(context.Context, string, string) (*agentCredentials, error) {
		called = true
		return nil, errors.New("credentials reached")
	}
	vault := filepath.Join(t.TempDir(), "missing.vault")
	broken := t.TempDir()
	if err := os.WriteFile(filepath.Join(broken, application.DescriptorFile), []byte(`{"format":"ssjack-app-v1","name":"broken","launch":{"executable":"absent"},"extra":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--vault", vault, "--app-route", "incus:guest:operator", "run", "harness"},
		{"--vault", vault, "--app", broken, "run", "harness"},
		{"--vault", vault, "--app", t.TempDir(), "run", "harness"},
		{"--vault", vault, "--app", syntheticApp(t, "ok"), "--app-route", "incus:guest", "run", "harness"},
		{"--vault", vault, "--app", syntheticApp(t, "twin"), "--app", syntheticApp(t, "twin"), "run", "harness"},
	} {
		if code, err := run(context.Background(), args); code == 0 || err == nil || err.Error() == "credentials reached" {
			t.Fatalf("args %v: %d %v", args, code, err)
		}
	}
	if called {
		t.Fatal("invalid application registration reached credentials")
	}
	code, err := run(context.Background(), []string{"--vault", vault, "--app", syntheticApp(t, "ok"), "--app-route", "incus:guest:operator", "run", "harness"})
	if code == 0 || err == nil || err.Error() != "credentials reached" || !called {
		t.Fatalf("valid registration did not proceed to credentials: %d %v", code, err)
	}
}

func TestApplicationFlagsRefusedOutsideFullMode(t *testing.T) {
	vault := filepath.Join(t.TempDir(), "missing.vault")
	for _, args := range [][]string{
		{"--mode", "declarative", "--app", syntheticApp(t, "ok"), "--vault", vault, "run", "driver"},
		{"--mode", "declarative", "--app-route", "incus:guest:operator", "--vault", vault, "run", "driver"},
	} {
		code, err := run(context.Background(), args)
		if code == 0 || err == nil || !strings.Contains(err.Error(), "only available in full mode") {
			t.Fatalf("application flags accepted outside full mode: %q => %d %v", args, code, err)
		}
	}
}

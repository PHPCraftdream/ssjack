package application

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

func sameDirectory(a, b string) bool {
	first, err := os.Stat(a)
	if err != nil {
		return false
	}
	second, err := os.Stat(b)
	return err == nil && os.SameFile(first, second)
}

func discardRunner(context.Context, string, string, io.Reader, io.Writer, io.Writer) (int, error) {
	return 0, nil
}

func TestApplicationAdmissionRefusals(t *testing.T) {
	manager := fixtureManager(t, context.Background())
	for _, input := range []Input{
		{Application: "other", Arguments: []string{"status"}},
		{Application: fixtureName},
		{Application: fixtureName, Arguments: []string{"Status"}},
		{Application: fixtureName, Arguments: []string{"--status"}},
		{Application: fixtureName, Arguments: []string{"inspect", "nul\x00"}},
		{Application: fixtureName, Arguments: []string{"status"}, TimeoutSeconds: 3601},
		{Application: fixtureName, Arguments: []string{"status"}, TimeoutSeconds: -1},
		{Application: fixtureName, Arguments: []string{"status", strings.Repeat("x", 8192)}},
		{Application: fixtureName, Arguments: append([]string{"status"}, make([]string, 128)...)},
	} {
		if manager.validateInput(input) == nil {
			t.Fatalf("accepted invalid input: %+v", input)
		}
	}
	if err := manager.validateInput(Input{Application: fixtureName, Arguments: []string{"status", strings.Repeat("x", 100)}, TimeoutSeconds: 3600}); err != nil {
		t.Fatal(err)
	}
}

func TestApplicationInteractiveStdinIsAlwaysRefused(t *testing.T) {
	manager := fixtureManager(t, context.Background())
	for _, arguments := range [][]string{{"inspect", "--stdin"}, {"apply", "--stdin"}, {"apply", "--stdin=-"}, {"status", "x", "--stdin=data"}} {
		for _, confirm := range []bool{false, true} {
			if manager.validateInput(Input{Application: fixtureName, Arguments: arguments, Confirm: confirm}) == nil {
				t.Fatalf("interactive stdin accepted: %v confirm=%v", arguments, confirm)
			}
		}
	}
	if manager.validateInput(Input{Application: fixtureName, Arguments: []string{"apply", "--stdin-file", "x"}, Confirm: true}) != nil {
		t.Fatal("an unrelated option with the same prefix was refused")
	}
}

func TestApplicationClassificationComesFromTheDescriptor(t *testing.T) {
	manager := fixtureManager(t, context.Background())
	for _, name := range []string{"status", "inspect"} {
		if err := manager.validateInput(Input{Application: fixtureName, Arguments: []string{name, "--json"}}); err != nil {
			t.Fatalf("observational %s needed confirm: %v", name, err)
		}
	}
	for _, name := range []string{"apply", "bootstrap", "help"} {
		if manager.validateInput(Input{Application: fixtureName, Arguments: []string{name}}) == nil {
			t.Fatalf("undeclared command %s ran without confirm", name)
		}
		if err := manager.validateInput(Input{Application: fixtureName, Arguments: []string{name}, Confirm: true}); err != nil {
			t.Fatalf("confirmed %s refused: %v", name, err)
		}
	}
	for _, name := range []string{"serve", "mcp-serve"} {
		for _, confirm := range []bool{false, true} {
			if manager.validateInput(Input{Application: fixtureName, Arguments: []string{name}, Confirm: confirm}) == nil {
				t.Fatalf("refused command %s accepted, confirm=%v", name, confirm)
			}
		}
	}
	other := fixtureApp(t, "other")
	other.Observational, other.Refused = []string{"apply"}, []string{"status"}
	both := fixtureManagerFor(t, context.Background(), applicationFixtureGuard(t), fixtureApp(t, fixtureName), other)
	if both.validateInput(Input{Application: "other", Arguments: []string{"apply"}}) != nil {
		t.Fatal("observational class of the second application was ignored")
	}
	if both.validateInput(Input{Application: "other", Arguments: []string{"status"}, Confirm: true}) == nil {
		t.Fatal("refused class of the second application was ignored")
	}
	if both.validateInput(Input{Application: fixtureName, Arguments: []string{"apply"}}) == nil {
		t.Fatal("one application's classification leaked into another")
	}
}

func TestApplicationRefusedAndUnconfirmedCommandsStartNothing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	manager := fixtureManager(t, ctx)
	for _, input := range []Input{
		{Application: fixtureName, Arguments: []string{"apply"}},
		{Application: fixtureName, Arguments: []string{"serve"}, Confirm: true},
		{Application: fixtureName, Arguments: []string{"inspect", "--stdin"}},
	} {
		if reply := applicationCall(t, ctx, manager, "app_start", input, nil); reply.OK {
			t.Fatalf("started %+v", input)
		}
	}
	data, err := wire.Encode(remote.ReadInput{JobID: "app-job"})
	if err != nil {
		t.Fatal(err)
	}
	if reply, _ := manager.Handle(ctx, wire.Request{Operation: "app_read", Data: data}); reply.OK {
		t.Fatal("a refused command left a job behind")
	}
}

func TestApplicationListAndDisabledRegistration(t *testing.T) {
	manager, err := New(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	var list ListOutput
	applicationCall(t, context.Background(), manager, "app_list", struct{}{}, &list)
	if len(list.Applications) != 0 {
		t.Fatal("disabled registration advertised an application")
	}
	if list.Hint != noApplicationHint || !strings.Contains(list.Hint, "--app DIR") {
		t.Fatalf("empty application list did not explain how it is enabled: %q", list.Hint)
	}
	for _, operation := range []string{"app_start", "app_read", "app_cancel"} {
		if reply := applicationCall(t, context.Background(), manager, operation, Input{}, nil); reply.OK {
			t.Fatalf("disabled application handled %s", operation)
		}
	}
	if _, handled := manager.Handle(context.Background(), wire.Request{Operation: "targets"}); handled {
		t.Fatal("application manager captured remote operations")
	}
	routed, err := New(context.Background(), &Options{Apps: []App{fixtureApp(t, "alpha"), fixtureApp(t, "beta")}, Profile: "fixed", Runner: discardRunner, Container: "guest", User: "operator"})
	if err != nil {
		t.Fatal(err)
	}
	defer routed.Close()
	list = ListOutput{}
	applicationCall(t, context.Background(), routed, "app_list", struct{}{}, &list)
	want := []Description{{Name: "alpha", Profile: "fixed", Container: "guest"}, {Name: "beta", Profile: "fixed", Container: "guest"}}
	if !reflect.DeepEqual(list.Applications, want) || list.Hint != "" {
		t.Fatalf("application list: %+v", list)
	}
}

func manyApps(t *testing.T, count int) []App {
	t.Helper()
	apps := make([]App, count)
	for i := range apps {
		apps[i] = fixtureApp(t, fmt.Sprintf("app-%d", i))
	}
	return apps
}

func TestApplicationRegistrationIsValidated(t *testing.T) {
	valid := fixtureApp(t, "valid")
	mutate := func(change func(*App)) []App {
		app := fixtureApp(t, "valid")
		change(&app)
		return []App{app}
	}
	for name, apps := range map[string][]App{
		"none":              nil,
		"empty directory":   mutate(func(a *App) { a.Directory = "" }),
		"relative dir":      mutate(func(a *App) { a.Directory = "." }),
		"missing workdir":   mutate(func(a *App) { a.Workdir = filepath.Join(a.Directory, "absent") }),
		"empty workdir":     mutate(func(a *App) { a.Workdir = "" }),
		"relative program":  mutate(func(a *App) { a.Executable = "tool" }),
		"empty program":     mutate(func(a *App) { a.Executable = "" }),
		"program with NUL":  mutate(func(a *App) { a.Executable += "\x00" }),
		"argument with NUL": mutate(func(a *App) { a.Args = []string{"a\x00"} }),
		"bad name":          mutate(func(a *App) { a.Name = "Bad Name" }),
		"empty name":        mutate(func(a *App) { a.Name = "" }),
		"duplicate names":   {valid, fixtureApp(t, "valid")},
		"too many":          manyApps(t, MaxApplications+1),
	} {
		manager, err := New(context.Background(), &Options{Apps: apps, Profile: "fixed", Runner: discardRunner})
		if err == nil {
			manager.Close()
			t.Fatalf("%s: accepted", name)
		}
	}
	for name, options := range map[string]*Options{
		"no runner":    {Apps: []App{valid}, Profile: "fixed"},
		"no profile":   {Apps: []App{valid}, Runner: discardRunner},
		"partial user": {Apps: []App{valid}, Profile: "fixed", Runner: discardRunner, User: "operator"},
		"bad route":    {Apps: []App{valid}, Profile: "fixed", Runner: discardRunner, Container: "guest;id", User: "operator"},
	} {
		manager, err := New(context.Background(), options)
		if err == nil {
			manager.Close()
			t.Fatalf("%s: accepted", name)
		}
	}
	manager, err := New(context.Background(), &Options{Apps: manyApps(t, MaxApplications), Profile: "fixed", Runner: discardRunner})
	if err != nil {
		t.Fatal(err)
	}
	manager.Close()
}

func TestApplicationsAreDispatchedByName(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	first, second := fixtureApp(t, "alpha"), fixtureApp(t, "beta")
	manager := fixtureManagerFor(t, ctx, applicationFixtureGuard(t), first, second)
	for _, app := range []App{first, second} {
		var start remote.StartOutput
		applicationCall(t, ctx, manager, "app_start", Input{Application: app.Name, Arguments: []string{"inspect"}}, &start)
		out := readApplication(t, ctx, manager, start.JobID)
		var report struct{ Directory string }
		if out.ExitCode != 7 || json.Unmarshal(out.Stdout, &report) != nil || !sameDirectory(report.Directory, app.Workdir) {
			t.Fatalf("%s did not run in its own working directory: %+v", app.Name, out)
		}
	}
	if manager.validateInput(Input{Application: "gamma", Arguments: []string{"inspect"}}) == nil {
		t.Fatal("unregistered application accepted")
	}
}

func TestApplicationRunsInItsDeclaredWorkdir(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	app := fixtureApp(t, fixtureName)
	app.Workdir = filepath.Join(app.Directory, "work")
	if err := os.Mkdir(app.Workdir, 0o700); err != nil {
		t.Fatal(err)
	}
	manager := fixtureManagerFor(t, ctx, applicationFixtureGuard(t), app)
	var start remote.StartOutput
	applicationCall(t, ctx, manager, "app_start", Input{Application: fixtureName, Arguments: []string{"inspect"}}, &start)
	out := readApplication(t, ctx, manager, start.JobID)
	var report struct{ Directory string }
	if json.Unmarshal(out.Stdout, &report) != nil || !sameDirectory(report.Directory, app.Workdir) {
		t.Fatalf("working directory ignored: %+v", out)
	}
}

func TestIncusRouteSpecification(t *testing.T) {
	container, user, err := ParseRoute("incus:lab-guest:operator")
	if err != nil || container != "lab-guest" || user != "operator" {
		t.Fatalf("valid route: %q %q %v", container, user, err)
	}
	if container, user, err = ParseRoute(""); err != nil || container != "" || user != "" {
		t.Fatal("empty route is not the absence of a route")
	}
	for _, spec := range []string{"incus", "incus:", "incus:guest", "incus:guest:", "incus::operator", "ssh:guest:operator", "Incus:guest:operator", "incus:guest;id:operator", "incus:guest:--root", "incus:guest:operator:extra", "guest:operator", " incus:guest:operator"} {
		if _, _, err := ParseRoute(spec); err == nil {
			t.Fatalf("invalid route accepted: %q", spec)
		}
	}
}

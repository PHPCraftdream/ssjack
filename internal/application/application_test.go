package application

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/apptransport"
	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

func TestPerApplicationRoutes(t *testing.T) {
	t.Run("new_validates_routes_and_app_list_reports_override", func(t *testing.T) {
		app := fixtureApp(t, fixtureName)
		runner := remote.StreamRunner(func(context.Context, string, string, io.Reader, io.Writer, io.Writer) (int, error) { return 0, nil })
		for _, options := range []*Options{
			{Apps: []App{app}, Profile: "fixed", Runner: runner, Routes: map[string]RouteSpec{"missing": {Container: "box", User: "user"}}},
			{Apps: []App{app}, Profile: "fixed", Runner: runner, Routes: map[string]RouteSpec{fixtureName: {Container: "bad;box", User: "user"}}},
		} {
			if _, err := New(context.Background(), options); err == nil {
				t.Fatal("invalid per-app route accepted")
			}
		}
		manager, err := New(context.Background(), &Options{Apps: []App{app}, Profile: "fixed", Runner: runner, Container: "global", User: "user", Routes: map[string]RouteSpec{fixtureName: {Container: "specific", User: "guest"}}})
		if err != nil {
			t.Fatal("valid per-app route rejected")
		}
		defer manager.Close()
		var out ListOutput
		applicationCall(t, context.Background(), manager, "app_list", nil, &out)
		if len(out.Applications) != 1 || out.Applications[0].Container != "specific" {
			t.Fatalf("app_list route = %+v", out.Applications)
		}
	})
}

func TestApplicationProcess(t *testing.T) {
	if os.Getenv("SSJACK_APPLICATION_TEST_HELPER") != "1" {
		return
	}
	for _, name := range []string{broker.EnvToken, broker.EnvSession, broker.EnvEndpoint, broker.EnvPin, broker.EnvFile} {
		if os.Getenv(name) != "" {
			os.Exit(90)
		}
	}
	if len(os.Getenv(apptransport.EnvToken)) != 64 || len(os.Getenv(apptransport.EnvPin)) != 64 {
		os.Exit(91)
	}
	cwd, err := os.Getwd()
	if err != nil {
		os.Exit(92)
	}
	var args []string
	for index, arg := range os.Args {
		if arg == "--" {
			args = os.Args[index+1:]
			break
		}
	}
	if len(args) > 1 && args[1] == "wait" {
		fmt.Println(os.Getenv(apptransport.EnvEndpoint))
		fmt.Println(strings.Repeat(".", 128))
		// A finite helper is terminated by the application's context.
		<-time.After(30 * time.Second)
		os.Exit(93)
	}
	json.NewEncoder(os.Stdout).Encode(struct {
		Directory string
		Arguments []string
		Endpoint  string
		Pin       string
		Token     string
	}{cwd, args, os.Getenv(apptransport.EnvEndpoint), os.Getenv(apptransport.EnvPin), os.Getenv(apptransport.EnvToken)})
	fmt.Fprint(os.Stderr, os.Getenv(apptransport.EnvToken))
	os.Exit(7)
}

func applicationCall(t *testing.T, ctx context.Context, manager *Manager, operation string, input, output any) wire.Reply {
	t.Helper()
	data, err := wire.Encode(input)
	if err != nil {
		t.Fatal(err)
	}
	reply, handled := manager.Handle(ctx, wire.Request{Operation: operation, Data: data})
	if !handled {
		t.Fatalf("unhandled %s", operation)
	}
	if output != nil {
		if !reply.OK || wire.Decode(reply.Data, output) != nil {
			t.Fatalf("%s: %s", operation, reply.Error)
		}
	}
	return reply
}

func fixtureManager(t *testing.T, ctx context.Context) *Manager {
	t.Helper()
	return fixtureManagerWithGuard(t, ctx, applicationFixtureGuard(t))
}

func readApplication(t *testing.T, ctx context.Context, manager *Manager, id string) remote.ReadOutput {
	t.Helper()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		var out remote.ReadOutput
		applicationCall(t, ctx, manager, "app_read", remote.ReadInput{JobID: id}, &out)
		if out.Done {
			return out
		}
		select {
		case <-ctx.Done():
			// Failure-only evidence: where the application helper is stuck.
			t.Fatalf("application did not finish\ngoroutine dump:\n%s", flakediag.GoroutineDump(64*1024))
		case <-ticker.C:
		}
	}
}

func TestApplicationNativeArgumentsAndFreshScopes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	manager := fixtureManager(t, ctx)
	args := []string{"inspect", "arg with spaces", `{"value":"quoted"}`, "x&echo injected", "'single'", "$HOME"}
	previous := ""
	for i := 0; i < 2; i++ {
		var start remote.StartOutput
		applicationCall(t, ctx, manager, "app_start", Input{Application: fixtureName, Arguments: args}, &start)
		out := readApplication(t, ctx, manager, start.JobID)
		if out.ExitCode != 7 || out.Error != "" || string(out.Stderr) != "***" {
			t.Fatalf("application result: %+v", out)
		}
		var report struct {
			Directory string
			Arguments []string
			Endpoint  string
			Pin       string
			Token     string
		}
		if json.Unmarshal(out.Stdout, &report) != nil || !reflect.DeepEqual(report.Arguments, args) || report.Token != "***" || !sameDirectory(report.Directory, manager.apps[fixtureName].Workdir) {
			t.Fatal("argv, directory or redaction mismatch")
		}
		if report.Pin == "" || report.Pin == previous {
			t.Fatal("application operations reused a scope")
		}
		previous = report.Pin
		endpoint, err := url.Parse(report.Endpoint)
		if err != nil {
			t.Fatal(err)
		}
		connection, err := net.DialTimeout("tcp", endpoint.Host, time.Second)
		if err == nil {
			connection.Close()
			t.Fatal("completed application left its listener open")
		}
	}
	if os.Getenv(broker.EnvToken) != "stale" || os.Getenv(apptransport.EnvToken) != "stale" {
		t.Fatal("parent environment changed")
	}
	var out remote.ReadOutput
	data, _ := wire.Encode(remote.ReadInput{JobID: "remote-job"})
	reply, _ := manager.Handle(ctx, wire.Request{Operation: "app_read", Data: data})
	if reply.OK {
		t.Fatalf("foreign operation accepted: %+v", out)
	}
}

func TestApplicationCancellationAndDisconnect(t *testing.T) {
	for _, disconnect := range []bool{false, true} {
		t.Run(fmt.Sprint(disconnect), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			session, closeSession := context.WithCancel(ctx)
			defer closeSession()
			manager := fixtureManager(t, ctx)
			var start remote.StartOutput
			applicationCall(t, session, manager, "app_start", Input{Application: fixtureName, Arguments: []string{"inspect", "wait"}}, &start)
			ticker := time.NewTicker(5 * time.Millisecond)
			defer ticker.Stop()
			var endpoint *url.URL
			for endpoint == nil {
				var progress remote.ReadOutput
				applicationCall(t, session, manager, "app_read", remote.ReadInput{JobID: start.JobID}, &progress)
				if line, _, found := strings.Cut(string(progress.Stdout), "\n"); found {
					var err error
					endpoint, err = url.Parse(line)
					if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" {
						t.Fatal("invalid helper endpoint")
					}
					break
				}
				if progress.Done {
					t.Fatalf("helper exited before cancellation: %+v", progress)
				}
				select {
				case <-ctx.Done():
					// Failure-only evidence: helper startup stall diagnostics.
					t.Fatalf("helper did not become ready\ngoroutine dump:\n%s", flakediag.GoroutineDump(64*1024))
				case <-ticker.C:
				}
			}
			if disconnect {
				closeSession()
			} else {
				var out remote.CancelOutput
				applicationCall(t, session, manager, "app_cancel", remote.JobInput{JobID: start.JobID}, &out)
				if !out.Cancelled {
					t.Fatal("cancel not acknowledged")
				}
			}
			out := readApplication(t, ctx, manager, start.JobID)
			if out.ExitCode == 0 || !strings.Contains(out.Error, "canceled") {
				t.Fatalf("cancellation was lost: %+v", out)
			}
			connection, err := net.DialTimeout("tcp", endpoint.Host, time.Second)
			if err == nil {
				connection.Close()
				t.Fatal("cancelled application left its child listener open")
			}
		})
	}
}

// app_read with wait_seconds blocks until output or completion instead of
// returning an empty chunk, and a cancelled operation ends the wait.
func TestApplicationReadWaitsForOutputAndCompletion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	manager := fixtureManager(t, ctx)
	var start remote.StartOutput
	applicationCall(t, ctx, manager, "app_start", Input{Application: fixtureName, Arguments: []string{"inspect", "wait"}}, &start)
	var first remote.ReadOutput
	applicationCall(t, ctx, manager, "app_read", remote.ReadInput{JobID: start.JobID, WaitSeconds: 15}, &first)
	if first.Done || len(first.Stdout) == 0 {
		t.Fatalf("a waiting read returned without output while the helper runs: %+v", first)
	}
	var cancelled remote.CancelOutput
	applicationCall(t, ctx, manager, "app_cancel", remote.JobInput{JobID: start.JobID}, &cancelled)
	if !cancelled.Cancelled {
		t.Fatal("cancel not acknowledged")
	}
	stdoutOffset, stderrOffset := first.StdoutOffset, first.StderrOffset
	for {
		var next remote.ReadOutput
		applicationCall(t, ctx, manager, "app_read", remote.ReadInput{JobID: start.JobID, StdoutOffset: stdoutOffset, StderrOffset: stderrOffset, WaitSeconds: 15}, &next)
		stdoutOffset, stderrOffset = next.StdoutOffset, next.StderrOffset
		if next.Done {
			if next.ExitCode == 0 || !strings.Contains(next.Error, "canceled") {
				t.Fatalf("cancellation was lost: %+v", next)
			}
			return
		}
		if ctx.Err() != nil {
			t.Fatalf("waiting reads did not see the cancelled application finish\ngoroutine dump:\n%s", flakediag.GoroutineDump(64*1024))
		}
	}
}

func TestApplicationTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	manager := fixtureManager(t, ctx)
	var start remote.StartOutput
	applicationCall(t, ctx, manager, "app_start", Input{Application: fixtureName, Arguments: []string{"inspect", "wait"}, TimeoutSeconds: 1}, &start)
	out := readApplication(t, ctx, manager, start.JobID)
	if out.ExitCode == 0 || !strings.Contains(out.Error, "deadline exceeded") {
		t.Fatalf("application deadline was lost: %+v", out)
	}
}

func TestApplicationClassifyIsSideEffectFree(t *testing.T) {
	t.Run("observational_command", func(t *testing.T) {
		classifyCase(t, Input{Application: fixtureName, Arguments: []string{"inspect"}}, false, false)
	})
	t.Run("non_observational_command", func(t *testing.T) {
		classifyCase(t, Input{Application: fixtureName, Arguments: []string{"apply"}}, true, false)
	})
	t.Run("unknown_application", func(t *testing.T) {
		classifyCase(t, Input{Application: "missing", Arguments: []string{"inspect"}}, false, true)
	})
	t.Run("refused_command", func(t *testing.T) {
		classifyCase(t, Input{Application: fixtureName, Arguments: []string{"serve"}}, false, true)
	})
}

func classifyCase(t *testing.T, input Input, wantClass, wantError bool) {
	t.Helper()
	var runnerCalls int
	app := fixtureApp(t, fixtureName)
	manager, err := New(context.Background(), &Options{
		Apps: []App{app}, Profile: "fixed", Runner: func(context.Context, string, string, io.Reader, io.Writer, io.Writer) (int, error) {
			runnerCalls++
			t.Errorf("runner invoked during classification")
			return 0, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()

	retainedBefore := manager.jobs.RetainedJobs()
	var before, after ListOutput
	applicationCall(t, context.Background(), manager, "app_list", struct{}{}, &before)
	reply := applicationCall(t, context.Background(), manager, "app_classify", input, nil)
	if wantError {
		if reply.OK {
			t.Fatal("invalid classification accepted")
		}
	} else {
		var out ClassifyOutput
		if !reply.OK || wire.Decode(reply.Data, &out) != nil {
			t.Fatalf("classification failed: %s", reply.Error)
		}
		if out.NonObservational != wantClass {
			t.Fatalf("non_observational = %v, want %v", out.NonObservational, wantClass)
		}
	}
	applicationCall(t, context.Background(), manager, "app_list", struct{}{}, &after)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("app_list changed: before %+v after %+v", before, after)
	}
	if retainedAfter := manager.jobs.RetainedJobs(); retainedAfter != retainedBefore {
		t.Fatalf("retained jobs changed: before %d after %d", retainedBefore, retainedAfter)
	}
	if runnerCalls != 0 {
		t.Fatalf("runner called %d times", runnerCalls)
	}
	read := applicationCall(t, context.Background(), manager, "app_read", remote.ReadInput{JobID: "fabricated-job"}, nil)
	if read.OK {
		t.Fatal("classification started a readable job")
	}
}

func TestFixedIncusRoute(t *testing.T) {
	for _, route := range [][2]string{{"guest", ""}, {"", "user"}, {"guest;id", "user"}, {"guest", "--root"}} {
		if ValidateRoute(route[0], route[1]) == nil {
			t.Fatal("invalid fixed route accepted")
		}
	}
	var gotProfile, gotCommand string
	runner := routeRunner(func(_ context.Context, profile, command string, _ io.Reader, _, _ io.Writer) (int, error) {
		gotProfile, gotCommand = profile, command
		return 0, nil
	}, "guest", "operator")
	_, err := runner(context.Background(), "fixed", "printf '%s' '$HOME; literal'", nil, io.Discard, io.Discard)
	want := "/usr/bin/sudo -n /usr/bin/incus exec 'guest' -- /usr/sbin/runuser -u 'operator' -- /bin/sh -c " + quote("printf '%s' '$HOME; literal'")
	if err != nil || gotProfile != "fixed" || gotCommand != want {
		t.Fatal("fixed route or inner quoting changed")
	}
}

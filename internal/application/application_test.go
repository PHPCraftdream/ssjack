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
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

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
	t.Setenv("SSJACK_APPLICATION_TEST_HELPER", "1")
	for _, name := range []string{broker.EnvToken, broker.EnvSession, broker.EnvEndpoint, broker.EnvPin, broker.EnvFile, apptransport.EnvToken, apptransport.EnvEndpoint, apptransport.EnvPin} {
		t.Setenv(name, "stale")
	}
	program, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	manager, err := New(ctx, &Options{Directory: t.TempDir(), Command: []string{program, "-test.run=^TestApplicationProcess$", "--"}, Profile: "host.profile", Runner: func(context.Context, string, string, io.Reader, io.Writer, io.Writer) (int, error) { return 0, nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.Close)
	return manager
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
			t.Fatal("application did not finish")
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
		applicationCall(t, ctx, manager, "app_start", Input{Application: Name, Arguments: args}, &start)
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
		if json.Unmarshal(out.Stdout, &report) != nil || !reflect.DeepEqual(report.Arguments, args) || report.Token != "***" || report.Directory == "" {
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
			applicationCall(t, session, manager, "app_start", Input{Application: Name, Arguments: []string{"inspect", "wait"}}, &start)
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
					t.Fatal("helper did not become ready")
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

func TestApplicationTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	manager := fixtureManager(t, ctx)
	var start remote.StartOutput
	applicationCall(t, ctx, manager, "app_start", Input{Application: Name, Arguments: []string{"inspect", "wait"}, TimeoutSeconds: 1}, &start)
	out := readApplication(t, ctx, manager, start.JobID)
	if out.ExitCode == 0 || !strings.Contains(out.Error, "deadline exceeded") {
		t.Fatalf("application deadline was lost: %+v", out)
	}
}

func TestApplicationAdmissionAndDisabledRegistration(t *testing.T) {
	for _, input := range []Input{
		{Application: "other", Arguments: []string{"status"}},
		{Application: Name},
		{Application: Name, Arguments: []string{"mcp-serve"}, Confirm: true},
		{Application: Name, Arguments: []string{"control-mcp"}, Confirm: true},
		{Application: Name, Arguments: []string{"apply"}},
		{Application: Name, Arguments: []string{"inspect", "--stdin"}},
		{Application: Name, Arguments: []string{"inspect", "nul\x00"}},
		{Application: Name, Arguments: []string{"status"}, TimeoutSeconds: 3601},
		{Application: Name, Arguments: []string{"status", strings.Repeat("x", 8192)}},
	} {
		if validateInput(input) == nil {
			t.Fatalf("accepted invalid input: %+v", input)
		}
	}
	for _, args := range [][]string{{"status"}, {"bootstrap", "--check", "--json"}, {"apply"}} {
		if err := validateInput(Input{Application: Name, Arguments: args, Confirm: true}); err != nil {
			t.Fatal(err)
		}
	}
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
	if reply := applicationCall(t, context.Background(), manager, "app_start", Input{}, nil); reply.OK {
		t.Fatal("disabled application started")
	}
	if _, handled := manager.Handle(context.Background(), wire.Request{Operation: "targets"}); handled {
		t.Fatal("application manager captured remote operations")
	}
}

func TestApplicationRequiresExplicitDirectory(t *testing.T) {
	program, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	manager, err := New(context.Background(), &Options{Command: []string{program}, Profile: "fixed", Runner: func(context.Context, string, string, io.Reader, io.Writer, io.Writer) (int, error) { return 0, nil }})
	if err == nil {
		manager.Close()
		t.Fatal("empty directory implicitly registered the keeper working directory")
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

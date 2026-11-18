package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/agent"
	"github.com/PHPCraftdream/ssjack/internal/application"
	"github.com/PHPCraftdream/ssjack/internal/launch"
	"github.com/PHPCraftdream/ssjack/internal/startupsecret"
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
		if code, err := Run(context.Background(), test.args); code != 1 || err == nil || !strings.Contains(err.Error(), test.want) {
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
	code, err := Run(context.Background(), []string{"--server", "production", "--account", "deploy", "check"})
	if code != 1 || err == nil || !strings.Contains(err.Error(), "an interactive terminal is required") {
		t.Fatal("named check was rejected as a legacy profile or bypassed trusted-terminal unlock")
	}
}

func TestNamedApplicationBindingUsesExactlyTheResolvedCredential(t *testing.T) {
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
	cliLoadAgentCredentials = func(_ context.Context, path, selector string) (keeperCredentials, error) {
		if selector != "@production/deploy" {
			t.Fatal("harness lost named selectors")
		}
		loaded = true
		return &stubKeeperCredentials{runner: func(context.Context, string, string, io.Writer, io.Writer) (int, error) {
			t.Fatal("selector test unexpectedly ran SSH")
			return 1, nil
		}, targets: []string{"resolved-credential"}}, nil
	}
	cliLaunchRun = func(_ context.Context, options launch.Options) (int, error) {
		launched = true
		if len(options.Command) != 1 || options.Command[0] != "synthetic-harness" {
			t.Fatal("named selection changed harness arguments")
		}
		return 0, nil
	}
	code, err := Run(context.Background(), []string{"--server", "production", "--account", "deploy", "run", "synthetic-harness"})
	if code != 0 || err != nil || !loaded || !launched {
		t.Fatal("explicit named harness dispatch failed")
	}
}

func TestStartupPasswordReachesUnlockButNotHarnessEnvironmentOrArguments(t *testing.T) {
	const warning = "WARNING: vault password supplied through argv/environment; hidden terminal input is safer."
	const unlockMarker = "SYNTHETIC-STARTUP-UNLOCK-REACHED"
	const harnessMarker = "SYNTHETIC-STARTUP-HARNESS-REACHED"
	for _, tc := range []struct {
		name       string
		env        string
		envPresent bool
		argument   string
		want       string
	}{
		{name: "environment-only", env: "synthetic-environment", envPresent: true, want: "synthetic-environment"},
		{name: "argument-only", argument: "synthetic-argument", want: "synthetic-argument"},
		{name: "argument-overrides-environment", env: "synthetic-environment", envPresent: true, argument: "synthetic-argument", want: "synthetic-argument"},
		{name: "argument-overrides-invalid-environment", env: "", envPresent: true, argument: "synthetic-argument", want: "synthetic-argument"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setStartupPasswordEnvironment(t, tc.env, tc.envPresent)
			if !tc.envPresent {
				if _, present := os.LookupEnv(startupsecret.Environment); present {
					t.Fatal("argument-only case did not start without the environment source")
				}
			}
			oldLoad, oldLaunch := cliLoadAgentCredentials, cliLaunchRun
			t.Cleanup(func() { cliLoadAgentCredentials, cliLaunchRun = oldLoad, oldLaunch })
			args := []string{"run", "fixture-harness", "--resume"}
			if tc.argument != "" {
				args = append([]string{"--vault-password", tc.argument}, args...)
			}
			loaded, launched := false, false
			cliLoadAgentCredentials = func(ctx context.Context, path, profile string) (keeperCredentials, error) {
				if _, present := os.LookupEnv(startupsecret.Environment); present {
					t.Fatal("vault password remained inheritable at unlock")
				}
				password, err := readVaultPassword(ctx, "unused prompt")
				if err != nil {
					t.Fatal("startup source did not reach the credential loader")
				}
				fmt.Fprintln(os.Stderr, unlockMarker)
				if string(password) != tc.want {
					clear(password)
					t.Fatal("unexpected startup password reached unlock")
				}
				clear(password)
				if _, err := readVaultPassword(ctx, "must not prompt twice"); !errors.Is(err, startupsecret.ErrConsumed) {
					t.Fatal("startup password was not single-use")
				}
				loaded = true
				return &stubKeeperCredentials{}, nil
			}
			cliLaunchRun = func(ctx context.Context, options launch.Options) (int, error) {
				fmt.Fprintln(os.Stderr, harnessMarker)
				launched = true
				if _, present := os.LookupEnv(startupsecret.Environment); present {
					t.Fatal("vault password remained inheritable at harness launch")
				}
				if !reflect.DeepEqual(options.Command, []string{"fixture-harness", "--resume"}) {
					t.Fatal("startup password arguments reached the harness")
				}
				return 0, nil
			}
			code, runErr, output := captureStartupRun(t, func() (int, error) {
				return Run(context.Background(), args)
			})
			if code != 0 || runErr != nil || !loaded || !launched {
				t.Fatal("startup did not unlock and reach the harness boundary")
			}
			warningAt := strings.Index(output, warning+"\n")
			unlockAt := strings.Index(output, unlockMarker+"\n")
			harnessAt := strings.Index(output, harnessMarker+"\n")
			if warningAt < 0 || unlockAt < 0 || harnessAt < 0 || warningAt >= unlockAt || unlockAt >= harnessAt {
				t.Fatal("fixed startup warning was absent or out of order")
			}
			for _, source := range []string{tc.env, tc.argument} {
				if source != "" && (strings.Contains(output, source) || (runErr != nil && strings.Contains(runErr.Error(), source))) {
					t.Fatal("startup source was echoed")
				}
			}
		})
	}
}

func TestInvalidStartupPasswordRefusesBeforeCredentialLoader(t *testing.T) {
	tooLong := strings.Repeat("s", startupsecret.Maximum+1)
	for _, tc := range []struct {
		name       string
		env        string
		envPresent bool
		args       []string
		sources    []string
		inputError bool
	}{
		{name: "empty-environment", envPresent: true, args: []string{"run", "fixture"}, inputError: true},
		{name: "oversized-environment", env: tooLong, envPresent: true, args: []string{"run", "fixture"}, sources: []string{tooLong}, inputError: true},
		{name: "empty-argument", env: "synthetic-environment", envPresent: true, args: []string{"--vault-password=", "run", "fixture"}, sources: []string{"synthetic-environment"}, inputError: true},
		{name: "oversized-argument", env: "synthetic-environment", envPresent: true, args: []string{"--vault-password=" + tooLong, "run", "fixture"}, sources: []string{"synthetic-environment", tooLong}, inputError: true},
		{name: "missing-argument-value", env: "synthetic-environment", envPresent: true, args: []string{"--vault-password"}, sources: []string{"synthetic-environment"}},
		{name: "repeated-argument", env: "synthetic-environment", envPresent: true, args: []string{"--vault-password=synthetic-first", "--vault-password=synthetic-second", "run", "fixture"}, sources: []string{"synthetic-environment", "synthetic-first", "synthetic-second"}, inputError: true},
		{name: "unrelated-secret-flag", args: []string{"--password=synthetic-unrelated", "run", "fixture"}, sources: []string{"synthetic-unrelated"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setStartupPasswordEnvironment(t, tc.env, tc.envPresent)
			oldLoad, oldLaunch := cliLoadAgentCredentials, cliLaunchRun
			t.Cleanup(func() { cliLoadAgentCredentials, cliLaunchRun = oldLoad, oldLaunch })
			loaded, launched := false, false
			cliLoadAgentCredentials = func(context.Context, string, string) (keeperCredentials, error) {
				loaded = true
				return nil, errors.New("credential loader reached")
			}
			cliLaunchRun = func(context.Context, launch.Options) (int, error) {
				launched = true
				return 0, nil
			}
			code, runErr, output := captureStartupRun(t, func() (int, error) {
				return Run(context.Background(), tc.args)
			})
			if code != 1 || runErr == nil || loaded || launched {
				t.Fatal("invalid startup input reached unlock or harness launch")
			}
			if errors.Is(runErr, startupsecret.ErrInput) != tc.inputError {
				t.Fatal("invalid startup input returned an unexpected refusal category")
			}
			for _, source := range tc.sources {
				if strings.Contains(output, source) || strings.Contains(runErr.Error(), source) {
					t.Fatal("invalid startup source was echoed")
				}
			}
			if _, present := os.LookupEnv(startupsecret.Environment); present {
				t.Fatal("failed startup left the password inheritable")
			}
		})
	}
}

func TestStartupPasswordAbsentSourceUsesHiddenTerminalFallback(t *testing.T) {
	setStartupPasswordEnvironment(t, "", false)
	oldLoad, oldLaunch := cliLoadAgentCredentials, cliLaunchRun
	t.Cleanup(func() { cliLoadAgentCredentials, cliLaunchRun = oldLoad, oldLaunch })
	loaded, launched := false, false
	cliLoadAgentCredentials = func(ctx context.Context, path, profile string) (keeperCredentials, error) {
		loaded = true
		_, err := readVaultPassword(ctx, "unused prompt")
		return nil, err
	}
	cliLaunchRun = func(context.Context, launch.Options) (int, error) {
		launched = true
		return 0, nil
	}
	code, runErr, output := captureStartupRun(t, func() (int, error) {
		return Run(context.Background(), []string{"run", "fixture"})
	})
	if code != 1 || runErr == nil || !strings.Contains(runErr.Error(), "interactive terminal is required") || !loaded || launched {
		t.Fatal("absent startup source did not retain the hidden terminal boundary")
	}
	if strings.Contains(output, "WARNING: vault password supplied") {
		t.Fatal("absent startup source emitted the explicit-source warning")
	}
}

func TestStartupPasswordFlagDoesNotRelaxOwnerTerminalRequirement(t *testing.T) {
	input, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	previous := os.Stdin
	os.Stdin = input
	defer func() { os.Stdin = previous }()
	for _, command := range [][]string{{"--interactive"}, {"owner", "add-mcp-server"}} {
		args := append([]string{"--vault-password", "synthetic-argument"}, command...)
		if code, err := Run(context.Background(), args); code != 1 || err == nil || !strings.Contains(err.Error(), "terminal") {
			t.Fatal("startup password bypassed owner terminal or was rejected as an unsupported option")
		}
	}
}

func setStartupPasswordEnvironment(t *testing.T, value string, present bool) {
	t.Helper()
	old, existed := os.LookupEnv(startupsecret.Environment)
	var err error
	if present {
		err = os.Setenv(startupsecret.Environment, value)
	} else {
		err = os.Unsetenv(startupsecret.Environment)
	}
	if err != nil {
		t.Fatal("cannot prepare startup password environment")
	}
	t.Cleanup(func() {
		if existed {
			_ = os.Setenv(startupsecret.Environment, old)
		} else {
			_ = os.Unsetenv(startupsecret.Environment)
		}
	})
}

func captureStartupRun(t *testing.T, call func() (int, error)) (int, error, string) {
	const outputLimit = 64 * 1024
	t.Helper()
	stdin, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal("cannot prepare startup stdin")
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		_ = stdin.Close()
		t.Fatal("cannot capture startup output")
	}
	oldStdin, oldStdout, oldStderr := os.Stdin, os.Stdout, os.Stderr
	os.Stdin, os.Stdout, os.Stderr = stdin, writer, writer
	restored := false
	restore := func() {
		if !restored {
			os.Stdin, os.Stdout, os.Stderr = oldStdin, oldStdout, oldStderr
			restored = true
		}
	}
	type drainResult struct {
		output []byte
		err    error
	}
	drained := make(chan drainResult, 1)
	go func() {
		output, err := io.ReadAll(io.LimitReader(reader, outputLimit+1))
		_ = reader.Close()
		drained <- drainResult{output: output, err: err}
	}()
	drainFinished := false
	t.Cleanup(func() {
		restore()
		_ = writer.Close()
		_ = stdin.Close()
		if !drainFinished {
			select {
			case result := <-drained:
				if result.err != nil {
					t.Error("startup output capture failed")
				}
			case <-time.After(5 * time.Second):
				_ = reader.Close()
			}
		}
	})
	code, runErr := call()
	_ = writer.Close()
	restore()
	select {
	case result := <-drained:
		drainFinished = true
		_ = stdin.Close()
		if result.err != nil {
			t.Fatal("startup output capture failed")
		}
		if len(result.output) > outputLimit {
			t.Fatal("startup output exceeded the capture bound")
		}
		return code, runErr, string(result.output)
	case <-time.After(5 * time.Second):
		_ = reader.Close()
		drainFinished = true
		t.Fatal("startup output drain did not finish")
		return 0, nil, ""
	}
}

type ownerCloseFunc func(context.Context) error

func (f ownerCloseFunc) Close(ctx context.Context) error { return f(ctx) }

func TestKeeperClosesRetainedOwnerAfterHarnessAndReportsFailure(t *testing.T) {
	for _, mode := range []string{"success", "harness-error", "owner-error", "both-errors", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			oldLoad, oldLaunch := cliLoadAgentCredentials, cliLaunchRun
			t.Cleanup(func() { cliLoadAgentCredentials, cliLaunchRun = oldLoad, oldLaunch })
			var events []string
			private := errors.New("synthetic-private-owner-diagnostic")
			harnessError := errors.New("synthetic harness failure")
			owner := ownerCloseFunc(func(closeContext context.Context) error {
				events = append(events, "owner-close")
				deadline, bounded := closeContext.Deadline()
				if closeContext.Err() != nil || !bounded || time.Until(deadline) <= 0 || time.Until(deadline) > time.Minute {
					t.Fatal("keeper shutdown reused a cancelled context or omitted its bound")
				}
				if mode == "owner-error" || mode == "both-errors" {
					return private
				}
				return nil
			})
			cliLoadAgentCredentials = func(context.Context, string, string) (keeperCredentials, error) {
				events = append(events, "load")
				return agent.NewOwnerCredentials(owner), nil
			}
			cliLaunchRun = func(context.Context, launch.Options) (int, error) {
				events = append(events, "harness-return")
				if mode == "cancelled" {
					cancel()
					return 1, context.Canceled
				}
				if mode == "harness-error" || mode == "both-errors" {
					return 7, harnessError
				}
				return 0, nil
			}
			code, err := Run(ctx, []string{"run", "synthetic-harness"})
			if !reflect.DeepEqual(events, []string{"load", "harness-return", "owner-close"}) {
				t.Fatal("keeper dropped owner lifetime before the harness stopped or failed to close it")
			}
			switch mode {
			case "owner-error", "both-errors":
				if code != 1 || !errors.Is(err, agent.ErrOwnerShutdown) || strings.Contains(err.Error(), private.Error()) {
					t.Fatal("owner shutdown failure was ignored or exposed raw diagnostics")
				}
			case "harness-error":
				if code != 7 || !errors.Is(err, harnessError) {
					t.Fatal("successful owner shutdown changed the harness outcome")
				}
			case "cancelled":
				if code != 1 || !errors.Is(err, context.Canceled) {
					t.Fatal("shutdown lost the original cancellation outcome")
				}
			default:
				if code != 0 || err != nil {
					t.Fatal("saved owner shutdown changed a successful harness outcome")
				}
			}
		})
	}
}

func TestKeeperClosesAnOwnedPartialStartupButRefusesMissingCredentials(t *testing.T) {
	oldLoad, oldLaunch := cliLoadAgentCredentials, cliLaunchRun
	t.Cleanup(func() { cliLoadAgentCredentials, cliLaunchRun = oldLoad, oldLaunch })
	launched, closed := false, false
	failure := errors.New("synthetic startup refusal")
	cliLoadAgentCredentials = func(context.Context, string, string) (keeperCredentials, error) {
		return agent.NewOwnerCredentials(ownerCloseFunc(func(context.Context) error { closed = true; return nil })), failure
	}
	cliLaunchRun = func(context.Context, launch.Options) (int, error) { launched = true; return 0, nil }
	if code, err := Run(context.Background(), []string{"run", "fixture"}); code != 1 || !errors.Is(err, failure) || !closed || launched {
		t.Fatal("partially initialized owner was leaked or launched after startup failure")
	}
	cliLoadAgentCredentials = func(context.Context, string, string) (keeperCredentials, error) { return nil, nil }
	if code, err := Run(context.Background(), []string{"run", "fixture"}); code != 1 || err == nil || launched {
		t.Fatal("missing credential session reached the harness")
	}
}

func TestTransferFlagsRefusedOutsideFullMode(t *testing.T) {
	subA := filepath.Join(realTempDir(t), "a")
	if err := os.MkdirAll(subA, 0700); err != nil {
		t.Fatal(err)
	}
	vault := filepath.Join(realTempDir(t), "v.ktav")
	for _, args := range [][]string{
		{"--mode", "declarative", "--transfer-root", subA, "--vault", vault, "run", "driver"},
		{"--mode", "declarative", "--transfer-max-bytes", "100", "--vault", vault, "run", "driver"},
	} {
		code, err := Run(context.Background(), args)
		if code == 0 || err == nil || !strings.Contains(err.Error(), "only available in full mode") {
			t.Fatalf("transfer flags accepted outside full mode: %q => %d %v", args, code, err)
		}
		if strings.Contains(err.Error(), subA) {
			t.Fatalf("refusal leaked the root path: %v", err)
		}
	}
}

func TestTransferRootParsedBeforeCredentials(t *testing.T) {
	subA := filepath.Join(realTempDir(t), "a")
	if err := os.MkdirAll(subA, 0700); err != nil {
		t.Fatal(err)
	}
	vault := filepath.Join(realTempDir(t), "v.ktav")
	markerErr := errors.New("credentials reached")
	credentialsCalled := false
	oldCredentials := cliLoadAgentCredentials
	cliLoadAgentCredentials = func(context.Context, string, string) (keeperCredentials, error) {
		credentialsCalled = true
		return nil, markerErr
	}
	defer func() { cliLoadAgentCredentials = oldCredentials }()
	code, err := Run(context.Background(), []string{"--transfer-root", subA, "--vault", vault, "run", "harness"})
	if code != 1 || !errors.Is(err, markerErr) || !credentialsCalled {
		t.Fatalf("valid root did not reach credentials: %d %v (credentials=%v)", code, err, credentialsCalled)
	}
	credentialsCalled = false
	code, err = Run(context.Background(), []string{"--transfer-root", "relative/dir", "--vault", vault, "run", "harness"})
	if code != 1 || err == nil || credentialsCalled {
		t.Fatalf("invalid root reached credentials: %d %v (credentials=%v)", code, err, credentialsCalled)
	}
	if !strings.Contains(err.Error(), "absolute") || strings.Contains(err.Error(), "relative/dir") {
		t.Fatalf("unexpected refusal message: %v", err)
	}
}

// realTempDir returns a temp directory with symlinks resolved; transfer roots
// refuse symlinked ancestors such as macOS /var.
func realTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

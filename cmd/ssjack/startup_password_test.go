package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/launch"
	"github.com/PHPCraftdream/ssjack/internal/startupsecret"
)

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
			cliLoadAgentCredentials = func(ctx context.Context, path, profile string) (*agentCredentials, error) {
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
				return &agentCredentials{}, nil
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
				return run(context.Background(), args)
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
			cliLoadAgentCredentials = func(context.Context, string, string) (*agentCredentials, error) {
				loaded = true
				return nil, errors.New("credential loader reached")
			}
			cliLaunchRun = func(context.Context, launch.Options) (int, error) {
				launched = true
				return 0, nil
			}
			code, runErr, output := captureStartupRun(t, func() (int, error) {
				return run(context.Background(), tc.args)
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
	cliLoadAgentCredentials = func(ctx context.Context, path, profile string) (*agentCredentials, error) {
		loaded = true
		_, err := readVaultPassword(ctx, "unused prompt")
		return nil, err
	}
	cliLaunchRun = func(context.Context, launch.Options) (int, error) {
		launched = true
		return 0, nil
	}
	code, runErr, output := captureStartupRun(t, func() (int, error) {
		return run(context.Background(), []string{"run", "fixture"})
	})
	if code != 1 || runErr == nil || !strings.Contains(runErr.Error(), "interactive terminal is required") || !loaded || launched {
		t.Fatal("absent startup source did not retain the hidden terminal boundary")
	}
	if strings.Contains(output, "WARNING: vault password supplied") {
		t.Fatal("absent startup source emitted the explicit-source warning")
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
		if code, err := run(context.Background(), args); code != 1 || err == nil || !strings.Contains(err.Error(), "terminal") {
			t.Fatal("startup password bypassed owner terminal or was rejected as an unsupported option")
		}
	}
}

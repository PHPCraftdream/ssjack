package main

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/launch"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/startupsecret"
)

func TestStartupPasswordReachesUnlockButNotHarnessEnvironmentOrArguments(t *testing.T) {
	for _, argument := range []bool{false, true} {
		t.Run(map[bool]string{false: "environment", true: "argument"}[argument], func(t *testing.T) {
			t.Setenv(startupsecret.Environment, "synthetic-environment")
			oldLoad, oldLaunch := cliLoadAgentCredentials, cliLaunchRun
			t.Cleanup(func() { cliLoadAgentCredentials, cliLaunchRun = oldLoad, oldLaunch })
			want := "synthetic-environment"
			args := []string{"run", "fixture-harness", "--resume"}
			if argument {
				want = "synthetic-argument"
				args = append([]string{"--vault-password", want}, args...)
			}
			loaded, launched := false, false
			cliLoadAgentCredentials = func(ctx context.Context, path, profile string) (remote.Runner, remote.StreamRunner, []string, error) {
				password, err := readVaultPassword(ctx, "unused prompt")
				if err != nil || string(password) != want {
					t.Fatal("startup source did not reach the credential loader")
				}
				clear(password)
				if _, err := readVaultPassword(ctx, "must not prompt twice"); !errors.Is(err, startupsecret.ErrConsumed) {
					t.Fatal("startup password was not single-use")
				}
				loaded = true
				return nil, nil, nil, nil
			}
			cliLaunchRun = func(ctx context.Context, options launch.Options) (int, error) {
				launched = true
				if _, present := os.LookupEnv(startupsecret.Environment); present {
					t.Fatal("vault password remained inheritable")
				}
				if !reflect.DeepEqual(options.Command, []string{"fixture-harness", "--resume"}) {
					t.Fatal("startup password arguments reached the harness")
				}
				return 0, nil
			}
			if code, err := run(context.Background(), args); code != 0 || err != nil || !loaded || !launched {
				t.Fatal("startup did not unlock and reach the harness boundary")
			}
		})
	}
}

func TestInvalidStartupPasswordRefusesBeforeCredentialLoader(t *testing.T) {
	for _, args := range [][]string{
		{"--vault-password=", "run", "fixture"},
		{"--vault-password=synthetic-first", "--vault-password=synthetic-second", "run", "fixture"},
	} {
		t.Setenv(startupsecret.Environment, "synthetic-environment")
		old := cliLoadAgentCredentials
		cliLoadAgentCredentials = func(context.Context, string, string) (remote.Runner, remote.StreamRunner, []string, error) {
			t.Fatal("invalid explicit input fell back or reached unlock")
			return nil, nil, nil, nil
		}
		code, err := run(context.Background(), args)
		cliLoadAgentCredentials = old
		if code != 1 || !errors.Is(err, startupsecret.ErrInput) || strings.Contains(err.Error(), "synthetic-") {
			t.Fatal("invalid startup input did not return a fixed refusal")
		}
		if _, present := os.LookupEnv(startupsecret.Environment); present {
			t.Fatal("failed startup left the password inheritable")
		}
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

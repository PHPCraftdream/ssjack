package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/launch"
	"github.com/PHPCraftdream/ssjack/internal/remote"
)

func TestEnrollmentMetadataValidationPrecedesCredentials(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "invalid.json")
	if err := os.WriteFile(bad, []byte(`{"format":!}`), 0600); err != nil {
		t.Fatal(err)
	}
	supported := runtime.GOOS == "linux" || runtime.GOOS == "darwin" || runtime.GOOS == "freebsd" || runtime.GOOS == "openbsd" || runtime.GOOS == "netbsd" || runtime.GOOS == "dragonfly" || runtime.GOOS == "solaris"
	for _, tc := range []struct {
		name string
		path string
		want error
	}{
		{"missing", filepath.Join(dir, "absent"), os.ErrNotExist},
		{"invalid", bad, &json.SyntaxError{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			credentialsCalled := false
			oldCredentials := cliLoadAgentCredentials
			cliLoadAgentCredentials = func(string, string) (remote.Runner, remote.StreamRunner, []string, error) {
				credentialsCalled = true
				return nil, nil, nil, errors.New("credentials reached")
			}
			defer func() { cliLoadAgentCredentials = oldCredentials }()
			args := []string{"--mode", "declarative", "--enrollment-metadata", tc.path, "--vault", filepath.Join(dir, "missing-vault"), "run", "driver"}
			code, err := run(context.Background(), args)
			if code == 0 || err == nil || credentialsCalled {
				t.Fatalf("expected early failure, got %d %v (credentials=%v)", code, err, credentialsCalled)
			}
			if supported {
				if _, ok := tc.want.(*json.SyntaxError); ok {
					var syntaxErr *json.SyntaxError
					if !errors.As(err, &syntaxErr) {
						t.Fatalf("expected %T error category, got %v", tc.want, err)
					}
				} else if !errors.Is(err, tc.want) {
					t.Fatalf("expected %v error category, got %v", tc.want, err)
				}
			}
			if !supported && !strings.Contains(err.Error(), "unsupported") {
				t.Fatalf("expected unsupported-platform error, got %v", err)
			}
		})
	}
	credentialsCalled := false
	oldCredentials := cliLoadAgentCredentials
	cliLoadAgentCredentials = func(string, string) (remote.Runner, remote.StreamRunner, []string, error) {
		credentialsCalled = true
		return nil, nil, nil, errors.New("credentials reached")
	}
	defer func() { cliLoadAgentCredentials = oldCredentials }()
	args := []string{"--enrollment-metadata", filepath.Join(dir, "absent"), "--vault", filepath.Join(dir, "missing-vault"), "run", "driver"}
	if code, err := run(context.Background(), args); code == 0 || err == nil || !strings.Contains(err.Error(), "requires --mode declarative") || credentialsCalled {
		t.Fatalf("expected full-mode rejection before credentials, got %d %v (credentials=%v)", code, err, credentialsCalled)
	}
}

const enrollmentLaunchHelperMarker = "SSJACK_ENROLLMENT_LAUNCH_HELPER"

func TestEnrollmentMetadataSnapshotReachesKeeper(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "freebsd" && runtime.GOOS != "openbsd" && runtime.GOOS != "netbsd" && runtime.GOOS != "dragonfly" && runtime.GOOS != "solaris" {
		t.Skip("safe metadata file loading is unsupported on this platform")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "metadata.json")
	const first = `{"format":"ssjack-enrollment-metadata-v1","enrollment_id":"AAAAAAAAAAAAAAAAAAAAAA","driver_id":"before","driver_protocol":1}`
	const second = `{"format":"ssjack-enrollment-metadata-v1","enrollment_id":"AAAAAAAAAAAAAAAAAAAAAA","driver_id":"after","driver_protocol":1}`
	if err := os.WriteFile(path, []byte(first), 0600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "launch-root")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	oldCredentials, oldLaunch := cliLoadAgentCredentials, cliLaunchRun
	defer func() { cliLoadAgentCredentials, cliLaunchRun = oldCredentials, oldLaunch }()
	credentialsCalled := false
	cliLoadAgentCredentials = func(string, string) (remote.Runner, remote.StreamRunner, []string, error) {
		credentialsCalled = true
		return nil, nil, nil, errors.New("declarative mode read credentials")
	}
	cliLaunchRun = func(ctx context.Context, opts launch.Options) (int, error) {
		if err := os.WriteFile(path, []byte(second), 0600); err != nil {
			return 1, err
		}
		return oldLaunch(ctx, launch.Options{
			Root: root, Executable: os.Args[0],
			Command:      []string{os.Args[0], "-test.run=^TestEnrollmentLaunchHelper$"},
			BootstrapTTL: time.Minute, Mode: opts.Mode, Metadata: opts.Metadata,
			Stdout: os.Stdout, Stderr: os.Stderr,
		})
	}
	t.Setenv(enrollmentLaunchHelperMarker, "1")
	if code, err := run(context.Background(), []string{"--mode", "declarative", "--enrollment-metadata", path, "--vault", filepath.Join(dir, "unused"), "run", "fixture"}); code != 0 || err != nil {
		t.Fatalf("run: %d %v", code, err)
	}
	if credentialsCalled {
		t.Fatal("declarative launch accessed credentials")
	}
}

func enrollmentLaunchHelperActive(marker string, args []string) bool {
	return marker == "1" && len(args) == 1 && args[0] == "-test.run=^TestEnrollmentLaunchHelper$"
}

func TestEnrollmentLaunchHelperActivation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		marker string
		args   []string
		want   bool
	}{
		{"exact activation", "1", []string{"-test.run=^TestEnrollmentLaunchHelper$"}, true},
		{"missing marker", "", []string{"-test.run=^TestEnrollmentLaunchHelper$"}, false},
		{"wrong marker", "other", []string{"-test.run=^TestEnrollmentLaunchHelper$"}, false},
		{"missing args", "1", nil, false},
		{"wrong args", "1", []string{"-test.run=TestEnrollmentLaunchHelper"}, false},
		{"extra args", "1", []string{"-test.run=^TestEnrollmentLaunchHelper$", "-test.v"}, false},
		{"marker and args wrong", "other", []string{"-test.run=other"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := enrollmentLaunchHelperActive(tc.marker, tc.args); got != tc.want {
				t.Fatalf("enrollmentLaunchHelperActive(%q, %v) = %v, want %v", tc.marker, tc.args, got, tc.want)
			}
		})
	}
}

func TestEnrollmentLaunchHelper(t *testing.T) {
	if !enrollmentLaunchHelperActive(os.Getenv(enrollmentLaunchHelperMarker), os.Args[1:]) {
		return
	}
	if os.Getenv(broker.EnvToken) == "" {
		t.Fatal("synthetic launch helper missing bootstrap token")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := broker.ConnectBootstrap(ctx, broker.Bootstrap{
		Session: os.Getenv(broker.EnvSession), Endpoint: os.Getenv(broker.EnvEndpoint),
		Pin: os.Getenv(broker.EnvPin), Token: os.Getenv(broker.EnvToken),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	descriptor, err := broker.Describe(ctx, client)
	if err != nil || descriptor.DriverID != "before" {
		t.Fatalf("descriptor snapshot: %+v %v", descriptor, err)
	}
	var result map[string]any
	if err := client.Call(ctx, "driver.execute", map[string]any{}, &result); err == nil {
		t.Fatal("forged operation accepted")
	}
}

func TestEnrollmentMetadataRejectsIgnoredAndEmptyOption(t *testing.T) {
	for _, args := range [][]string{
		{"--enrollment-metadata=", "list"}, {"--enrollment-metadata", "", "run", "driver"},
		{"--enrollment-metadata=", "--version"}, {"--enrollment-metadata=", "--generate-key", "x"},
	} {
		code, err := run(context.Background(), args)
		if code == 0 || err == nil || !strings.Contains(err.Error(), "enrollment-metadata") {
			t.Fatalf("option was ignored/accepted: %v => %d %v", args, code, err)
		}
	}
}

func TestHelpAndMissingCommand(t *testing.T) {
	if code, err := run(context.Background(), []string{"-help"}); code != 0 || err != nil {
		t.Fatalf("help: %d %v", code, err)
	}
	if code, err := run(context.Background(), nil); code == 0 || err == nil {
		t.Fatal("missing harness was accepted")
	}
}

func TestMCPRequiresSession(t *testing.T) {
	t.Setenv(broker.EnvFile, "")
	t.Setenv(broker.EnvToken, "")
	if code, err := run(context.Background(), []string{"mcp"}); code == 0 || err == nil {
		t.Fatal("MCP started without a session")
	}
	if code, err := run(context.Background(), []string{"mcp", "extra"}); code == 0 || err == nil {
		t.Fatal("invalid MCP arguments were accepted")
	}
}

func TestHarnessTailIsNotParsedAsSSJackFlags(t *testing.T) {
	dir := t.TempDir()
	file, err := os.CreateTemp(dir, "input")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	previous := os.Stdin
	os.Stdin = file
	defer func() { os.Stdin = previous }()
	for _, profileFlag := range []string{"-p", "--profile"} {
		args := []string{"--vault", filepath.Join(dir, "missing"), profileFlag, "main", "run", "claude", "-c"}
		code, err := run(context.Background(), args)
		if code == 0 || err == nil || !strings.Contains(err.Error(), "terminal") {
			t.Fatalf("harness tail was parsed as local flags: %d %v", code, err)
		}
	}
}

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/enrollment"
	"github.com/PHPCraftdream/ssjack/internal/launch"
)

func policyFileLoadingSupported() bool {
	return runtime.GOOS == "linux" || runtime.GOOS == "darwin" || runtime.GOOS == "freebsd" || runtime.GOOS == "openbsd" || runtime.GOOS == "netbsd" || runtime.GOOS == "dragonfly" || runtime.GOOS == "solaris"
}

func TestPolicySnapshotCLIValidationPrecedesCredentials(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	metadata, policy := filepath.Join(dir, "metadata.json"), filepath.Join(dir, "policy.json")
	if err = os.WriteFile(metadata, []byte(`{"format":"ssjack-enrollment-metadata-v1","enrollment_id":"AAAAAAAAAAAAAAAAAAAAAA","driver_id":"driver","driver_protocol":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(policy, []byte(`{"format":"ssjack-policy-subset-v1","enrollment_id":"AAAAAAAAAAAAAAAAAAAAAA","driver_id":"driver","driver_protocol":1,"revision":"r1"}`), 0600); err != nil {
		t.Fatal(err)
	}
	old := cliLoadAgentCredentials
	called := false
	cliLoadAgentCredentials = func(context.Context, string, string) (*agentCredentials, error) {
		called = true
		return nil, errors.New("credentials reached")
	}
	defer func() { cliLoadAgentCredentials = old }()
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--policy-snapshot", policy, "--vault", filepath.Join(dir, "missing"), "run", "driver"}, "--policy-snapshot requires --enrollment-metadata"},
		{[]string{"--mode", "full", "--enrollment-metadata", metadata, "--policy-snapshot", policy, "run", "driver"}, "--enrollment-metadata requires --mode declarative"},
		{[]string{"--mode", "declarative", "--enrollment-metadata", metadata, "--policy-snapshot", filepath.Join(dir, "absent"), "run", "driver"}, "missing"},
	} {
		code, err := run(context.Background(), tc.args)
		if tc.want == "missing" {
			if policyFileLoadingSupported() {
				if code == 0 || !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("missing policy: %d %v", code, err)
				}
			} else if code == 0 || err == nil || !strings.Contains(err.Error(), "unsupported") {
				t.Fatalf("unsupported platform policy error: %d %v", code, err)
			}
		} else if code == 0 || err == nil || err.Error() != tc.want {
			t.Fatalf("args %v: got %d %v; want %q", tc.args, code, err, tc.want)
		}
	}
	if called {
		t.Fatal("policy validation reached credentials")
	}
}

const policyLaunchHelperMarker = "SSJACK_POLICY_LAUNCH_HELPER"

func TestPolicySnapshotCLIReachesAuthenticatedKeeper(t *testing.T) {
	if !policyFileLoadingSupported() {
		t.Skip("safe policy file loading is unsupported on this platform")
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	metadataPath, policyPath := filepath.Join(dir, "metadata.json"), filepath.Join(dir, "policy.json")
	const metadataRaw = `{"format":"ssjack-enrollment-metadata-v1","enrollment_id":"AAAAAAAAAAAAAAAAAAAAAA","driver_id":"before","driver_protocol":1}`
	const policyRaw = `{"format":"ssjack-policy-subset-v1","enrollment_id":"AAAAAAAAAAAAAAAAAAAAAA","driver_id":"before","driver_protocol":1,"revision":"rev-1"}`
	for path, raw := range map[string]string{metadataPath: metadataRaw, policyPath: policyRaw} {
		if err = os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
	}
	meta, err := enrollment.Parse([]byte(metadataRaw))
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := enrollment.LoadPolicy(policyPath, meta)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "launch-root")
	if err = os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	oldCredentials, oldLaunch := cliLoadAgentCredentials, cliLaunchRun
	defer func() { cliLoadAgentCredentials, cliLaunchRun = oldCredentials, oldLaunch }()
	cliLoadAgentCredentials = func(context.Context, string, string) (*agentCredentials, error) {
		return nil, errors.New("declarative mode read credentials")
	}
	cliLaunchRun = func(ctx context.Context, opts launch.Options) (int, error) {
		if opts.Policy == nil || opts.Policy.Digest() != loaded.Digest() {
			t.Fatalf("CLI did not pass captured policy: %+v", opts.Policy)
		}
		if err := os.WriteFile(policyPath, []byte(`{}`), 0600); err != nil {
			return 1, err
		}
		executable, err := os.Executable()
		if err != nil {
			return 1, err
		}
		return oldLaunch(ctx, launch.Options{Root: root, Executable: executable, Command: []string{executable, "-test.run=^TestPolicyLaunchHelper$"}, BootstrapTTL: time.Minute, Mode: opts.Mode, Metadata: opts.Metadata, Policy: opts.Policy, Stdout: os.Stdout, Stderr: os.Stderr})
	}
	t.Setenv(policyLaunchHelperMarker, "1")
	t.Setenv("SSJACK_EXPECTED_POLICY_DIGEST", loaded.Digest())
	args := []string{"--mode", "declarative", "--enrollment-metadata", metadataPath, "--policy-snapshot", policyPath, "--vault", filepath.Join(dir, "unused"), "run", "fixture"}
	if code, err := run(context.Background(), args); code != 0 || err != nil {
		t.Fatalf("CLI launch: %d %v", code, err)
	}
}

func policyLaunchHelperActive(marker string, args []string) bool {
	return marker == "1" && len(args) == 1 && args[0] == "-test.run=^TestPolicyLaunchHelper$"
}

func TestPolicyLaunchHelper(t *testing.T) {
	if !policyLaunchHelperActive(os.Getenv(policyLaunchHelperMarker), os.Args[1:]) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := broker.ConnectBootstrap(ctx, broker.Bootstrap{Session: os.Getenv(broker.EnvSession), Endpoint: os.Getenv(broker.EnvEndpoint), Pin: os.Getenv(broker.EnvPin), Token: os.Getenv(broker.EnvToken)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	descriptor, err := broker.Describe(ctx, client)
	if err != nil || descriptor.Protocol != broker.PolicyProtocol || descriptor.PolicyRevision != "rev-1" || descriptor.PolicyDigest != os.Getenv("SSJACK_EXPECTED_POLICY_DIGEST") || len(descriptor.Tools) != 0 {
		t.Fatalf("policy descriptor: %+v %v", descriptor, err)
	}
	var result map[string]any
	if err := client.Call(ctx, "driver.execute", map[string]any{}, &result); err == nil {
		t.Fatal("policy keeper accepted operation")
	}
}

func TestEnrollmentIdentityCLIRejectsInvalidAndForgedInputsBeforeCredentials(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	metaPath, policyPath, identityPath := filepath.Join(dir, "metadata.json"), filepath.Join(dir, "policy.json"), filepath.Join(dir, "identity.json")
	for p, raw := range map[string]string{metaPath: cliIdentityMeta, policyPath: cliIdentityPolicy, identityPath: cliIdentityJSON} {
		if err := os.WriteFile(p, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
	}
	old := cliLoadAgentCredentials
	defer func() { cliLoadAgentCredentials = old }()
	called := false
	cliLoadAgentCredentials = func(context.Context, string, string) (*agentCredentials, error) {
		called = true
		return nil, errors.New("credentials accessed")
	}
	cases := [][]string{{"--enrollment-identity", identityPath, "run", "fixture"}, {"--mode", "full", "--enrollment-identity", identityPath, "run", "fixture"}, {"--mode", "declarative", "--enrollment-metadata", metaPath, "--enrollment-identity", identityPath, "run", "fixture"}, {"--mode", "declarative", "--enrollment-metadata", metaPath, "--policy-snapshot", policyPath, "--enrollment-identity", "relative.json", "run", "fixture"}}
	for _, args := range cases {
		if code, err := run(context.Background(), args); code == 0 || err == nil {
			t.Errorf("accepted invalid args %v", args)
		}
	}
	if err := os.WriteFile(identityPath, []byte(`{"format":"forged"}`), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"--mode", "declarative", "--enrollment-metadata", metaPath, "--policy-snapshot", policyPath, "--enrollment-identity", identityPath, "run", "fixture"}
	if code, err := run(context.Background(), args); code == 0 || err == nil {
		t.Fatal("accepted forged snapshot")
	}
	if called {
		t.Fatal("invalid identity reached credentials")
	}
}

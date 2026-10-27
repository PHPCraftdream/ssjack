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
	"github.com/PHPCraftdream/ssjack/internal/remote"
)

func TestClawwrightRegistrationWithoutUnlock(t *testing.T) {
	if options, err := registeredClawwright("", "", "", "", "main", nil); err != nil || options != nil {
		t.Fatal("standalone keeper unexpectedly registered Clawwright")
	}
	for _, args := range [][4]string{{"", "entry.js", "", ""}, {"", "", "guest", "user"}, {t.TempDir(), "entry.js", "guest", ""}} {
		if _, err := registeredClawwright(args[0], args[1], args[2], args[3], "main", nil); err == nil {
			t.Fatal("incomplete registration accepted")
		}
	}
	bin := t.TempDir()
	node := "node"
	if runtime.GOOS == "windows" {
		node = "node.exe"
	}
	if err := os.WriteFile(filepath.Join(bin, node), []byte("fixture, never executed"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	root := t.TempDir()
	entry := fixtureClawwrightPackage(t, filepath.Join(t.TempDir(), "checked package"))
	relative, err := filepath.Rel(root, entry)
	if err != nil {
		t.Fatal(err)
	}
	options, err := registeredClawwright(root, relative, "guest", "operator", "fixed", nil)
	if err != nil {
		t.Fatal(err)
	}
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	canonicalEntry, err := filepath.EvalSymlinks(entry)
	if err != nil {
		t.Fatal(err)
	}
	if options.Directory != canonicalRoot || len(options.Command) != 2 || options.Command[1] != canonicalEntry || !filepath.IsAbs(options.Command[0]) || options.Profile != "fixed" {
		t.Fatalf("registration changed fixed inputs: %+v", options)
	}
	if _, err := registeredClawwright(root, root, "", "", "main", nil); err == nil {
		t.Fatal("entry directory accepted")
	}
	if _, err := registeredClawwright(root, "missing.js", "", "", "main", nil); err == nil {
		t.Fatal("missing entry accepted")
	}
	if code, err := run(context.Background(), []string{"--clawwright-entry", entry, "run", "harness"}); code == 0 || err == nil {
		t.Fatal("orphan entry reached vault unlock")
	}
	metadata := filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(entry))), "package.json")
	if err := os.WriteFile(metadata, []byte(`{"name":"@phpcraftdream/clawwright","version":"0.1.2"}`), 0600); err != nil {
		t.Fatal(err)
	}
	code, err := run(context.Background(), []string{"--vault", filepath.Join(root, "missing.vault"), "--clawwright-directory", root, "--clawwright-entry", entry, "run", "harness"})
	if code == 0 || err == nil || !strings.Contains(err.Error(), "Clawwright package") {
		t.Fatal("old Clawwright package was not refused before vault authorization")
	}
}

func TestInstalledClawwrightEntryDoesNotExecuteShim(t *testing.T) {
	root := t.TempDir()
	if runtime.GOOS == "windows" {
		entry, err := installedClawwrightEntry(filepath.Join(root, "clawwright.cmd"))
		if err != nil || entry != filepath.Join(root, "node_modules", "@phpcraftdream", "clawwright", "dist", "entry", "bin.js") {
			t.Fatal("npm shim was not resolved to its Node entry")
		}
		return
	}
	entry := filepath.Join(root, "bin.js")
	if err := os.WriteFile(entry, []byte("// fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	shim := filepath.Join(root, "clawwright")
	if err := os.Symlink(entry, shim); err != nil {
		t.Fatal(err)
	}
	got, err := installedClawwrightEntry(shim)
	want, canonicalErr := filepath.EvalSymlinks(entry)
	if err != nil || canonicalErr != nil || got != want {
		t.Fatal("npm executable symlink was not resolved")
	}
	if _, err := installedClawwrightEntry(filepath.Join(root, "missing")); err == nil {
		t.Fatal("missing installed entry accepted")
	}
}

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
	cliLoadAgentCredentials = func(string, string) (remote.Runner, remote.StreamRunner, []string, error) {
		called = true
		return nil, nil, nil, errors.New("credentials reached")
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
	cliLoadAgentCredentials = func(string, string) (remote.Runner, remote.StreamRunner, []string, error) {
		return nil, nil, nil, errors.New("declarative mode read credentials")
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

package cli

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

	"github.com/PHPCraftdream/ssjack/internal/application"
	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/enrollment"
	"github.com/PHPCraftdream/ssjack/internal/launch"
)

func TestEnrollmentMetadataValidationPrecedesCredentials(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
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
			cliLoadAgentCredentials = func(context.Context, string, string) (keeperCredentials, error) {
				credentialsCalled = true
				return nil, errors.New("credentials reached")
			}
			defer func() { cliLoadAgentCredentials = oldCredentials }()
			args := []string{"--mode", "declarative", "--enrollment-metadata", tc.path, "--vault", filepath.Join(dir, "missing-vault"), "run", "driver"}
			code, err := Run(context.Background(), args)
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
	cliLoadAgentCredentials = func(context.Context, string, string) (keeperCredentials, error) {
		credentialsCalled = true
		return nil, errors.New("credentials reached")
	}
	defer func() { cliLoadAgentCredentials = oldCredentials }()
	args := []string{"--enrollment-metadata", filepath.Join(dir, "absent"), "--vault", filepath.Join(dir, "missing-vault"), "run", "driver"}
	if code, err := Run(context.Background(), args); code == 0 || err == nil || !strings.Contains(err.Error(), "requires --mode declarative") || credentialsCalled {
		t.Fatalf("expected full-mode rejection before credentials, got %d %v (credentials=%v)", code, err, credentialsCalled)
	}
}

const enrollmentLaunchHelperMarker = "SSJACK_ENROLLMENT_LAUNCH_HELPER"

func TestEnrollmentMetadataSnapshotReachesKeeper(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "freebsd" && runtime.GOOS != "openbsd" && runtime.GOOS != "netbsd" && runtime.GOOS != "dragonfly" && runtime.GOOS != "solaris" {
		t.Skip("safe metadata file loading is unsupported on this platform")
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
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
	cliLoadAgentCredentials = func(context.Context, string, string) (keeperCredentials, error) {
		credentialsCalled = true
		return nil, errors.New("declarative mode read credentials")
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
	if code, err := Run(context.Background(), []string{"--mode", "declarative", "--enrollment-metadata", path, "--vault", filepath.Join(dir, "unused"), "run", "fixture"}); code != 0 || err != nil {
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
		code, err := Run(context.Background(), args)
		if code == 0 || err == nil || !strings.Contains(err.Error(), "enrollment-metadata") {
			t.Fatalf("option was ignored/accepted: %v => %d %v", args, code, err)
		}
	}
}

func TestHelpAndMissingCommand(t *testing.T) {
	if code, err := Run(context.Background(), []string{"-help"}); code != 0 || err != nil {
		t.Fatalf("help: %d %v", code, err)
	}
	if code, err := Run(context.Background(), nil); code == 0 || err == nil {
		t.Fatal("missing harness was accepted")
	}
}

func TestMCPRequiresSession(t *testing.T) {
	t.Setenv(broker.EnvFile, "")
	t.Setenv(broker.EnvToken, "")
	if code, err := Run(context.Background(), []string{"mcp"}); code == 0 || err == nil {
		t.Fatal("MCP started without a session")
	}
	if code, err := Run(context.Background(), []string{"mcp", "extra"}); code == 0 || err == nil {
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
		code, err := Run(context.Background(), args)
		if code == 0 || err == nil || !strings.Contains(err.Error(), "terminal") {
			t.Fatalf("harness tail was parsed as local flags: %d %v", code, err)
		}
	}
}

const cliIdentityMeta = `{"format":"ssjack-enrollment-metadata-v1","enrollment_id":"AAAAAAAAAAAAAAAAAAAAAA","driver_id":"driver.one-v1","driver_protocol":1}`
const cliIdentityPolicy = `{"format":"ssjack-policy-subset-v1","enrollment_id":"AAAAAAAAAAAAAAAAAAAAAA","driver_id":"driver.one-v1","driver_protocol":1,"revision":"rev-1"}`
const cliIdentityJSON = `{"format":"ssjack-enrollment-identity-subset-v1","enrollment_id":"AAAAAAAAAAAAAAAAAAAAAA","driver_id":"driver.one-v1","driver_protocol":1,"executable":{"path":"/opt/driver","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"artifact_digests":{"main":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"dependency_digests":{},"configuration_digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","principal":{"issuer":"local","subject":"operator"}}`

func TestEnrollmentIdentityCLIReadsSnapshotAndNeverCredentials(t *testing.T) {
	supported := runtime.GOOS == "linux" || runtime.GOOS == "darwin" || runtime.GOOS == "freebsd" || runtime.GOOS == "openbsd" || runtime.GOOS == "netbsd" || runtime.GOOS == "dragonfly" || runtime.GOOS == "solaris"
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
	oldC, oldL := cliLoadAgentCredentials, cliLaunchRun
	defer func() { cliLoadAgentCredentials, cliLaunchRun = oldC, oldL }()
	credentials := false
	cliLoadAgentCredentials = func(context.Context, string, string) (keeperCredentials, error) {
		credentials = true
		return nil, errors.New("credentials accessed")
	}
	launched := false
	cliLaunchRun = func(_ context.Context, opts launch.Options) (int, error) {
		launched = true
		if opts.Identity == nil {
			return 1, errors.New("identity missing")
		}
		if err := os.WriteFile(identityPath, []byte(`{}`), 0600); err != nil {
			return 1, err
		}
		if opts.Identity.DriverID() != "driver.one-v1" {
			return 1, errors.New("identity mutated")
		}
		return 0, nil
	}
	args := []string{"--mode", "declarative", "--enrollment-metadata", metaPath, "--policy-snapshot", policyPath, "--enrollment-identity", identityPath, "run", "fixture"}
	code, err := Run(context.Background(), args)
	if supported {
		if err != nil || code != 0 {
			t.Fatalf("run %d %v", code, err)
		}
		if !launched || credentials {
			t.Fatalf("launch=%v credentials=%v", launched, credentials)
		}
	} else if err == nil || !strings.Contains(err.Error(), "unsupported") || launched || credentials {
		t.Fatalf("unsupported safe-open did not fail closed: %d %v", code, err)
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
	cliLoadAgentCredentials = func(context.Context, string, string) (keeperCredentials, error) {
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
		code, err := Run(context.Background(), tc.args)
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
	const policyRaw = `{"format":"ssjack-enrollment-metadata-v1","enrollment_id":"AAAAAAAAAAAAAAAAAAAAAA","driver_id":"before","driver_protocol":1,"revision":"rev-1"}`
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
	cliLoadAgentCredentials = func(context.Context, string, string) (keeperCredentials, error) {
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
	if code, err := Run(context.Background(), args); code != 0 || err != nil {
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
	cliLoadAgentCredentials = func(context.Context, string, string) (keeperCredentials, error) {
		called = true
		return nil, errors.New("credentials accessed")
	}
	cases := [][]string{{"--enrollment-identity", identityPath, "run", "fixture"}, {"--mode", "full", "--enrollment-identity", identityPath, "run", "fixture"}, {"--mode", "declarative", "--enrollment-metadata", metaPath, "--enrollment-identity", identityPath, "run", "fixture"}, {"--mode", "declarative", "--enrollment-metadata", metaPath, "--policy-snapshot", policyPath, "--enrollment-identity", "relative.json", "run", "fixture"}}
	for _, args := range cases {
		if code, err := Run(context.Background(), args); code == 0 || err == nil {
			t.Errorf("accepted invalid args %v", args)
		}
	}
	if err := os.WriteFile(identityPath, []byte(`{"format":"forged"}`), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"--mode", "declarative", "--enrollment-metadata", metaPath, "--policy-snapshot", policyPath, "--enrollment-identity", identityPath, "run", "fixture"}
	if code, err := Run(context.Background(), args); code == 0 || err == nil {
		t.Fatal("accepted forged snapshot")
	}
	if called {
		t.Fatal("invalid identity reached credentials")
	}
}

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
	// "./" keeps the fixture inside DIR; a bare name would be a PATH lookup.
	descriptor := `{"format":"ssjack-app-v1","name":"` + name + `","launch":{"executable":"./` + executable + `","args":["entry"]},"commands":{"observational":["status"]}}`
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
	cliLoadAgentCredentials = func(context.Context, string, string) (keeperCredentials, error) {
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
		if code, err := Run(context.Background(), args); code == 0 || err == nil || err.Error() == "credentials reached" {
			t.Fatalf("args %v: %d %v", args, code, err)
		}
	}
	if called {
		t.Fatal("invalid application registration reached credentials")
	}
	code, err := Run(context.Background(), []string{"--vault", vault, "--app", syntheticApp(t, "ok"), "--app-route", "incus:guest:operator", "run", "harness"})
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
		code, err := Run(context.Background(), args)
		if code == 0 || err == nil || !strings.Contains(err.Error(), "only available in full mode") {
			t.Fatalf("application flags accepted outside full mode: %q => %d %v", args, code, err)
		}
	}
}

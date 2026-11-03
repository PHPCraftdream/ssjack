package launch

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/enrollment"
)

const identityMeta = `{"format":"ssjack-enrollment-metadata-v1","enrollment_id":"AAAAAAAAAAAAAAAAAAAAAA","driver_id":"driver.one-v1","driver_protocol":1}`
const identityPolicy = `{"format":"ssjack-policy-subset-v1","enrollment_id":"AAAAAAAAAAAAAAAAAAAAAA","driver_id":"driver.one-v1","driver_protocol":1,"revision":"rev-1"}`
const identityJSON = `{"format":"ssjack-enrollment-identity-subset-v1","enrollment_id":"AAAAAAAAAAAAAAAAAAAAAA","driver_id":"driver.one-v1","driver_protocol":1,"executable":{"path":"/opt/driver","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"artifact_digests":{"main":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"dependency_digests":{},"configuration_digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","principal":{"issuer":"local","subject":"operator"}}`

func TestIdentityHarnessProcess(t *testing.T) {
	if os.Getenv("SSJACK_IDENTITY_HELPER") != "1" {
		return
	}
	if err := os.WriteFile(os.Getenv("SSJACK_IDENTITY_SOURCE"), []byte(`{}`), 0600); err != nil {
		os.Exit(120)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := broker.ConnectBootstrap(ctx, broker.Bootstrap{Session: os.Getenv(broker.EnvSession), Endpoint: os.Getenv(broker.EnvEndpoint), Pin: os.Getenv(broker.EnvPin), Token: os.Getenv(broker.EnvToken)})
	if err != nil {
		os.Exit(121)
	}
	defer client.Close()
	d, err := broker.Describe(ctx, client)
	if err != nil || d.Protocol != broker.SnapshotProtocol || d.SnapshotDigest != os.Getenv("SSJACK_EXPECTED_IDENTITY_DIGEST") || len(d.Tools) != 0 {
		os.Exit(122)
	}
	var out map[string]any
	if client.Call(ctx, "driver.execute", map[string]any{}, &out) == nil {
		os.Exit(123)
	}
	os.Exit(0)
}

func TestLaunchRunIdentityAuthenticatedAndSourceImmutable(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "freebsd" && runtime.GOOS != "openbsd" && runtime.GOOS != "netbsd" && runtime.GOOS != "dragonfly" && runtime.GOOS != "solaris" {
		t.Skip("safe enrollment file loading unsupported")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := enrollment.Parse([]byte(identityMeta))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := enrollment.ParsePolicy([]byte(identityPolicy), metadata)
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "identity.json")
	if err := os.WriteFile(source, []byte(identityJSON), 0600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := enrollment.LoadSnapshot(source, metadata, policy)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSJACK_IDENTITY_HELPER", "1")
	t.Setenv("SSJACK_IDENTITY_SOURCE", source)
	t.Setenv("SSJACK_EXPECTED_IDENTITY_DIGEST", snapshot.Digest())
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	code, err := Run(ctx, Options{Root: root, Executable: executable, Command: []string{executable, "-test.run=^TestIdentityHarnessProcess$"}, BootstrapTTL: time.Minute, Mode: broker.ModeDeclarative, Metadata: &metadata, Policy: &policy, Identity: &snapshot})
	if err != nil || code != 0 {
		t.Fatalf("identity launch: %d %v", code, err)
	}
	changed, err := os.ReadFile(source)
	if err != nil || string(changed) != "{}" {
		t.Fatalf("helper did not mutate source: %q %v", changed, err)
	}
}

func TestIdentitySnapshotMismatchRejectedBeforeSideEffects(t *testing.T) {
	metadata, err := enrollment.Parse([]byte(identityMeta))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := enrollment.ParsePolicy([]byte(identityPolicy), metadata)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := enrollment.ParseSnapshot([]byte(identityJSON), metadata, policy)
	if err != nil {
		t.Fatal(err)
	}
	mismatch, err := enrollment.Parse([]byte(`{"format":"ssjack-enrollment-metadata-v1","enrollment_id":"AAAAAAAAAAAAAAAAAAAAAA","driver_id":"driver.other","driver_protocol":1}`))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	_, err = Run(context.Background(), Options{Root: root, Command: []string{"unused"}, BootstrapTTL: time.Minute, Mode: broker.ModeDeclarative, Metadata: &mismatch, Policy: &policy, Identity: &snapshot})
	if err == nil {
		t.Fatal("mismatched identity accepted")
	}
	if _, err := os.Stat(filepath.Join(root, ".mcp.json")); !os.IsNotExist(err) {
		t.Fatal("mismatched identity caused side effect")
	}
}

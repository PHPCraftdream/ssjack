//go:build linux || darwin

package transferacceptance

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/faultproxy"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/sshauth"
	"github.com/PHPCraftdream/ssjack/internal/transfer"
	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal"
)

// newProxiedStack builds the same stack as newStack, but the SSH client of
// the engine dials a fault-injecting proxy that forwards to the exec fixture.
// The fixture's host key stays pinned, so the proxy is transparent until a
// rule is set. Faults are armed per scenario with proxy.MustSetRules.
func newProxiedStack(t *testing.T, limits transfercore.Limits) (*stack, *faultproxy.Proxy) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	rootDir, sandbox := evalDir(t), evalDir(t)
	server := StartExecServer(t, sandbox, sandboxEnv(t, nil))
	proxy := faultproxy.Start(t, server.Address())
	config := &ssh.ClientConfig{
		User:            "acceptance",
		Auth:            []ssh.AuthMethod{sshauth.PublicKey(server.ClientSigner())},
		HostKeyCallback: ssh.FixedHostKey(server.HostKey()),
		Timeout:         5 * time.Second,
	}
	runner, err := remote.NewCredentialStreamRunner(targetName, proxy.Addr(), config)
	if err != nil {
		t.Fatal(err)
	}
	root, err := transferlocal.ParseRoot(rootDir, "")
	if err != nil {
		t.Fatal(err)
	}
	manager, err := transfer.NewManager([]*transferlocal.Root{root}, []string{targetName}, limits, func(target string) (transfer.Engine, error) {
		return transfer.NewEngine(runner, target, limits)
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.Close)
	session := connectBridge(t, ctx, manager)
	return &stack{
		ctx: ctx, root: root, rootDir: rootDir, sandbox: sandbox,
		server: server, manager: manager, session: session,
	}, proxy
}

// TestTransferFaultProxyAcceptance runs fault-injection scenarios on the real
// stack through the fault proxy. It carries the same build constraint as the
// neighbouring real-stack acceptance (a POSIX sh exec fixture) and runs with
// the package's tests in CI. The scenarios document today's behaviour that a
// resumable chunked mode extends: a dropped connection fails the whole
// transfer and publishes nothing.
func TestTransferFaultProxyAcceptance(t *testing.T) {
	t.Run("whole-file-upload-dropped-mid-stream-publishes-nothing", scenarioProxyUploadDropped)
}

// scenarioProxyUploadDropped cuts the connection that streams a whole-file
// upload after an exact byte count. The job must end failed, nothing may be
// published at the destination and the job's staging directory must be gone.
// Only the connection carrying the payload crosses the cut: the SSH
// handshake and the control commands each move far fewer bytes client to
// server, and they run on their own connections.
func scenarioProxyUploadDropped(t *testing.T) {
	s, proxy := newProxiedStack(t, transfercore.DefaultLimits())
	var c captured
	source := SeedPayload(2*1024*1024, 41)
	WriteTree(t, s.rootDir, map[string][]byte{"big/blob.bin": source}, []string{"big"})
	parent := filepath.Join(s.sandbox, "in")
	mkdirAll(t, parent)
	const cut = 256 * 1024
	proxy.MustSetRules(t, faultproxy.Rule{Faults: []faultproxy.Fault{
		faultproxy.DropAfterBytes(faultproxy.ClientToServer, cut),
	}})
	destination := parent + "/blob.bin"
	out := waitStatus(t, s, &c, startUpload(t, s, &c, map[string]any{
		"target": targetName, "local": "big/blob.bin", "remote": destination,
	}))
	if out.State != "failed" || out.ErrorClass != string(transfercore.ClassRemoteFailed) {
		t.Fatalf("dropped upload status = %+v", out)
	}
	// The destination directory is empty: nothing published, no staging left.
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		t.Errorf("dropped upload left %q in the destination directory", entry.Name())
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatal("dropped upload published a destination")
	}
	AssertNoStaging(t, parent)
	AssertNoStaging(t, s.sandbox)
	AssertNoStaging(t, s.rootDir)
	// Exactly one connection was cut, at exactly the configured byte.
	stats := proxy.Stats()
	var cuts []faultproxy.ConnStats
	for _, conn := range stats.Conns {
		if conn.Reason == faultproxy.ReasonBytes {
			cuts = append(cuts, conn)
		}
	}
	if stats.Dropped != 1 || len(cuts) != 1 || cuts[0].ClientToServer != cut {
		t.Fatalf("proxy stats = %+v, want one connection cut at exactly %d bytes client to server", stats, cut)
	}
	assertNoLeaks(t, c, source)
}

package ownertest

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/agent"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/startup"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/testsupport/sshfixture"
	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/ownercontrol"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
	"github.com/PHPCraftdream/ssjack/internal/ownerterminal"
	"github.com/PHPCraftdream/ssjack/internal/ownertui"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/sshauth"
	"github.com/PHPCraftdream/ssjack/internal/startupsecret"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func TestVaultOwnerControlFullProfile(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("production owner helper control is CI-only")
	}
	ctx, cancel := nativeAcceptanceRoot(t, context.Background(), 10*time.Minute)
	defer cancel()
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	defer clear(private)
	public, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	server := sshfixture.StartLoopbackSSH(t, public, sshfixture.ConnectPassword, "owner-control")
	v := vault.NewDirectory()
	defer v.Close()
	target := vault.Target{Address: server.Address(), User: "second", Password: []byte(sshfixture.ConnectPassword), HostKeys: []string{string(ssh.MarshalAuthorizedKey(server.HostKey))}, Usage: "both"}
	defer clear(target.Password)
	serverID, err := v.AddServer("production", "main", target)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(private, "synthetic native writer refusal")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(block.Bytes)
	keyTarget := target
	keyTarget.User, keyTarget.Password, keyTarget.PrivateKey, keyTarget.Usage = "first", nil, pem.EncodeToMemory(block), "agent"
	defer clear(keyTarget.PrivateKey)
	if err := v.SetAccount(serverID, "key-only", keyTarget); err != nil {
		t.Fatal(err)
	}
	password := []byte("synthetic owner control password")
	defer clear(password)
	path := filepath.Join(t.TempDir(), "control.ktav")
	if err := vault.CreateWithRecords(ctx, path, v, password); err != nil {
		t.Fatal(err)
	}
	local, err := ownercontrol.Open(ctx, path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := nativePhaseCleanup(t)
		defer stop()
		if err := local.Close(cleanup); err != nil {
			t.Error("standalone control did not close")
		}
	}()
	helper, err := ownercontrol.Open(ctx, path, password)
	if err != nil {
		t.Fatal("helper did not attach to the existing coordinator")
	}
	defer helper.Detach()
	metadata, err := helper.Backend().Metadata()
	if err != nil || len(metadata.Servers) != 1 {
		t.Fatal("remote helper lost directory metadata")
	}
	status := helper.Backend().Status()
	selected := ownertui.Connection{ServerID: serverID, Account: "main", Revision: status.Database.Revision}
	config, address, err := helper.HumanSSH(ctx, selected)
	if err != nil {
		t.Fatal("helper could not capture a human-permitted saved login")
	}
	change := ownerpacket.DirectoryChange{Action: "edit-server", ServerID: serverID, Fields: [][]byte{[]byte("127.0.0.1:1"), nil}}
	scoped := helper.Backend().(interface {
		AtImportPlan(uint64, uint64) ownertui.Backend
	}).AtImportPlan(selected.Revision, 0)
	if err := scoped.(interface {
		ApplyDirectory(ownerpacket.DirectoryChange) error
	}).ApplyDirectory(change); err != nil {
		t.Fatal(err)
	}
	if err := helper.Backend().Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := helper.HumanSSH(ctx, selected); !errors.Is(err, vault.ErrOwnerRevision) {
		t.Fatal("stale human selection adopted newer account state")
	}
	runner, err := remote.NewCredentialRunner("captured", address, config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner(ctx, "captured", "true", io.Discard, io.Discard); err == nil {
		t.Fatal("shell-only SSH fixture accepted exec")
	}
	if got := server.Authentications(); len(got) != 1 || got[0] != "second|password" {
		t.Fatal("captured helper config changed after saved edits or byte cleanup")
	}
	if err := helper.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := local.Backend().Metadata(); err != nil {
		t.Fatal("remote helper detach closed the local coordinator")
	}
	t.Run("native-command-helper", func(t *testing.T) {
		nativeOwnerCommandAcceptance(t, ctx, path, password, serverID, "native-added", local)
	})
	if err := local.Close(ctx); err != nil {
		t.Fatal(err)
	}
	reopened, err := ownercontrol.Open(ctx, path, password)
	if err != nil || ctx.Err() != nil {
		if reopened != nil {
			cleanup, stop := nativePhaseCleanup(t)
			if closeErr := reopened.Close(cleanup); closeErr != nil {
				t.Error("over-budget reopened control did not close")
			}
			stop()
		}
		t.Fatal("closed standalone control retained writer role or reopen exceeded its lifetime")
	}
	defer func() {
		cleanup, stop := nativePhaseCleanup(t)
		defer stop()
		if err := reopened.Close(cleanup); err != nil {
			t.Error("reopened control did not close")
		}
	}()
	reopenCheck, stopReopenCheck := nativeOperationPhase(t, ctx, 30*time.Second)
	nativeServerAddress(t, reopenCheck, reopened, serverID, server.Address())
	stopReopenCheck()
	closeReopened, stopCloseReopened := nativePhaseCleanup(t)
	if err := reopened.Close(closeReopened); err != nil {
		stopCloseReopened()
		t.Fatal(err)
	}
	stopCloseReopened()
	t.Run("actual-keeper-process", func(t *testing.T) {
		nativeKeeperProcessAcceptance(t, ctx, path, password, serverID, "production", server)
	})
	t.Run("ordinary-ssh-live", func(t *testing.T) { ordinarySSHLiveAcceptance(t, ctx) })
}

const ordinaryLiveOldPassword = "synthetic ordinary live old password"
const ordinaryLiveNewPassword = "synthetic ordinary live replacement password"

type ordinaryLiveFixture struct {
	ctx         context.Context
	server      *sshfixture.LoopbackSSH
	credentials *agent.Credentials
	jobs        *remote.Manager
	helper      *ownercontrol.Control
	selected    ownertui.Connection
}

func newOrdinaryLiveFixture(t *testing.T, parent context.Context) *ordinaryLiveFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	public, err := ssh.NewPublicKey(private.Public())
	clear(private)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	server := sshfixture.StartLoopbackSSH(t, public, sshfixture.ConnectPassword, "owner-control")
	oldPassword := []byte(ordinaryLiveOldPassword)
	newPassword := []byte(ordinaryLiveNewPassword)
	server.SetPasswordLabel(string(oldPassword), "old", true)
	server.SetPasswordLabel(string(newPassword), "new", true)
	v := vault.NewDirectory()
	target := vault.Target{Address: server.Address(), User: "second", Password: oldPassword, HostKeys: []string{string(ssh.MarshalAuthorizedKey(server.HostKey))}, Usage: "both"}
	serverID, err := v.AddServer("production", "main", target)
	if err != nil {
		cancel()
		v.Close()
		t.Fatal(err)
	}
	vaultPassword := []byte("synthetic ordinary live vault password")
	path := filepath.Join(t.TempDir(), "ordinary-live.ktav")
	err = vault.CreateWithRecords(ctx, path, v, vaultPassword)
	v.Close()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	source := startupsecret.New(string(vaultPassword), true)
	clear(vaultPassword)
	credentials, err := agent.Load(startup.WithInput(ctx, source), path, "@production/main")
	source.Close()
	clear(oldPassword)
	clear(newPassword)
	if err != nil || credentials == nil || len(credentials.Targets()) != 1 {
		cancel()
		t.Fatal("synthetic agent startup did not retain its authenticated owner")
	}
	jobs := credentials.Manager(ctx, credentials.Targets(), credentials.Guard(), false)
	helper, err := ownercontrol.Open(ctx, path, []byte("synthetic ordinary live vault password"))
	if err != nil {
		cancel()
		t.Fatal("owner helper did not attach to the synthetic agent")
	}
	status := helper.Backend().Status()
	if status.Database.SSH == nil {
		cancel()
		t.Fatal("synthetic agent startup did not publish live SSH status")
	}
	selected := ownertui.Connection{ServerID: serverID, Account: "main", Revision: status.Database.Revision}
	fixture := &ordinaryLiveFixture{ctx: ctx, server: server, credentials: credentials, jobs: jobs, helper: helper, selected: selected}
	t.Cleanup(func() {
		server.ReleaseSyntheticHolds()
		jobs.Close()
		helper.Detach()
		code := 0
		var result error
		credentials.Finish(&code, &result)
		cancel()
		if code != 0 || result != nil {
			t.Error("synthetic agent owner did not close cleanly")
		}
	})
	return fixture
}

func liveEditAccount(ctx context.Context, helper *ownercontrol.Control, serverID string, revision uint64, password []byte) error {
	change := ownerpacket.DirectoryChange{
		Action: "edit-account", ServerID: serverID, Account: "main",
		Fields: [][]byte{
			[]byte("main"), []byte("second"), []byte("password"),
			append([]byte(nil), password...), []byte("both"),
		},
	}
	defer func() {
		for _, field := range change.Fields {
			clear(field)
		}
	}()
	backend := helper.Backend()
	scoped := backend.(interface {
		AtImportPlan(uint64, uint64) ownertui.Backend
	}).AtImportPlan(revision, 0)
	if err := scoped.(interface {
		ApplyDirectory(ownerpacket.DirectoryChange) error
	}).ApplyDirectory(change); err != nil {
		return err
	}
	return backend.Flush(ctx)
}
func liveHumanShell(t *testing.T, ctx context.Context, helper *ownercontrol.Control, selected ownertui.Connection) (*ssh.Client, *ssh.Session, *bufio.Reader, io.WriteCloser) {
	t.Helper()
	config, address, err := helper.HumanSSH(ctx, selected)
	if err != nil {
		t.Fatal("helper did not capture the original human SSH identity")
	}
	prepared, used, err := sshauth.ForConnection(config)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := sshauth.DialContext(ctx, address, config)
	if err != nil {
		t.Fatal("captured human SSH identity did not connect")
	}
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	t.Cleanup(func() { stopClose(); _ = conn.Close() })
	sshConn, channels, requests, err := ssh.NewClientConn(conn, address, prepared)
	if err != nil || !used() {
		t.Fatal("human connection did not authenticate with the captured identity")
	}
	client := ssh.NewClient(sshConn, channels, requests)
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := session.StdinPipe()
	if err != nil || session.Shell() != nil {
		t.Fatal("captured human SSH shell did not open")
	}
	reader := bufio.NewReader(stdout)
	if line, err := reader.ReadString('\n'); err != nil || !strings.Contains(line, "SYNTHETIC-SSH-READY") {
		t.Fatal("human shell did not become observable")
	}
	return client, session, reader, stdin
}

// ownerChildTail keeps the last bytes of a child's captured output for
// failure-only diagnostics. It is independent of ownerterminal captures, so
// evidence survives capture.Clear in teardown.
const ownerChildTailKeep = 64 << 10

type ownerChildTail struct {
	mu   sync.Mutex
	data []byte
}

func newOwnerChildTail() *ownerChildTail { return &ownerChildTail{} }

func (t *ownerChildTail) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.data = append(t.data, p...)
	if len(t.data) > ownerChildTailKeep {
		t.data = append([]byte(nil), t.data[len(t.data)-ownerChildTailKeep:]...)
	}
	return len(p), nil
}

func (t *ownerChildTail) snapshot() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.data)
}

// ownerChildTee passes through a terminal output reader while recording it.
type ownerChildTee struct {
	io.Reader
	closer io.Closer
	tail   *ownerChildTail
}

// teeOwnerChildOutput wraps terminal.Output; the capture sees the same bytes.
func teeOwnerChildOutput(output io.ReadCloser, tail *ownerChildTail) io.ReadCloser {
	return &ownerChildTee{Reader: output, closer: output, tail: tail}
}

func (t *ownerChildTee) Read(p []byte) (int, error) {
	n, err := t.Reader.Read(p)
	if n > 0 {
		_, _ = t.tail.Write(p[:n])
	}
	return n, err
}

func (t *ownerChildTee) Close() error {
	if t.closer == nil {
		return nil
	}
	return t.closer.Close()
}

// ownerChildExecFail prints failure-only evidence for a finished exec-based
// driver child: command name (never arguments), pid, exit status, output size,
// a digest and a 16 KiB tail of the already-captured combined output.
func ownerChildExecFail(t *testing.T, what string, command *exec.Cmd, output []byte, err error) {
	t.Helper()
	if err == nil {
		return
	}
	name := ""
	if len(command.Args) > 0 {
		name = filepath.Base(command.Args[0])
	}
	pid := 0
	if command.Process != nil {
		pid = command.Process.Pid
	}
	t.Logf("owner child evidence: what=%s name=%s pid=%d exit=%v output-bytes=%d digest=%s\noutput tail:%s",
		what, name, pid, err, len(output), flakediag.Short(output), flakediag.Tail(string(output), 16*1024))
}

// ownerChildTerminal registers failure-only evidence for a PTY terminal child:
// command name, start time, elapsed time, exit status and a 16 KiB tail of the
// captured output plus a goroutine dump. Passing runs add no work.
func ownerChildTerminal(t *testing.T, what, executableName string, terminal *ownerterminal.Terminal, tail *ownerChildTail, started time.Time) {
	t.Helper()
	flakediag.OnFailure(t, func() string {
		state := "still running or unjoined"
		ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
		switch err := terminal.Wait(ctx); {
		case err == nil:
			state = "exited cleanly"
		case ctx.Err() == nil:
			// The child ended on its own: the error is its exit status.
			state = "exited with error: " + flakediag.Tail(err.Error(), 200)
		}
		stop()
		return "owner terminal child: what=" + what +
			" name=" + filepath.Base(executableName) +
			" started=" + started.Format(time.RFC3339) +
			" elapsed=" + time.Since(started).Round(time.Millisecond).String() +
			" exit=" + state +
			"\noutput tail:" + flakediag.Tail(tail.snapshot(), 16*1024) +
			"\ngoroutine dump:\n" + flakediag.GoroutineDump(64*1024)
	})
}

// captureWaitDiag waits for expected terminal output through flakediag
// polling, preserving the caller's fatal message and timeout semantics, and
// registers failure-only evidence (what was waited for, elapsed, last state,
// goroutine dump) via WaitForDesc's OnFailure hook.
func captureWaitDiag(t *testing.T, ctx context.Context, capture *ownerterminal.Capture, expected, failMessage string) {
	t.Helper()
	remaining := time.Until(deadlineOf(ctx))
	if remaining <= 0 {
		remaining = time.Millisecond
	}
	done, _, lastErr := flakediag.WaitForDesc(t, "terminal output "+expected, remaining, func() (string, bool, error) {
		if capture.Contains([]byte(expected)) {
			return "", true, nil
		}
		stop, cancel := context.WithCancel(context.Background())
		cancel()
		if capture.Join(stop) == nil {
			return "process ended before the expected output", false, errors.New("process ended")
		}
		if err := ctx.Err(); err != nil {
			return "wait context ended", false, err
		}
		return "output not seen yet", false, nil
	})
	_ = lastErr
	if !done {
		t.Fatal(failMessage)
	}
}

func deadlineOf(ctx context.Context) (deadline time.Time) {
	if ctx == nil {
		return time.Now().Add(-time.Second)
	}
	deadline, _ = ctx.Deadline()
	return deadline
}

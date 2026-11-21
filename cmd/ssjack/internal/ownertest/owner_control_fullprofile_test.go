package ownertest

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/agent"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/startup"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/testsupport/childdiag"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/testsupport/sshfixture"
	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/ownercontrol"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
	"github.com/PHPCraftdream/ssjack/internal/ownertui"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/sshauth"
	"github.com/PHPCraftdream/ssjack/internal/startupsecret"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func TestVaultOwnerControlFullProfile(t *testing.T) {
	flakediag.Begin(t)
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("production owner helper control is CI-only")
	}
	var dumpScope flakediag.FlowDumpScope
	dumpScope.Bind(t)
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
	phases := childdiag.NewPhases()
	flakediag.OnFailure(t, phases.Render)
	markResult := func(phase string, err error) {
		class := "ok"
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			class = "deadline"
		case errors.Is(err, context.Canceled):
			class = "canceled"
		case err != nil:
			class = "error"
		}
		phases.Mark(phase + "-" + class)
	}
	phases.Mark("control-open-start")
	local, err := ownercontrol.Open(ctx, path, password)
	markResult("control-open", err)
	if err != nil {
		t.Fatal("standalone control did not open")
	}
	defer func() {
		cleanup, stop := nativePhaseCleanup(t)
		defer stop()
		if err := local.Close(cleanup); err != nil {
			t.Error("standalone control did not close")
		}
	}()
	phases.Mark("helper-attach-start")
	helper, err := ownercontrol.Open(ctx, path, password)
	markResult("helper-attach", err)
	if err != nil {
		t.Fatal("helper did not attach to the existing coordinator")
	}
	defer helper.Detach()
	metadata, err := helper.Backend().Metadata()
	if err != nil {
		t.Fatalf("remote helper metadata read failed: class=%s", nativeResultClass(err, "metadata-error"))
	}
	if got := len(metadata.Servers); got != 1 {
		t.Fatalf("remote helper metadata server count: got %d, want 1", got)
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
	authentications := server.Authentications()
	if got := len(authentications); got != 1 {
		t.Fatalf("captured helper authentication count: got %d, want 1", got)
	}
	if authentications[0] != "second|password" {
		t.Fatal("captured helper authentication did not match the saved login")
	}
	phases.Mark("helper-detach-start")
	err = helper.Close(ctx)
	markResult("helper-detach", err)
	if err != nil {
		t.Fatal("helper did not detach from the existing coordinator")
	}
	if _, err := local.Backend().Metadata(); err != nil {
		t.Fatal("remote helper detach closed the local coordinator")
	}
	phases.Mark("native-command-helper-start")
	diagnostics := t
	if t.Run("native-command-helper", func(t *testing.T) {
		flakediag.Begin(t)
		nativeOwnerCommandAcceptance(t, diagnostics, ctx, path, password, serverID, "native-added", local)
	}) {
		phases.Mark("native-command-helper-ok")
	} else {
		phases.Mark("native-command-helper-failed")
	}
	phases.Mark("control-close-start")
	err = local.Close(ctx)
	markResult("control-close", err)
	if err != nil {
		t.Fatal("standalone control did not close before reopen")
	}
	phases.Mark("control-reopen-start")
	reopened, err := ownercontrol.Open(ctx, path, password)
	budgetErr := ctx.Err()
	markResult("control-reopen", err)
	markResult("control-reopen-budget", budgetErr)
	if reopened != nil && (err != nil || budgetErr != nil) {
		cleanup, stop := nativePhaseCleanup(t)
		closeErr := reopened.Close(cleanup)
		markResult("control-reopen-cleanup", closeErr)
		if closeErr != nil {
			t.Error("rejected reopened control did not close")
		}
		stop()
	}
	if err != nil {
		t.Fatal("standalone control reopen failed")
	}
	if budgetErr != nil {
		t.Fatal("standalone control reopened after its context ended")
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
	phases.Mark("control-reclose-start")
	closeReopened, stopCloseReopened := nativePhaseCleanup(t)
	err = reopened.Close(closeReopened)
	markResult("control-reclose", err)
	if err != nil {
		stopCloseReopened()
		t.Fatal("reopened control did not close after verification")
	}
	stopCloseReopened()
	t.Run("actual-keeper-process", func(t *testing.T) {
		nativeKeeperProcessAcceptance(t, ctx, path, password, serverID, "production", server, &dumpScope)
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

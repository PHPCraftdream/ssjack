package ownerrotationtest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/ownerterminal"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

const rotationVaultPassword = "synthetic independent rotation database password"

// rig owns one synthetic vault, SSH fixture and every capture of a scenario.
// Secrets stay in test RAM until finish has joined and scanned every capture.
type rig struct {
	t          *testing.T
	ctx        context.Context
	root, path string
	serverID   string
	password   []byte
	oldPrivate []byte
	oldPEM     []byte
	oldSSH     ssh.PublicKey
	fixture    *rotationSSHFixture
	diag       *rotationDiag

	keeper        *ownerterminal.Terminal
	keeperCapture *ownerterminal.Capture
	captures      []scanner
	secrets       [][]byte
}

func newRig(t *testing.T) *rig {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	t.Cleanup(cancel)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("could not create synthetic old SSH identity")
	}
	r := &rig{t: t, ctx: ctx, oldPrivate: private, password: []byte(rotationVaultPassword), diag: newRotationDiag(t)}
	if r.oldSSH, err = ssh.NewPublicKey(public); err != nil {
		t.Fatal("could not encode synthetic old SSH identity")
	}
	block, err := ssh.MarshalPrivateKey(private, "synthetic in-memory old owner key")
	if err != nil {
		t.Fatal("could not encode synthetic old SSH key")
	}
	r.oldPEM = pem.EncodeToMemory(block)
	clear(block.Bytes)
	r.hide(r.password, r.oldPrivate, r.oldPEM)
	t.Cleanup(r.finish)
	r.fixture = startRotationSSHFixture(t, r.oldSSH)
	target := vault.Target{Address: r.fixture.address(), User: "rotation-user", PrivateKey: append([]byte(nil), r.oldPEM...), HostKeys: []string{string(ssh.MarshalAuthorizedKey(r.fixture.hostKey))}, Usage: "both"}
	defer clear(target.PrivateKey)
	directory := vault.NewDirectory()
	if r.serverID, err = directory.AddServer("production", "main", target); err != nil || r.serverID == "" {
		t.Fatal("could not create synthetic server/account")
	}
	r.root = t.TempDir()
	r.path = filepath.Join(r.root, "rotation.ktav")
	if err := vault.CreateWithRecords(ctx, r.path, directory, r.password); err != nil {
		t.Fatal("could not create synthetic encrypted rotation vault")
	}
	r.diag.mark("rig-created")
	return r
}

type waiter interface {
	Wait(context.Context, string) error
}

// hide registers private input that no capture may ever contain.
func (r *rig) hide(secrets ...[]byte) { r.secrets = append(r.secrets, secrets...) }

func (r *rig) watch(c scanner) { r.captures = append(r.captures, c) }

// expectClean checks a capture's current content, which is all that a still
// running process allows.
func (r *rig) expectClean(c scanner) {
	r.t.Helper()
	for _, secret := range r.secrets {
		if len(secret) > 0 && c.Contains(secret) {
			r.t.Error("capture disclosed synthetic private input")
			return
		}
	}
}

// scan joins finished captures, then checks them. A capture that cannot join is
// reported too: an undrained tail proves nothing.
func (r *rig) scan(ctx context.Context, captures ...scanner) {
	r.t.Helper()
	for _, c := range captures {
		if c.Join(ctx) != nil {
			r.t.Error("capture did not join before the secret scan")
			continue
		}
		r.expectClean(c)
	}
}

// finish runs after every terminal cleanup, on success and on failure alike.
func (r *rig) finish() {
	r.t.Helper()
	ctx, stop := context.WithTimeout(context.Background(), time.Minute)
	defer stop()
	r.scan(ctx, r.captures...)
	for _, c := range r.captures {
		c.Clear()
	}
	for _, secret := range r.secrets {
		clear(secret)
	}
}

func rotationPTYBridge() (string, error) {
	return filepath.Abs(filepath.Join("..", "..", "scripts", "ci", "owner", "owner_pty_bridge.py"))
}

// spawn starts a PTY process; cancelling ctx stops only that process.
func (r *rig) spawn(ctx context.Context, args []string, environment ...string) *ownerterminal.Terminal {
	r.t.Helper()
	executable, err := os.Executable()
	if err != nil {
		r.t.Fatal(err)
	}
	bridge, err := rotationPTYBridge()
	if err != nil {
		r.t.Fatal(err)
	}
	command := ownerterminal.Command{Executable: executable, UnixBridge: bridge, Directory: r.t.TempDir(), Environment: append(rotationTestEnvironment(), environment...), Args: args}
	terminal, err := ownerterminal.Start(ctx, command)
	if err != nil {
		r.t.Fatal("actual owner process did not start")
	}
	r.t.Cleanup(func() { closeRotationTerminal(terminal) })
	tail := newRotationTail()
	terminal.Output = rotationTeeOutput(terminal.Output, tail)
	r.diag.child(rotationChildName(executable), terminal, tail)
	return terminal
}

func (r *rig) unlock(terminal *ownerterminal.Terminal, capture waiter, prompt string) {
	r.t.Helper()
	if capture.Wait(r.ctx, prompt) != nil {
		r.t.Fatal("process did not request its hidden unlock", prompt)
	}
	writeRotationPTY(r.t, terminal, append(append([]byte(nil), r.password...), rotationLineEnding()))
}

// start launches an owner rotate-key child (role cli or owner) after unlock.
func (r *rig) start(role string, refusal bool, extra ...string) (*ownerterminal.Terminal, *rotationPTYCapture) {
	r.t.Helper()
	return r.startIn(r.ctx, role, refusal, extra...)
}

// startIn is start with a process-scoped context, so a test can stop one child.
func (r *rig) startIn(ctx context.Context, role string, refusal bool, extra ...string) (*ownerterminal.Terminal, *rotationPTYCapture) {
	r.t.Helper()
	args := append([]string{"-test.run=^TestRotationComposedProcessChild$", "--", "--vault", r.path, "owner", "rotate-key", "--server", "production", "--account", "main"}, extra...)
	environment := []string{"SSJACK_OWNER_ROTATION_CHILD=" + role}
	if refusal {
		environment = append(environment, "SSJACK_OWNER_ROTATION_EXPECT_REFUSAL=1")
	}
	terminal := r.spawn(ctx, args, environment...)
	capture := captureRotationPTY(terminal.Output)
	r.watch(capture)
	r.unlock(terminal, capture, "Owner database password:")
	r.diag.mark("started-" + role)
	return terminal, capture
}

func (r *rig) startHuman() (*ownerterminal.Terminal, *rotationPTYCapture) {
	r.t.Helper()
	args := []string{"-test.run=^TestRotationComposedProcessChild$", "--", "--vault", r.path, "--server", "production", "--account", "main", "ssh"}
	terminal := r.spawn(r.ctx, args, "SSJACK_OWNER_ROTATION_CHILD=human")
	capture := captureRotationPTY(terminal.Output)
	r.watch(capture)
	r.unlock(terminal, capture, "Vault secret:")
	if capture.Wait(r.ctx, "SYNTHETIC-ROTATION-HUMAN-READY") != nil {
		r.t.Fatal("human SSH CLI did not retain its pinned fixture shell")
	}
	r.diag.mark("human-ready")
	return terminal, capture
}

// startKeeper launches the actual keeper and waits until its MCP job is held.
func (r *rig) startKeeper() {
	r.t.Helper()
	executable, err := os.Executable()
	if err != nil {
		r.t.Fatal(err)
	}
	args := []string{"-test.run=^TestNativeKeeperProcessChild$", "--", "--vault", r.path, "--server", "production", "--account", "main", "run", executable, "-test.run=^TestRotationComposedProcessChild$"}
	r.keeper = r.spawn(r.ctx, args, "SSJACK_OWNER_KEEPER_CHILD=1", "SSJACK_OWNER_TUI_CHILD=1", "SSJACK_OWNER_TUI_CHILD_SECONDS=600", "SSJACK_OWNER_ROTATION_CHILD=mcp")
	r.keeperCapture = ownerterminal.CaptureOutput(r.keeper.Output)
	r.watch(r.keeperCapture)
	r.unlock(r.keeper, r.keeperCapture, "Vault secret:")
	if r.keeperCapture.Wait(r.ctx, "ACTUAL-ROTATION-MCP-OLD-JOB-READY") != nil {
		r.t.Fatal("actual keeper did not launch its authenticated MCP SSH fixture")
	}
	r.diag.mark("keeper-ready")
}

// command sends one MCP fixture command and waits for its acknowledgement.
func (r *rig) command(key, ack string) {
	r.t.Helper()
	writeRotationPTY(r.t, r.keeper, []byte(key+"\n"))
	if r.keeperCapture.Wait(r.ctx, ack) != nil {
		r.t.Fatal("keeper MCP fixture did not acknowledge", key)
	}
}

// oldJobAlive proves the admitted old-key job is unfinished and its SSH
// transport (checked at the fixture) survived the rotation.
func (r *rig) oldJobAlive() {
	r.t.Helper()
	r.command("h", "ACTUAL-ROTATION-MCP-OLD-JOB-ALIVE")
	if r.fixture.holdLost.Load() {
		r.t.Fatal("rotation terminated the old admitted SSH transport")
	}
}

// stopKeeper is the graceful, joined stop. A kill would leave the keeper
// endpoint stale and production deliberately refuses to reuse a stale endpoint,
// so every restart goes through here: q, MCP exit, process exit, drain, close.
func (r *rig) stopKeeper() {
	r.t.Helper()
	r.command("q", "ACTUAL-ROTATION-MCP-STOPPED")
	if err := r.keeper.Wait(r.ctx); err != nil {
		r.t.Fatal("keeper did not finish its graceful run", err)
	}
	if r.keeperCapture.Join(r.ctx) != nil {
		r.t.Fatal("keeper capture did not join after graceful stop")
	}
	if err := r.keeper.Close(r.ctx); err != nil {
		r.t.Fatal("joined keeper terminal could not close cleanly")
	}
	r.keeper, r.keeperCapture = nil, nil
	r.diag.mark("keeper-stopped")
}

// restartKeeper stops the keeper gracefully and starts a fresh one.
func (r *rig) restartKeeper() {
	r.t.Helper()
	r.stopKeeper()
	r.startKeeper()
}

// consent waits for the exact approval phrase of the wanted kind.
func (r *rig) consent(capture *rotationPTYCapture, kind string) string {
	r.t.Helper()
	phrase, err := capture.consent(r.ctx)
	if err != nil || !strings.HasPrefix(phrase, kind+" ") {
		r.t.Fatal("CLI did not display the exact bound consent for", kind)
	}
	return phrase
}

func (r *rig) details(capture *rotationPTYCapture) {
	r.t.Helper()
	for _, marker := range []string{"saved revision:", "operation ID:", "old client-key fingerprint:", "new client-key fingerprint:", "verified server host-key fingerprints:"} {
		waitRotationCapture(r.t, r.ctx, capture, marker)
	}
}

// approve sends the phrase, waits for each expected line and joins the process.
func (r *rig) approve(terminal *ownerterminal.Terminal, capture *rotationPTYCapture, phrase string, lines ...string) {
	r.t.Helper()
	sendRotationConsent(r.t, terminal, phrase)
	for _, line := range lines {
		waitRotationCapture(r.t, r.ctx, capture, line)
	}
	waitRotationPTY(r.t, r.ctx, terminal)
	if capture.Join(r.ctx) != nil {
		r.t.Fatal("CLI output did not join")
	}
}

// recovery runs the verify-only recovery CLI to completion.
func (r *rig) recovery(refusal bool, lines ...string) *rotationPTYCapture {
	r.t.Helper()
	terminal, capture := r.start("cli", refusal, "--recover")
	r.approve(terminal, capture, r.consent(capture, "VERIFY-ONLY"), lines...)
	return capture
}

// snapshotReceipt reads the keeper's completed-rotation receipt through a short-lived owner.
func (r *rig) snapshotReceipt() *vault.RotationInfo {
	r.t.Helper()
	control := r.attach()
	defer control.Detach()
	saved, err := control.RotationSnapshot(r.ctx)
	if err != nil || saved.Rotation == nil || saved.Rotation.Phase != vault.RotationComplete {
		r.t.Fatal("completed rotation receipt unavailable")
	}
	return saved.Rotation
}

// rotate completes one approved rotation and returns the new durable active key.
func (r *rig) rotate() []byte {
	r.t.Helper()
	owner, capture := r.start("cli", false)
	r.approve(owner, capture, r.consent(capture, "ROTATE"), commitLine)
	active := r.activeKey()
	r.hide(active)
	return active
}

// archiveAndNextRotation archives a completed rotation into an encrypted
// recovery file, then prepares the next rotation in a separate invocation.
func (r *rig) archiveAndNextRotation() {
	t := r.t
	firstNew := r.rotate()
	if bytes.Equal(firstNew, r.oldPEM) || r.fixture.mutationCount() != 1 {
		t.Fatal("first rotation did not replace the active key with exactly one remote addition")
	}
	receipt := r.snapshotReceipt()
	firstID, firstPlan, firstDigest := receipt.ID, receipt.PlanID, receipt.CommitDigest
	archive, archiveCapture := r.start("cli", false, "--archive-completed")
	r.approve(archive, archiveCapture, r.consent(archiveCapture, "ARCHIVE"), "Completed rotation archived at revision")
	archived := r.load()
	if archived.Rotation == nil || archived.Rotation.Phase != vault.RotationArchived || archived.Rotation.ID != firstID || archived.Rotation.CommitDigest != firstDigest || archived.Rotation.RecoveryPath == "" {
		archived.Close()
		t.Fatal("archived receipt lost first rotation identity")
	}
	archivePath, archiveDigest := archived.Rotation.RecoveryPath, archived.Rotation.RecoveryDigest
	archived.Close()
	recovery, err := vault.Load(archivePath, r.password)
	if err != nil {
		t.Fatal("encrypted rotation recovery archive could not be reopened")
	}
	defer recovery.Close()
	kept := recovery.Rotation
	if kept == nil || kept.Phase != vault.RotationComplete || kept.ID != firstID || kept.PlanID != firstPlan || kept.ServerID != r.serverID || !bytes.Equal(kept.Original.PrivateKey, r.oldPEM) || !bytes.Equal(kept.NewPrivate, firstNew) {
		t.Fatal("encrypted recovery archive did not retain the complete original rotation")
	}
	if profile, err := recovery.AccountProfile(r.serverID, "main"); err != nil || !bytes.Equal(recovery.Targets[profile].PrivateKey, firstNew) {
		t.Fatal("encrypted recovery archive selected active key did not match the replacement")
	}
	ciphertext, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal("saved encrypted rotation archive missing")
	}
	digest := sha256.Sum256(ciphertext)
	clear(ciphertext)
	if hex.EncodeToString(digest[:]) != archiveDigest {
		t.Fatal("archived ciphertext did not match its receipt digest")
	}
	r.scan(r.ctx, archiveCapture)
	r.expectClean(r.keeperCapture)
	if !r.fixture.hasKeyFromPrivate(r.oldPrivate) || !r.fixture.hasKeyFromPrivate(firstNew) || r.fixture.mutationCount() != 1 {
		t.Fatal("archive retired a remote key or attempted another add")
	}
	r.restartKeeper()
	inspect, inspectCapture := r.start("cli", false, "--recover")
	if inspectCapture.Wait(r.ctx, "Archived completed rotation receipt:") != nil {
		t.Fatal("archived receipt inspection was not available")
	}
	waitRotationPTY(t, r.ctx, inspect)
	r.scan(r.ctx, inspectCapture)
	secondNew := r.rotate()
	loaded := r.load()
	next := loaded.Rotation
	if bytes.Equal(secondNew, firstNew) || bytes.Equal(secondNew, r.oldPEM) || next == nil || next.Phase != vault.RotationComplete || next.PlanID <= firstPlan || next.ID == firstID {
		loaded.Close()
		t.Fatal("next invocation did not persist a newer plan with a distinct replacement identity")
	}
	loaded.Close()
	fingerprint := publicFingerprint(t, secondNew)
	before := r.fingerprintCount(fingerprint)
	if before == 0 {
		t.Fatal("second invocation lacked a replacement-key verification handshake")
	}
	r.command("n", "ACTUAL-ROTATION-MCP-NEW-JOB-DONE")
	r.waitFingerprints(fingerprint, before+1)
	if got := r.fingerprintCount(fingerprint); got != before+1 {
		t.Fatal("ordinary agent job did not add exactly one replacement-key SSH handshake")
	}
	for _, key := range [][]byte{r.oldPrivate, firstNew, secondNew} {
		if !r.fixture.hasKeyFromPrivate(key) {
			t.Fatal("a previously authorized remote key was retired")
		}
	}
	if r.fixture.mutationCount() != 2 {
		t.Fatal("next rotation did not make exactly one further remote addition")
	}
	r.stopKeeper()
	r.expectInventory(filepath.Base(r.path), filepath.Base(archivePath))
}

// retireOldKey completes a rotation, then removes the old remote key in a
// separate exact-confirmed invocation that authenticates with the new key.
// A repeat is harmless, and local journal state never changes.
func (r *rig) retireOldKey() {
	t := r.t
	newKey := r.rotate()
	if r.fixture.mutationCount() != 1 || !r.fixture.hasKeyFromPrivate(r.oldPrivate) || !r.fixture.hasKeyFromPrivate(newKey) {
		t.Fatal("rotation did not leave both keys authorized before retirement")
	}
	for attempt := 0; attempt < 2; attempt++ {
		retire, capture := r.start("cli", false, "--retire-old")
		r.approve(retire, capture, r.consent(capture, "RETIRE-OLD-KEY"), "Old remote key retired:")
		r.scan(r.ctx, capture)
		r.expectClean(r.keeperCapture)
		if r.fixture.hasKeyFromPrivate(r.oldPrivate) || !r.fixture.hasKeyFromPrivate(newKey) || r.fixture.mutationCount() != 2 {
			t.Fatalf("attempt %d: retirement did not remove exactly the old key once", attempt)
		}
		if r.diskPhase() != vault.RotationComplete {
			t.Fatal("retirement changed the local journal phase")
		}
	}
	r.stopKeeper()
	r.expectInventory(filepath.Base(r.path))
}

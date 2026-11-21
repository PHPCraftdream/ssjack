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
	children      map[*ownerterminal.Terminal]*rotationChild
	captureOwners map[scanner]*rotationChild
	nextChild     int
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
	if r.serverID, err = directory.AddServer("production", "main", target); err != nil {
		r.failCondition("synthetic-server-account", "add-error", "could not create synthetic server/account")
	}
	if r.serverID == "" {
		r.failCondition("synthetic-server-account", "missing-server-id", "could not create synthetic server/account")
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

type rotationChild struct {
	id       rotationChildID
	capture  scanner
	readDone bool // observed through an existing keeper Wait or Join
}

func (c *rotationChild) stats() rotationCaptureStats {
	if c == nil {
		return rotationCaptureStats{}
	}
	return captureStats(c.capture, c.readDone)
}

func captureStats(c any, readDone bool) rotationCaptureStats {
	switch c := c.(type) {
	case *rotationPTYCapture:
		return c.stats()
	case *ownerterminal.Capture:
		s := rotationCaptureStats{known: true, readDone: readDone}
		// Capture.Clear zeros the backing bytes without changing the length.
		c.Inspect(func(data []byte, total int, overflow bool) {
			s.retained, s.total, s.overflow = len(data), total, overflow
			s.discarded = total - len(data)
		})
		return s
	default:
		return rotationCaptureStats{}
	}
}

func (r *rig) watch(terminal *ownerterminal.Terminal, c scanner) {
	r.captures = append(r.captures, c)
	if r.captureOwners == nil {
		r.captureOwners = make(map[scanner]*rotationChild)
	}
	child := r.children[terminal]
	child.capture = c
	r.captureOwners[c] = child
}

func (r *rig) recordCapture(name, class string, c any, start time.Time, stats rotationCaptureStats) {
	var id rotationChildID
	if c, ok := c.(scanner); ok {
		if child := r.captureOwners[c]; child != nil {
			id = child.id
		}
	}
	r.diag.record(name, class, id, start, stats)
}

func (r *rig) captureStats(c any) rotationCaptureStats {
	if c, ok := c.(scanner); ok {
		if child := r.captureOwners[c]; child != nil {
			return child.stats()
		}
	}
	return captureStats(c, false)
}

func rotationOutputOutcome(err error, stats rotationCaptureStats) string {
	if err == nil {
		return "matched"
	}
	if class := rotationContextOutcome(err); class != "" {
		return class
	}
	if stats.overflow {
		return "capture-overflow"
	}
	if stats.readDone {
		return "read-ended-without-match"
	}
	return "output-unavailable"
}

// expected must be a fixed test marker, never a value read from the child.
func (r *rig) waitOutput(capture waiter, expected string) error {
	return r.waitOutputNamed(capture, expected, expected)
}

func (r *rig) waitOutputNamed(capture waiter, expected, condition string) error {
	start := time.Now()
	err := capture.Wait(r.ctx, expected)
	stats := r.captureStats(capture)
	if keeper, ok := capture.(*ownerterminal.Capture); ok && err == ownerterminal.ErrTerminal && !stats.overflow {
		// Without overflow, the keeper Wait returns ErrTerminal only after done.
		stats.readDone = true
		if child := r.captureOwners[keeper]; child != nil {
			child.readDone = true
		}
	}
	r.recordCapture(condition, rotationOutputOutcome(err, stats), capture, start, stats)
	return err
}

func (r *rig) joinCapture(ctx context.Context, c scanner, condition string) error {
	start := time.Now()
	err := c.Join(ctx)
	class := "drained"
	if err != nil {
		class = rotationContextOutcome(err)
		if class != "" {
			class = "unjoined-" + class
		} else {
			class = "drain-error"
		}
	}
	if _, ok := c.(*ownerterminal.Capture); ok && (err == nil || err == ownerterminal.ErrTerminal) {
		if child := r.captureOwners[c]; child != nil {
			child.readDone = true
		}
	}
	stats := r.captureStats(c)
	if class == "drain-error" && stats.readDone && stats.overflow {
		class = "drained-with-discard"
	}
	r.recordCapture(condition, class, c, start, stats)
	return err
}

// condition must be a fixed test label. Cleanup is recorded separately.
func (r *rig) waitChild(terminal *ownerterminal.Terminal, condition string) error {
	start := time.Now()
	err := terminal.Wait(r.ctx)
	r.recordChild(terminal, condition, rotationExitOutcome(err, false), start)
	return err
}

func (r *rig) closeChild(ctx context.Context, terminal *ownerterminal.Terminal, condition string) error {
	start := time.Now()
	err := terminal.Close(ctx)
	r.recordChild(terminal, condition, rotationExitOutcome(err, true), start)
	return err
}

func (r *rig) recordChild(terminal *ownerterminal.Terminal, condition, class string, start time.Time) {
	child := r.children[terminal]
	var id rotationChildID
	if child != nil {
		id = child.id
	}
	r.diag.record(condition, class, id, start, child.stats())
}

// expectClean checks a capture's current content, which is all that a still
// running process allows.
func (r *rig) expectClean(c scanner) {
	r.t.Helper()
	start := time.Now()
	for _, secret := range r.secrets {
		if len(secret) > 0 && c.Contains(secret) {
			r.recordCapture("secret-scan", "disclosure", c, start, r.captureStats(c))
			r.t.Error("capture disclosed synthetic private input")
			return
		}
	}
	r.recordCapture("secret-scan", "clean", c, start, r.captureStats(c))
}

// scan joins finished captures, then checks them. A capture that cannot join is
// reported too: an undrained tail proves nothing.
func (r *rig) scan(ctx context.Context, captures ...scanner) {
	r.t.Helper()
	for _, c := range captures {
		if r.joinCapture(ctx, c, "secret-scan-drain") != nil {
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
		start := time.Now()
		stats := r.captureStats(c)
		if keeper, ok := c.(*ownerterminal.Capture); ok && r.t.Failed() {
			operation, found := inspectRotationMCP(keeper)
			class := "not-observed"
			if found {
				class = "received"
			}
			r.diag.recordEvidence("keeper-mcp-operation", class, r.captureOwners[c].id, time.Time{}, stats, rotationEvidence{mcpOperation: operation})
		}
		c.Clear()
		r.recordCapture("capture-clear", "cleared", c, start, stats)
	}
	for _, secret := range r.secrets {
		clear(secret)
	}
	r.diag.mark("rig-finished")
}

func rotationPTYBridge() (string, error) {
	return filepath.Abs(filepath.Join("..", "..", "scripts", "ci", "owner", "owner_pty_bridge.py"))
}

// spawn starts a PTY process; cancelling ctx stops only that process.
func (r *rig) spawn(ctx context.Context, role string, args []string, environment ...string) *ownerterminal.Terminal {
	r.t.Helper()
	executable, err := os.Executable()
	if err != nil {
		r.t.Fatal("could not locate rotation test executable")
	}
	bridge, err := rotationPTYBridge()
	if err != nil {
		r.t.Fatal("could not locate rotation PTY bridge")
	}
	command := ownerterminal.Command{Executable: executable, UnixBridge: bridge, Directory: r.t.TempDir(), Environment: append(rotationTestEnvironment(), environment...), Args: args}
	r.nextChild++
	id := rotationChildID{role: role, seq: r.nextChild}
	start := time.Now()
	terminal, err := ownerterminal.Start(ctx, command)
	if err != nil {
		r.diag.record("child-start", "start-failed", id, start, rotationCaptureStats{})
		r.t.Fatal("actual owner process did not start")
	}
	r.t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Minute)
		defer stop()
		_ = r.closeChild(cleanup, terminal, "child-cleanup-close")
	})
	if r.children == nil {
		r.children = make(map[*ownerterminal.Terminal]*rotationChild)
	}
	r.children[terminal] = &rotationChild{id: id}
	r.diag.record("child-start", "started", id, start, rotationCaptureStats{})
	return terminal
}

func (r *rig) unlock(terminal *ownerterminal.Terminal, capture waiter, prompt string) {
	r.t.Helper()
	if r.waitOutputNamed(capture, prompt, "unlock: "+prompt) != nil {
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
	terminal := r.spawn(ctx, role, args, environment...)
	capture := captureRotationPTY(terminal.Output)
	r.watch(terminal, capture)
	r.unlock(terminal, capture, "Owner database password:")
	r.diag.mark("started-" + role)
	return terminal, capture
}

func (r *rig) startHuman() (*ownerterminal.Terminal, *rotationPTYCapture) {
	r.t.Helper()
	args := []string{"-test.run=^TestRotationComposedProcessChild$", "--", "--vault", r.path, "--server", "production", "--account", "main", "ssh"}
	terminal := r.spawn(r.ctx, "human", args, "SSJACK_OWNER_ROTATION_CHILD=human")
	capture := captureRotationPTY(terminal.Output)
	r.watch(terminal, capture)
	r.unlock(terminal, capture, "Vault secret:")
	if r.waitOutput(capture, "SYNTHETIC-ROTATION-HUMAN-READY") != nil {
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
		r.t.Fatal("could not locate rotation test executable")
	}
	args := []string{"-test.run=^TestNativeKeeperProcessChild$", "--", "--vault", r.path, "--server", "production", "--account", "main", "run", executable, "-test.run=^TestRotationComposedProcessChild$"}
	r.keeper = r.spawn(r.ctx, "keeper", args, "SSJACK_OWNER_KEEPER_CHILD=1", "SSJACK_OWNER_TUI_CHILD=1", "SSJACK_OWNER_TUI_CHILD_SECONDS=600", "SSJACK_OWNER_ROTATION_CHILD=mcp")
	r.keeperCapture = ownerterminal.CaptureOutput(r.keeper.Output)
	r.watch(r.keeper, r.keeperCapture)
	r.unlock(r.keeper, r.keeperCapture, "Vault secret:")
	if r.waitOutput(r.keeperCapture, "ACTUAL-ROTATION-MCP-OLD-JOB-READY") != nil {
		r.t.Fatal("actual keeper did not launch its authenticated MCP SSH fixture")
	}
	r.diag.mark("keeper-ready")
}

func (r *rig) waitHold(condition string) error {
	start := time.Now()
	err := r.fixture.waitHold(r.ctx)
	r.recordCapture(condition, rotationOperationOutcome(err, "ready", "wait-error"), r.keeperCapture, start, r.captureStats(r.keeperCapture))
	return err
}

// command sends one MCP fixture command and waits for its acknowledgement.
func (r *rig) command(key, ack string) {
	r.t.Helper()
	writeRotationPTY(r.t, r.keeper, []byte(key+"\n"))
	if r.waitOutput(r.keeperCapture, ack) != nil {
		r.t.Fatal("keeper MCP fixture did not acknowledge", key)
	}
}

// oldJobAlive proves the admitted old-key job is unfinished and its SSH
// transport (checked at the fixture) survived the rotation.
func (r *rig) oldJobAlive() {
	r.t.Helper()
	r.command("h", "ACTUAL-ROTATION-MCP-OLD-JOB-ALIVE")
	if r.fixture.holdLost.Load() {
		r.failCondition("old-job-transport", "lost", "rotation terminated the old admitted SSH transport")
	}
}

// stopKeeper is the graceful, joined stop. A kill would leave the keeper
// endpoint stale and production deliberately refuses to reuse a stale endpoint,
// so every restart goes through here: q, MCP exit, process exit, drain, close.
func (r *rig) stopKeeper() {
	r.t.Helper()
	r.command("q", "ACTUAL-ROTATION-MCP-STOPPED")
	if err := r.waitChild(r.keeper, "keeper-graceful-exit"); err != nil {
		r.t.Fatal("keeper did not finish its graceful run")
	}
	if r.joinCapture(r.ctx, r.keeperCapture, "keeper-graceful-drain") != nil {
		r.t.Fatal("keeper capture did not join after graceful stop")
	}
	if err := r.closeChild(r.ctx, r.keeper, "keeper-graceful-close"); err != nil {
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
	start := time.Now()
	phrase, err := capture.consent(r.ctx)
	stats := r.captureStats(capture)
	r.recordCapture("consent wait: "+kind, rotationOutputOutcome(err, stats), capture, start, stats)
	if err != nil {
		r.t.Fatal("CLI did not display the exact bound consent for", kind)
	}
	if !strings.HasPrefix(phrase, kind+" ") {
		r.recordCapture("consent kind: "+kind, "wrong-kind", capture, time.Time{}, stats)
		r.t.Fatal("CLI did not display the exact bound consent for", kind)
	}
	r.recordCapture("consent kind: "+kind, "matched", capture, time.Time{}, stats)
	return phrase
}

func (r *rig) details(capture *rotationPTYCapture) {
	r.t.Helper()
	for _, marker := range []string{"saved revision:", "operation ID:", "old client-key fingerprint:", "new client-key fingerprint:", "verified server host-key fingerprints:"} {
		if r.waitOutput(capture, marker) != nil {
			r.t.Fatal("actual rotate-key CLI output missing", marker)
		}
	}
}

// approve sends the phrase, waits for each expected line and joins the process.
func (r *rig) approve(terminal *ownerterminal.Terminal, capture *rotationPTYCapture, phrase string, lines ...string) {
	r.t.Helper()
	sendRotationConsent(r.t, terminal, phrase)
	for _, line := range lines {
		if r.waitOutput(capture, line) != nil {
			r.t.Fatal("actual rotate-key CLI output missing", line)
		}
	}
	if r.waitChild(terminal, "approved-cli-exit") != nil {
		r.t.Fatal("actual rotate-key CLI process failed")
	}
	if r.joinCapture(r.ctx, capture, "approved-cli-drain") != nil {
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

func (r *rig) failCondition(name, class, message string) {
	r.t.Helper()
	r.diag.outcome(name, class)
	r.t.Fatal(message)
}

// snapshotReceipt reads the keeper's completed-rotation receipt through a short-lived owner.
func (r *rig) snapshotReceipt() *vault.RotationInfo {
	r.t.Helper()
	control := r.attach()
	defer control.Detach()
	start := time.Now()
	saved, err := control.RotationSnapshot(r.ctx)
	class := rotationSnapshotState(saved, err, false, true)
	r.recordSnapshot("completed-receipt-snapshot", class, start, saved, err)
	if class != "matched" {
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
	const firstRotationFailure = "first rotation did not replace the active key with exactly one remote addition"
	if bytes.Equal(firstNew, r.oldPEM) {
		r.failCondition("first-rotation", "active-key-unchanged", firstRotationFailure)
	}
	if r.fixture.mutationCount() != 1 {
		r.failCondition("first-rotation", "wrong-mutation-count", firstRotationFailure)
	}
	receipt := r.snapshotReceipt()
	firstID, firstPlan, firstDigest := receipt.ID, receipt.PlanID, receipt.CommitDigest
	archive, archiveCapture := r.start("cli", false, "--archive-completed")
	r.approve(archive, archiveCapture, r.consent(archiveCapture, "ARCHIVE"), "Completed rotation archived at revision")
	archived := r.load()
	archiveClass := "matched"
	switch {
	case archived.Rotation == nil:
		archiveClass = "missing-receipt"
	case archived.Rotation.Phase != vault.RotationArchived:
		archiveClass = "wrong-phase"
	case archived.Rotation.ID != firstID:
		archiveClass = "rotation-id-mismatch"
	case archived.Rotation.CommitDigest != firstDigest:
		archiveClass = "commit-digest-mismatch"
	case archived.Rotation.RecoveryPath == "":
		archiveClass = "missing-recovery-path"
	}
	if archiveClass != "matched" {
		archived.Close()
		r.failCondition("archived-receipt", archiveClass, "archived receipt lost first rotation identity")
	}
	r.diag.outcome("archived-receipt", archiveClass)
	archivePath, archiveDigest := archived.Rotation.RecoveryPath, archived.Rotation.RecoveryDigest
	archived.Close()
	recovery, err := vault.Load(archivePath, r.password)
	if err != nil {
		r.failCondition("recovery-archive-load", "load-error", "encrypted rotation recovery archive could not be reopened")
	}
	defer recovery.Close()
	const recoveryFailure = "encrypted recovery archive did not retain the complete original rotation"
	switch kept := recovery.Rotation; {
	case kept == nil:
		r.failCondition("recovery-receipt", "missing-receipt", recoveryFailure)
	case kept.Phase != vault.RotationComplete:
		r.failCondition("recovery-receipt", "wrong-phase", recoveryFailure)
	case kept.ID != firstID:
		r.failCondition("recovery-receipt", "rotation-id-mismatch", recoveryFailure)
	case kept.PlanID != firstPlan:
		r.failCondition("recovery-receipt", "plan-id-mismatch", recoveryFailure)
	case kept.ServerID != r.serverID:
		r.failCondition("recovery-receipt", "server-id-mismatch", recoveryFailure)
	case !bytes.Equal(kept.Original.PrivateKey, r.oldPEM):
		r.failCondition("recovery-receipt", "original-key-mismatch", recoveryFailure)
	case !bytes.Equal(kept.NewPrivate, firstNew):
		r.failCondition("recovery-receipt", "replacement-key-mismatch", recoveryFailure)
	}
	r.diag.outcome("recovery-receipt", "matched")
	const profileFailure = "encrypted recovery archive selected active key did not match the replacement"
	profile, err := recovery.AccountProfile(r.serverID, "main")
	if err != nil {
		r.failCondition("recovery-profile", "lookup-error", profileFailure)
	}
	if !bytes.Equal(recovery.Targets[profile].PrivateKey, firstNew) {
		r.failCondition("recovery-profile", "active-key-mismatch", profileFailure)
	}
	ciphertext, err := os.ReadFile(archivePath)
	if err != nil {
		r.failCondition("recovery-archive-read", "read-error", "saved encrypted rotation archive missing")
	}
	digest := sha256.Sum256(ciphertext)
	clear(ciphertext)
	if hex.EncodeToString(digest[:]) != archiveDigest {
		r.failCondition("recovery-archive-digest", "mismatch", "archived ciphertext did not match its receipt digest")
	}
	r.scan(r.ctx, archiveCapture)
	r.expectClean(r.keeperCapture)
	const archiveRemoteFailure = "archive retired a remote key or attempted another add"
	switch {
	case !r.fixture.hasKeyFromPrivate(r.oldPrivate):
		r.failCondition("archive-remote-keys", "old-key-missing", archiveRemoteFailure)
	case !r.fixture.hasKeyFromPrivate(firstNew):
		r.failCondition("archive-remote-keys", "replacement-key-missing", archiveRemoteFailure)
	case r.fixture.mutationCount() != 1:
		r.failCondition("archive-remote-keys", "wrong-mutation-count", archiveRemoteFailure)
	}
	r.restartKeeper()
	inspect, inspectCapture := r.start("cli", false, "--recover")
	if r.waitOutput(inspectCapture, "Archived completed rotation receipt:") != nil {
		t.Fatal("archived receipt inspection was not available")
	}
	if r.waitChild(inspect, "archive-inspection-exit") != nil {
		t.Fatal("actual rotate-key CLI process failed")
	}
	r.scan(r.ctx, inspectCapture)
	secondNew := r.rotate()
	loaded := r.load()
	next := loaded.Rotation
	nextClass := "matched"
	switch {
	case bytes.Equal(secondNew, firstNew):
		nextClass = "prior-replacement-reused"
	case bytes.Equal(secondNew, r.oldPEM):
		nextClass = "original-key-reused"
	case next == nil:
		nextClass = "missing-receipt"
	case next.Phase != vault.RotationComplete:
		nextClass = "wrong-phase"
	case next.PlanID <= firstPlan:
		nextClass = "plan-not-newer"
	case next.ID == firstID:
		nextClass = "rotation-id-reused"
	}
	if nextClass != "matched" {
		loaded.Close()
		r.failCondition("next-rotation-receipt", nextClass, "next invocation did not persist a newer plan with a distinct replacement identity")
	}
	loaded.Close()
	r.diag.outcome("next-rotation-receipt", nextClass)
	fingerprint := publicFingerprint(t, secondNew)
	before := r.fingerprintCount(fingerprint)
	r.expectHandshake("next-rotation-verification-at-least-one", before, "second invocation lacked a replacement-key verification handshake")
	r.command("n", "ACTUAL-ROTATION-MCP-NEW-JOB-DONE")
	r.waitFingerprints(fingerprint, before+1)
	got := r.fingerprintCount(fingerprint)
	class := "matched"
	if got != before+1 {
		class = "wrong-handshake-count"
	}
	r.recordHandshakes("ordinary-agent-job-exact", class, time.Time{}, got, before+1)
	if got != before+1 {
		t.Fatal("ordinary agent job did not add exactly one replacement-key SSH handshake")
	}
	for _, key := range [][]byte{r.oldPrivate, firstNew, secondNew} {
		if !r.fixture.hasKeyFromPrivate(key) {
			r.failCondition("next-rotation-remote-keys", "authorized-key-missing", "a previously authorized remote key was retired")
		}
	}
	if r.fixture.mutationCount() != 2 {
		r.failCondition("next-rotation-mutations", "wrong-mutation-count", "next rotation did not make exactly one further remote addition")
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
	const preRetireFailure = "rotation did not leave both keys authorized before retirement"
	switch {
	case r.fixture.mutationCount() != 1:
		r.failCondition("before-retirement", "wrong-mutation-count", preRetireFailure)
	case !r.fixture.hasKeyFromPrivate(r.oldPrivate):
		r.failCondition("before-retirement", "old-key-missing", preRetireFailure)
	case !r.fixture.hasKeyFromPrivate(newKey):
		r.failCondition("before-retirement", "replacement-key-missing", preRetireFailure)
	}
	for attempt := 0; attempt < 2; attempt++ {
		retire, capture := r.start("cli", false, "--retire-old")
		r.approve(retire, capture, r.consent(capture, "RETIRE-OLD-KEY"), "Old remote key retired:")
		r.scan(r.ctx, capture)
		r.expectClean(r.keeperCapture)
		class := "matched"
		switch {
		case r.fixture.hasKeyFromPrivate(r.oldPrivate):
			class = "old-key-still-present"
		case !r.fixture.hasKeyFromPrivate(newKey):
			class = "replacement-key-missing"
		case r.fixture.mutationCount() != 2:
			class = "wrong-mutation-count"
		}
		r.diag.outcome("after-retirement", class)
		if class != "matched" {
			t.Fatalf("attempt %d: retirement did not remove exactly the old key once", attempt)
		}
		if r.diskPhase() != vault.RotationComplete {
			r.failCondition("retirement-disk-phase", "wrong-phase", "retirement changed the local journal phase")
		}
	}
	r.stopKeeper()
	r.expectInventory(filepath.Base(r.path))
}

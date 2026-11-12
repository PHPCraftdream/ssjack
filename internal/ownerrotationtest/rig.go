package ownerrotationtest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
	r := &rig{t: t, ctx: ctx, oldPrivate: private, password: []byte(rotationVaultPassword)}
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
	return filepath.Abs(filepath.Join("..", "..", "scripts", "ci", "owner_pty_bridge.py"))
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

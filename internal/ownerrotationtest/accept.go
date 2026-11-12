package ownerrotationtest

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/vault"
)

// Accept is the actual-process acceptance of owner key rotation. Every scenario
// uses a launched keeper, launched owner CLIs and an in-memory SSH fixture.
func Accept(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("actual CLI/keeper key rotation acceptance runs in public full-profile CI")
	}
	t.Run("composed-success", runSuccessfulAcceptance)
	for _, scenario := range []struct {
		name string
		run  func(*rig)
	}{
		{"pre-effect-persistence", (*rig).preEffectRefusal},
		{"lost-add-ack-restart", func(r *rig) { r.effectFailure("lost-add-ack-restart") }},
		{"new-login-refusal", func(r *rig) { r.effectFailure("new-login-refusal") }},
		{"post-add-persistence-restart", func(r *rig) { r.effectFailure("post-add-persistence-restart") }},
		{"archive-next", (*rig).archiveAndNextRotation},
		{"owner-crash-inflight", (*rig).ownerCrashInFlight},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			r := newRig(t)
			r.startKeeper()
			if r.fixture.waitHold(r.ctx) != nil {
				t.Fatal("old-key MCP SSH job did not remain held")
			}
			scenario.run(r)
		})
	}
}

func runSuccessfulAcceptance(t *testing.T) {
	r := newRig(t)
	r.startKeeper()
	if r.fixture.waitHold(r.ctx) != nil {
		t.Fatal("actual ordinary MCP job did not retain an old-key SSH connection")
	}
	oldFingerprint := ssh.FingerprintSHA256(r.oldSSH)
	if r.fingerprintCount(oldFingerprint) == 0 {
		t.Fatal("initial actual MCP job was not authenticated by the saved old key")
	}
	control := r.attach()
	defer control.Detach()
	human, humanCapture := r.startHuman()
	r.wrongApprovalAndCancel()
	r.expectEncrypted(r.path)
	owner, capture := r.start("cli", false)
	phrase := r.consent(capture, "ROTATE")
	r.details(capture)
	r.approve(owner, capture, phrase, "Encrypted selected-account commit: durable at revision")
	_, newPublic := r.committed(control)
	newFingerprint := ssh.FingerprintSHA256(newPublic)
	if text, overflow := capture.text(); overflow || !strings.Contains(text, newFingerprint) {
		t.Fatal("displayed replacement fingerprint did not match the durably selected SSH key")
	}
	r.expectEncrypted(r.path)
	if !r.fixture.hasKey(r.oldSSH) || !r.fixture.hasKey(newPublic) {
		t.Fatal("fixture remote authorization did not retain old and add new key")
	}
	before := r.fingerprintCount(newFingerprint)
	if before == 0 {
		t.Fatal("rotation proof did not include a new-key SSH handshake")
	}
	writeRotationPTY(t, human, []byte("still-old-human\n"))
	if humanCapture.Wait(r.ctx, "HUMAN-ECHO:still-old-human") != nil {
		t.Fatal("rotation terminated or replaced the actual running human CLI connection")
	}
	r.oldJobAlive()
	r.command("n", "ACTUAL-ROTATION-MCP-NEW-JOB-DONE")
	r.waitFingerprints(newFingerprint, before+1)
	if r.fingerprintCount(oldFingerprint) == 0 {
		t.Fatal("actual SSH handshakes did not prove both retained old and selected new key identities")
	}
	r.command("o", "ACTUAL-ROTATION-MCP-OLD-JOB-DONE")
	writeRotationPTY(t, human, []byte("exit\n"))
	if err := human.Wait(r.ctx); err != nil {
		t.Fatal("actual human CLI did not exit its pinned shell cleanly", err)
	}
	r.stopKeeper()
	r.scan(r.ctx, r.captures...)
	r.expectInventory("rotation.ktav")
}

// wrongApprovalAndCancel proves a wrong approval and a prepared-plan cancel
// cause no remote effect. The cancelled candidate stays in test RAM, registered
// as a secret, so the keeper and every later capture are scanned for it too.
func (r *rig) wrongApprovalAndCancel() {
	t, mutations := r.t, r.fixture.mutationCount()
	refused, capture := r.start("cli", true)
	r.consent(capture, "ROTATE")
	r.details(capture)
	r.retainCandidate()
	writeRotationPTY(t, refused, append([]byte("ROTATE wrong synthetic approval"), rotationLineEnding()))
	waitRotationPTY(t, r.ctx, refused)
	r.scan(r.ctx, capture)
	r.expectClean(r.keeperCapture)
	if r.fixture.mutationCount() != mutations || !r.fixture.hasKeyFromPrivate(r.oldPrivate) {
		t.Fatal("wrong approval caused remote key mutation")
	}
	r.expectJournal(vault.RotationPrepared)
	cancel, cancelCapture := r.start("cli", false, "--recover", "--cancel-prepared")
	r.approve(cancel, cancelCapture, r.consent(cancelCapture, "CANCEL-PREPARED"), "Prepared encrypted intent cancelled; no remote effect was attempted.")
	r.scan(r.ctx, cancelCapture)
	r.expectClean(r.keeperCapture)
	if r.fixture.mutationCount() != mutations || !r.fixture.hasKeyFromPrivate(r.oldPrivate) {
		t.Fatal("prepared-plan cancellation caused remote mutation")
	}
	r.expectJournal(vault.RotationCancelled)
}

const commitLine = "Encrypted selected-account commit: durable at revision"

func (r *rig) expectEffects(mutations int, phase string) {
	r.t.Helper()
	if r.fixture.mutationCount() != mutations || r.diskPhase() != phase || !r.fixture.hasKeyFromPrivate(r.oldPrivate) {
		r.t.Fatal("remote mutation count, durable phase or retained old key differs from the expected state", phase)
	}
}

// effectFailure drives an Add whose outcome fails after its remote effect, then
// recovers with a restarted keeper and verify-only consent, never replaying Add.
func (r *rig) effectFailure(kind string) {
	t, lock := r.t, r.path+".lock"
	want := vault.RotationUnknown
	switch kind {
	case "lost-add-ack-restart":
		r.fixture.configure(func(f *rotationSSHFixture) { f.loseAck = true })
	case "new-login-refusal":
		want = vault.RotationAdded
		r.fixture.configure(func(f *rotationSSHFixture) { f.rejectNew = true })
	case "post-add-persistence-restart":
		want = vault.RotationAttempting
		r.fixture.configure(func(f *rotationSSHFixture) {
			f.afterAdd = func() error { return os.WriteFile(lock, []byte("synthetic-owned-lock"), 0600) }
		})
	}
	owner, capture := r.start("cli", true)
	phrase := r.consent(capture, "ROTATE")
	r.details(capture)
	r.approve(owner, capture, phrase)
	r.retainCandidate()
	r.expectEffects(1, want)
	r.expectJournal(want)
	if kind == "post-add-persistence-restart" {
		if os.Remove(lock) != nil || r.retryDatabase() != vault.RotationAdded {
			t.Fatal("explicit local-save retry did not persist the acknowledged addition")
		}
	}
	r.restartKeeper()
	if kind == "new-login-refusal" {
		r.recovery(true)
		r.expectEffects(1, vault.RotationAdded)
	} else {
		r.recovery(false, commitLine)
		r.expectEffects(1, vault.RotationComplete)
	}
	r.stopKeeper()
	r.expectInventory("rotation.ktav")
}

// preEffectRefusal makes local persistence fail after preparation: no Add may
// be sent, and a verify-only recovery must keep the no-effect journal.
func (r *rig) preEffectRefusal() {
	t, lock := r.t, r.path+".lock"
	owner, capture := r.start("cli", true)
	phrase := r.consent(capture, "ROTATE")
	if os.WriteFile(lock, []byte("synthetic-owned-lock"), 0600) != nil {
		t.Fatal("could not create persistence refusal after preparation")
	}
	r.approve(owner, capture, phrase)
	r.retainCandidate()
	r.expectEffects(0, vault.RotationPrepared)
	r.expectJournal(vault.RotationPrepared)
	if os.Remove(lock) != nil || r.retryDatabase() != vault.RotationAttempting {
		t.Fatal("explicit local-save retry did not preserve the no-effect attempting journal")
	}
	r.expectEffects(0, vault.RotationAttempting)
	r.restartKeeper()
	r.recovery(true)
	r.expectEffects(0, vault.RotationAttempting)
	r.stopKeeper()
	r.expectInventory("rotation.ktav")
}

// ownerCrashInFlight kills only the owner child while the keeper holds the
// remote Add after its effect. The keeper owns the operation, so an
// independently authenticated owner must find an unknown outcome, never replay
// Add, and finish through verify-only recovery.
func (r *rig) ownerCrashInFlight() {
	t := r.t
	barrier := r.fixture.armAddBarrier(t, r.ctx)
	r.fixture.configure(func(f *rotationSSHFixture) { f.loseAck = true })
	crashCtx, crash := context.WithCancel(r.ctx)
	defer crash()
	owner, capture := r.startIn(crashCtx, "owner", false)
	sendRotationConsent(t, owner, r.consent(capture, "ROTATE"))
	if barrier.wait(r.ctx) != nil {
		t.Fatal("synthetic Add did not reach its after-effect barrier")
	}
	r.expectEffects(1, vault.RotationAttempting)
	r.expectJournal(vault.RotationAttempting)
	candidate := r.retainCandidate()
	// Stop only this owner child; its output is joined before the terminal closes.
	crash()
	if owner.Wait(r.ctx) == nil {
		t.Fatal("in-flight owner process did not report its deliberate crash")
	}
	r.scan(r.ctx, capture)
	barrier.free()
	control := r.attach()
	defer control.Detach()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		saved, err := control.RotationSnapshot(r.ctx)
		if err == nil && saved.Rotation != nil && saved.Rotation.Phase == vault.RotationUnknown {
			if scoped(control, saved.Status.Database.Revision).Flush(r.ctx) != nil {
				t.Fatal("keeper could not save the unknown outcome after the Add barrier release")
			}
			break
		}
		select {
		case <-r.ctx.Done():
			t.Fatal("keeper did not settle the lost Add acknowledgement as unknown")
		case <-ticker.C:
		}
	}
	r.expectEffects(1, vault.RotationUnknown)
	r.expectJournal(vault.RotationUnknown)
	kept := r.journalKey()
	defer clear(kept)
	if !bytes.Equal(kept, candidate) {
		t.Fatal("owner crash discarded the candidate replacement key")
	}
	r.expectClean(r.keeperCapture)
	r.recovery(false, commitLine)
	r.expectEffects(1, vault.RotationComplete)
	r.oldJobAlive()
	r.stopKeeper()
}

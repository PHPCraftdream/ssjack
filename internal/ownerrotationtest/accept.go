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
		{"abandon-stuck", (*rig).abandonStuckRotation},
		{"retire-old-key", (*rig).retireOldKey},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			r := newRig(t)
			r.startKeeper()
			if r.waitHold("scenario-old-job-hold-ready") != nil {
				t.Fatal("old-key MCP SSH job did not remain held")
			}
			scenario.run(r)
		})
	}
}

func runSuccessfulAcceptance(t *testing.T) {
	r := newRig(t)
	r.startKeeper()
	if r.waitHold("composed-old-job-hold-ready") != nil {
		t.Fatal("actual ordinary MCP job did not retain an old-key SSH connection")
	}
	oldFingerprint := ssh.FingerprintSHA256(r.oldSSH)
	r.expectHandshake("initial-old-key-handshake", r.fingerprintCount(oldFingerprint), "initial actual MCP job was not authenticated by the saved old key")
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
	text, overflow := capture.text()
	if overflow {
		r.failCondition("displayed-replacement-fingerprint", "capture-overflow", "could not inspect the displayed replacement fingerprint")
	}
	if !strings.Contains(text, newFingerprint) {
		r.failCondition("displayed-replacement-fingerprint", "mismatch", "displayed replacement fingerprint did not match the durably selected SSH key")
	}
	r.expectEncrypted(r.path)
	switch {
	case !r.fixture.hasKey(r.oldSSH):
		r.failCondition("composed-remote-keys", "old-key-missing", "fixture remote authorization did not retain the old key")
	case !r.fixture.hasKey(newPublic):
		r.failCondition("composed-remote-keys", "replacement-key-missing", "fixture remote authorization did not add the new key")
	}
	before := r.fingerprintCount(newFingerprint)
	r.expectHandshake("rotation-proof-handshake", before, "rotation proof did not include a new-key SSH handshake")
	writeRotationPTY(t, human, []byte("still-old-human\n"))
	if r.waitOutput(humanCapture, "HUMAN-ECHO:still-old-human") != nil {
		t.Fatal("rotation terminated or replaced the actual running human CLI connection")
	}
	r.oldJobAlive()
	r.command("n", "ACTUAL-ROTATION-MCP-NEW-JOB-DONE")
	r.waitFingerprints(newFingerprint, before+1)
	r.expectHandshake("retained-old-key-handshake", r.fingerprintCount(oldFingerprint), "actual SSH handshakes did not prove both retained old and selected new key identities")
	r.command("o", "ACTUAL-ROTATION-MCP-OLD-JOB-DONE")
	writeRotationPTY(t, human, []byte("exit\n"))
	if r.waitChild(human, "human-pinned-shell-exit") != nil {
		t.Fatal("actual human CLI did not exit its pinned shell cleanly")
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
	if r.waitChild(refused, "wrong-approval-cli-exit") != nil {
		t.Fatal("actual rotate-key CLI process failed")
	}
	r.scan(r.ctx, capture)
	r.expectClean(r.keeperCapture)
	r.expectUnchangedRemote("wrong-approval-effects", mutations)
	r.expectJournal(vault.RotationPrepared)
	cancel, cancelCapture := r.start("cli", false, "--recover", "--cancel-prepared")
	r.approve(cancel, cancelCapture, r.consent(cancelCapture, "CANCEL-PREPARED"), "Prepared encrypted intent cancelled; no remote effect was attempted.")
	r.scan(r.ctx, cancelCapture)
	r.expectClean(r.keeperCapture)
	r.expectUnchangedRemote("cancel-prepared-effects", mutations)
	r.expectJournal(vault.RotationCancelled)
}

func (r *rig) expectUnchangedRemote(name string, mutations int) {
	r.t.Helper()
	switch {
	case r.fixture.mutationCount() != mutations:
		r.failCondition(name, "wrong-mutation-count", "remote mutation count changed")
	case !r.fixture.hasKeyFromPrivate(r.oldPrivate):
		r.failCondition(name, "old-key-missing", "remote authorization did not retain the old key")
	}
}

const commitLine = "Encrypted selected-account commit: durable at revision"

func (r *rig) expectEffects(mutations int, phase string) {
	r.t.Helper()
	switch {
	case r.fixture.mutationCount() != mutations:
		r.failCondition("rotation-effects", "wrong-mutation-count", "remote mutation count differs from the expected state")
	case r.diskPhase() != phase:
		r.failCondition("rotation-effects", "wrong-phase", "durable phase differs from the expected state")
	case !r.fixture.hasKeyFromPrivate(r.oldPrivate):
		r.failCondition("rotation-effects", "old-key-missing", "remote authorization did not retain the old key")
	}
}

// effectFailure drives an Add whose outcome fails after its remote effect, then
// recovers with a restarted keeper and verify-only consent, never replaying Add.
func (r *rig) effectFailure(kind string) {
	lock := r.path + ".lock"
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
		if os.Remove(lock) != nil {
			r.failCondition("post-add-local-save-retry", "lock-remove-error", "could not remove the synthetic persistence lock")
		}
		if r.retryDatabase() != vault.RotationAdded {
			r.failCondition("post-add-local-save-retry", "wrong-phase", "explicit local-save retry did not persist the acknowledged addition")
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

// abandonStuckRotation abandons a journal whose new login is refused for good:
// the abandon is local, so no remote call is made, the old key stays the active
// credential, and the encrypted journal ends in the cancelled terminal phase.
func (r *rig) abandonStuckRotation() {
	r.fixture.configure(func(f *rotationSSHFixture) { f.rejectNew = true })
	owner, capture := r.start("cli", true)
	phrase := r.consent(capture, "ROTATE")
	r.details(capture)
	r.approve(owner, capture, phrase)
	r.retainCandidate()
	r.expectEffects(1, vault.RotationAdded)
	r.expectJournal(vault.RotationAdded)
	r.restartKeeper()
	terminal, abandonCapture := r.start("cli", false, "--recover", "--abandon")
	r.approve(terminal, abandonCapture, r.consent(abandonCapture, "ABANDON"), "Rotation abandoned locally; the current key remains in use.")
	r.scan(r.ctx, abandonCapture)
	r.expectClean(r.keeperCapture)
	r.expectEffects(1, vault.RotationCancelled)
	r.expectJournal(vault.RotationCancelled)
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
	if os.Remove(lock) != nil {
		r.failCondition("pre-effect-local-save-retry", "lock-remove-error", "could not remove the synthetic persistence lock")
	}
	if r.retryDatabase() != vault.RotationAttempting {
		r.failCondition("pre-effect-local-save-retry", "wrong-phase", "explicit local-save retry did not preserve the no-effect attempting journal")
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
	// This runs before the fixture's idempotent fallback cleanup.
	t.Cleanup(func() {
		select {
		case <-barrier.release:
			return
		default:
		}
		barrier.free()
		r.diag.outcome("add-barrier-cleanup", "release-signaled")
	})
	r.diag.outcome("add-barrier", "armed")
	r.fixture.configure(func(f *rotationSSHFixture) { f.loseAck = true })
	crashCtx, crash := context.WithCancel(r.ctx)
	defer crash()
	owner, capture := r.startIn(crashCtx, "owner", false)
	sendRotationConsent(t, owner, r.consent(capture, "ROTATE"))
	start := time.Now()
	err := barrier.wait(r.ctx)
	r.diag.observe("add-barrier-wait", rotationOperationOutcome(err, "entry-observed", "wait-error"), start, rotationEvidence{})
	if err != nil {
		// The context branch can win even when entry is already observable.
		select {
		case <-barrier.entered:
			r.diag.outcome("add-barrier-entry-after-wait", "observed")
		default:
			r.diag.outcome("add-barrier-entry-after-wait", "not-observed")
		}
		t.Fatal("synthetic Add did not reach its after-effect barrier")
	}
	r.expectEffects(1, vault.RotationAttempting)
	r.expectJournal(vault.RotationAttempting)
	candidate := r.retainCandidate()
	// Stop only this owner child; its output is joined before the terminal closes.
	crash()
	// Any non-nil Wait result satisfies the original crash assertion; the
	// timeline distinguishes an unjoined wait from an exit/backend failure.
	if r.waitChild(owner, "deliberate-owner-crash-wait") == nil {
		t.Fatal("in-flight owner process did not report its deliberate crash")
	}
	r.scan(r.ctx, capture)
	r.diag.outcome("add-barrier", "release-requested")
	barrier.free()
	r.diag.outcome("add-barrier", "release-signaled")
	control := r.attach()
	defer control.Detach()
	start = time.Now()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	evidence := rotationEvidence{lastRPCFailure: "none"}
	for {
		saved, err := control.RotationSnapshot(r.ctx)
		evidence.attempts++
		if err != nil {
			evidence.lastRPCFailure = rotationOperationOutcome(err, "", "snapshot-error")
		} else {
			evidence.snapshot = snapshotStats(saved)
		}
		if err == nil && saved.Rotation != nil && saved.Rotation.Phase == vault.RotationUnknown {
			r.diag.observe("post-release-snapshot-settle", "unknown-observed", start, evidence)
			flushStart := time.Now()
			err := scoped(control, saved.Status.Database.Revision).Flush(r.ctx)
			r.diag.observe("post-release-flush", rotationOperationOutcome(err, "returned-ok", "flush-error"), flushStart, rotationEvidence{})
			if err != nil {
				t.Fatal("keeper could not save the unknown outcome after the Add barrier release")
			}
			break
		}
		select {
		case <-r.ctx.Done():
			r.diag.observe("post-release-snapshot-settle", rotationContextOutcome(r.ctx.Err()), start, evidence)
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

package ownerrotationtest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"

	"github.com/PHPCraftdream/ssjack/internal/vault"
)

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

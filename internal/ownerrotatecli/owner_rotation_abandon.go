package ownerrotatecli

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/PHPCraftdream/ssjack/internal/ownercontrol"
	"github.com/PHPCraftdream/ssjack/internal/ownerrotation"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

// abandonRetainedRotation is the local-only exit from a journal stuck after a
// remote addition attempt. It claims the journal like recovery does, then closes
// it; the remote addition itself is never undone.
func abandonRetainedRotation(ctx context.Context, control *ownercontrol.Control, plan ownerrotation.Plan, display rotationDisplay, readSecret func(string) ([]byte, error)) (int, error) {
	info := plan.Info
	if !vault.RotationAwaitsVerification(info.Phase) {
		return 1, errors.New("--abandon is allowed only for an uncommitted rotation after a remote addition attempt; no action taken")
	}
	confirmation := abandonConfirmation(display)
	printRotationMetadata(os.Stdout, display, confirmation)
	fmt.Fprintln(os.Stdout, "Abandon is local: the encrypted journal and the unused new private key are destroyed and the current key stays in use. The remote addition is not undone: the new public key above may remain authorized on the server until you remove it through a trusted session.")
	if err := rotationConsent(readSecret, "Type the exact ABANDON confirmation shown above: ", confirmation); err != nil {
		return 1, err
	}
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	claimed, err := control.DecideRotation(ctx, plan.Revision, info.PlanID, info.ID, "recover")
	if err != nil {
		return 1, err
	}
	if err := validateRotationReceipt(plan, claimed, info.Phase, true); err != nil {
		return 1, err
	}
	abandoned, err := control.DecideRotation(ctx, claimed.Revision, info.PlanID, info.ID, "abandon")
	if err != nil {
		return 1, err
	}
	if abandoned.Info.ID == "" || abandoned.Info.Phase != vault.RotationCancelled {
		snapshot, snapshotErr := control.RotationSnapshot(ctx)
		if snapshotErr != nil || snapshot.Rotation == nil || snapshot.Rotation.Phase != vault.RotationCancelled || snapshot.Status.Database.SavedRevision != snapshot.Status.Database.Revision || snapshot.CipherDigest == ([32]byte{}) {
			return 1, errors.New("abandoned rotation lacks a readable durable receipt")
		}
		abandoned = ownerrotation.Plan{Info: *snapshot.Rotation, Revision: snapshot.Status.Database.Revision, Digest: snapshot.CipherDigest}
	}
	if err := validateRotationCancellation(claimed, abandoned); err != nil {
		return 1, err
	}
	fmt.Fprintf(os.Stdout, "Rotation abandoned locally; the current key remains in use. If the remote addition took effect, remove the new public key (%s) from the server's authorized_keys through a trusted session.\n", display.NewFingerprint)
	return 0, nil
}

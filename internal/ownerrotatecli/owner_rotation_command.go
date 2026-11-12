package ownerrotatecli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/term"

	"github.com/PHPCraftdream/ssjack/internal/ownercontrol"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
	"github.com/PHPCraftdream/ssjack/internal/ownerrotation"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

type rotationDisplay struct {
	ServerID, Account, Profile, Endpoint, User, Usage string
	HostFingerprints, OldFingerprint, NewFingerprint  string
	OperationID, Phase                                string
	PlanID, Revision                                  uint64
	BaseRevision, CommitRevision                      uint64
	CommitDigest, RecoveryPath, RecoveryDigest        string
}

// Run executes owner rotate-key using the root's startup-password decision and terminal reader.
func Run(ctx context.Context, path, globalServer, globalAccount string, args []string, startupPasswordSupplied bool, readSecret func(string) ([]byte, error)) (code int, result error) {
	if ctx == nil || ctx.Err() != nil {
		return 1, errors.New("owner rotation requires an active context")
	}
	if readSecret == nil {
		return 1, errors.New("owner rotation requires a trusted terminal secret reader")
	}
	command, err := parseRotationCommand(args, globalServer, globalAccount)
	if err != nil {
		return 1, err
	}
	if startupPasswordSupplied {
		return 1, errors.New("rotate-key requires an independent hidden owner database password; startup password sources are not accepted")
	}
	if !rotationTerminal(os.Stdin, os.Stdout) || !term.IsTerminal(int(os.Stderr.Fd())) {
		return 1, errors.New("owner key rotation requires trusted input, output and prompt terminals")
	}
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	password, err := readSecret("Owner database password: ")
	if err != nil {
		return 1, err
	}
	control, err := ownercontrol.Open(ctx, path, password)
	clear(password)
	if err != nil {
		return 1, ownercontrol.ErrControl
	}
	closeOK := false
	defer func() {
		if closeOK {
			return
		}
		closeCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if closeErr := control.Close(closeCtx); closeErr != nil {
			control.Detach()
			if result == nil {
				code, result = 1, ownercontrol.ErrControl
			}
		}
	}()
	if command.Archive {
		code, result = runRotationArchive(ctx, control, command, readSecret)
	} else if command.Recover || command.Cancel {
		code, result = runRotationRecovery(ctx, control, command, readSecret)
	} else {
		code, result = runRotationPrepareInstall(ctx, control, command, readSecret)
	}
	if result == nil {
		closeCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if closeErr := control.Close(closeCtx); closeErr != nil {
			control.Detach()
			return 1, ownercontrol.ErrControl
		}
		closeOK = true
	}
	return code, result
}

func runRotationPrepareInstall(ctx context.Context, control *ownercontrol.Control, command rotationCommand, readSecret func(string) ([]byte, error)) (int, error) {
	snapshot, err := control.RotationSnapshot(ctx)
	if err != nil {
		return 1, err
	}
	if err := rotationSnapshotReady(snapshot); err != nil {
		return 1, err
	}
	serverID, profile, err := rotationSelection(snapshot, command.Server, command.Account)
	if err != nil {
		return 1, err
	}
	if snapshot.Rotation != nil && snapshot.Rotation.Phase != vault.RotationCancelled && snapshot.Rotation.Phase != vault.RotationArchived {
		return 1, errors.New("a key rotation journal already exists; completed journals require explicit preservation before rotation")
	}
	plan, err := control.PrepareRotation(ctx, snapshot.Status.Database.Revision, serverID, command.Account)
	if err != nil {
		return 1, err
	}
	if err := validateRotationPlan(plan, serverID, command.Account, profile, snapshot.Status.Database.Revision); err != nil {
		return 1, err
	}
	display, err := makeRotationDisplay(plan)
	if err != nil {
		return 1, err
	}
	printRotationMetadata(os.Stdout, display, rotationConfirmation(display))
	fmt.Fprintln(os.Stdout, "Remote add acknowledgement: not requested. No remote effect has been attempted.")
	if err := rotationConsent(readSecret, "Type the exact ROTATE confirmation shown above: ", rotationConfirmation(display)); err != nil {
		return 1, fmt.Errorf("%w; the encrypted prepared plan remains with no remote attempt; inspect with owner rotate-key --server %s --account %s --recover --cancel-prepared", err, command.Server, command.Account)
	}
	if err := ctx.Err(); err != nil {
		return 1, err
	}
	added, err := control.DecideRotation(ctx, plan.Revision, plan.Info.PlanID, plan.Info.ID, "install")
	if err != nil {
		if errors.Is(err, ownerrotation.ErrUncertain) || errors.Is(err, ownerpacket.ErrUncertain) {
			return 1, errors.New("remote key-add acknowledgement is unresolved; do not retry install; inspect with owner rotate-key --server " + command.Server + " --account " + command.Account + " --recover")
		}
		return 1, err
	}
	if err := validateRotationTransition(plan, added, vault.RotationAdded); err != nil {
		return 1, err
	}
	fmt.Fprintln(os.Stdout, "Remote add acknowledgement: received; this is not new-key login verification.")
	verified, err := control.DecideRotation(ctx, added.Revision, added.Info.PlanID, added.Info.ID, "verify")
	if err != nil {
		return 1, errors.New("new-key login was not verified; encrypted recovery remains; inspect with owner rotate-key --recover")
	}
	if err := validateRotationTransition(added, verified, vault.RotationVerified); err != nil {
		return 1, err
	}
	fmt.Fprintln(os.Stdout, "New-key login verification: successful through the saved host pins.")
	complete, err := control.DecideRotation(ctx, verified.Revision, verified.Info.PlanID, verified.Info.ID, "commit")
	if err != nil {
		return 1, errors.New("new-key login was verified but encrypted owner commit is incomplete; inspect with owner rotate-key --recover")
	}
	if err := validateRotationTransition(verified, complete, vault.RotationComplete); err != nil {
		return 1, err
	}
	fmt.Fprintf(os.Stdout, "Encrypted selected-account commit: durable at revision %d. Old remote key remains authorized. This does not prove adoption by every consumer; active sessions/jobs were not restarted or terminated.\n", complete.Revision)
	finalSnapshot, err := control.RotationSnapshot(ctx)
	if err == nil {
		printAdoptionStatus(os.Stdout, finalSnapshot.Status.Database.SSH)
	} else {
		fmt.Fprintln(os.Stdout, "Consumer adoption status: unavailable in the final owner snapshot; rotation receipt does not prove consumer adoption.")
	}
	return 0, nil
}

func rotationTerminal(input, output *os.File) bool {
	return input != nil && output != nil && term.IsTerminal(int(input.Fd())) && term.IsTerminal(int(output.Fd()))
}

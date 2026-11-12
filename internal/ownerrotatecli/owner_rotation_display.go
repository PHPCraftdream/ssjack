package ownerrotatecli

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/ownerrotation"
	"github.com/PHPCraftdream/ssjack/internal/sshstatus"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func makeRotationDisplay(plan ownerrotation.Plan) (rotationDisplay, error) {
	info := plan.Info
	oldFingerprint, err := ownerrotation.Fingerprint(info.OldPublic)
	if err != nil {
		return rotationDisplay{}, err
	}
	newFingerprint, err := ownerrotation.Fingerprint(info.NewPublic)
	if err != nil {
		return rotationDisplay{}, err
	}
	pins := make([]string, 0, len(info.HostKeys))
	for _, encoded := range info.HostKeys {
		key, err := vault.ParseHostKey([]byte(encoded))
		if err != nil {
			return rotationDisplay{}, errors.New("retained verified host-key metadata is invalid")
		}
		pins = append(pins, ssh.FingerprintSHA256(key))
	}
	return rotationDisplay{
		ServerID: info.ServerID, Account: info.Account, Profile: info.Profile,
		Endpoint: info.Address, User: info.User, Usage: info.Usage,
		HostFingerprints: strings.Join(pins, ", "), OldFingerprint: oldFingerprint,
		NewFingerprint: newFingerprint, OperationID: info.ID, PlanID: info.PlanID,
		Revision: plan.Revision, Phase: info.Phase, BaseRevision: info.BaseRevision,
		CommitRevision: info.CommitRevision, CommitDigest: info.CommitDigest, RecoveryPath: info.RecoveryPath, RecoveryDigest: info.RecoveryDigest,
	}, nil
}

func printRotationMetadata(out *os.File, display rotationDisplay, confirmation string) {
	fmt.Fprintf(out, "Owner key rotation\n  server ID: %q\n  account: %q\n  profile: %q\n  endpoint: %q\n  SSH user: %q\n  usage: %q\n  verified server host-key fingerprints: %s\n  old client-key fingerprint: %s\n  new client-key fingerprint: %s\n  saved revision: %d\n  operation ID: %q\n  plan ID: %d\n  base revision: %d\n  commit revision: %d\n  commit digest: %s\n  recovery path: %q\n  recovery digest: %s\n  phase: %q\n  required confirmation:\n  %s\n", display.ServerID, display.Account, display.Profile, display.Endpoint, display.User, display.Usage, display.HostFingerprints, display.OldFingerprint, display.NewFingerprint, display.Revision, display.OperationID, display.PlanID, display.BaseRevision, display.CommitRevision, display.CommitDigest, display.RecoveryPath, display.RecoveryDigest, display.Phase, confirmation)
}

func printAdoptionStatus(out *os.File, status *sshstatus.Status) {
	if status == nil {
		fmt.Fprintln(out, "Live consumer status: unavailable. Rotation does not prove desired, delivered or adopted revisions for any consumer.")
		return
	}
	format := func(known bool, revision uint64) string {
		if !known {
			return "unknown"
		}
		return strconv.FormatUint(revision, 10)
	}
	fmt.Fprintf(out, "Live SSH status is last-observed metadata only: profile=%q desired=%s delivered=%s adopted=%s unavailable=%t. It does not prove adoption by every consumer.\n", status.Profile, format(status.DesiredKnown, status.DesiredRevision), format(status.DeliveredKnown, status.DeliveredRevision), format(status.AdoptedKnown, status.AdoptedRevision), status.Unavailable)
}

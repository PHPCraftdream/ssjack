package ownerrotatecli

import (
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/ownerrotation"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func TestParseRotationCommandSelectorsAndRecovery(t *testing.T) {
	parsed, err := parseRotationCommand([]string{"rotate-key", "--server=prod", "--account", "deploy"}, "", "")
	if err != nil || parsed.Server != "prod" || parsed.Account != "deploy" || parsed.Recover {
		t.Fatalf("prepare: %#v, %v", parsed, err)
	}
	parsed, err = parseRotationCommand([]string{"rotate-key", "--recover"}, "prod", "deploy")
	if err != nil || !parsed.Recover || parsed.Server != "prod" || parsed.Account != "deploy" {
		t.Fatalf("recovery: %#v, %v", parsed, err)
	}
	parsed, err = parseRotationCommand([]string{"rotate-key", "--archive-completed"}, "prod", "deploy")
	if err != nil || !parsed.Archive || parsed.Recover || parsed.Cancel {
		t.Fatalf("archive: %#v, %v", parsed, err)
	}
	parsed, err = parseRotationCommand([]string{"rotate-key", "--recover", "--cancel-prepared"}, "prod", "deploy")
	if err != nil || !parsed.Recover || !parsed.Cancel {
		t.Fatalf("cancel: %#v, %v", parsed, err)
	}
}

func TestParseRotationCommandRejectsDuplicateConflictingAndIntentFlags(t *testing.T) {
	invalid := [][]string{
		{"rotate-key"},
		{"rotate-key", "--server", "prod", "--account", "deploy", "--server", "other"},
		{"rotate-key", "--server", "prod", "--account"},
		{"rotate-key", "--server", "prod", "--account", "deploy", "--private-key", "secret"},
		{"rotate-key", "--server", "prod", "--account", "deploy", "--recover", "--recover"},
		{"rotate-key", "--server", "prod", "--account", "deploy", "--cancel-prepared"},
		{"rotate-key", "--server", "prod", "--account", "deploy", "--confirm"},
		{"rotate-key", "--server", "prod", "--account", "deploy", "--archive-completed", "--recover"},
		{"rotate-key", "--server", "prod", "--account", "deploy", "--archive-completed", "--cancel-prepared"},
		{"rotate-key", "--server", "prod", "--account", "deploy", "--archive-completed", "--archive-completed"},
	}
	for _, args := range invalid {
		if _, err := parseRotationCommand(args, "", ""); err == nil {
			t.Errorf("accepted %q", args)
		}
	}
	if _, err := parseRotationCommand([]string{"rotate-key", "--server", "other", "--account", "deploy"}, "prod", ""); err == nil {
		t.Fatal("accepted conflicting global selector")
	}
	if _, err := parseRotationCommand([]string{"rotate-key", "--recover"}, "bad!", "deploy"); err == nil {
		t.Fatal("accepted invalid global server")
	}
	if _, err := parseRotationCommand([]string{"rotate-key", "--recover"}, "prod", "bad!"); err == nil {
		t.Fatal("accepted invalid global account")
	}
}

func TestRotationConfirmationBindsDisplayedIdentity(t *testing.T) {
	info := rotationDisplay{ServerID: "server-opaque", Account: "operator", Revision: 42, OperationID: "operation-opaque"}
	checks := map[string]string{
		rotationConfirmation(info):     "ROTATE server-opaque operator revision=42 operation=operation-opaque",
		recoveryConfirmation(info):     "VERIFY-ONLY server-opaque operator revision=42 operation=operation-opaque",
		cancellationConfirmation(info): "CANCEL-PREPARED server-opaque operator revision=42 operation=operation-opaque",
		archiveConfirmation(info):      "ARCHIVE server-opaque operator revision=42 operation=operation-opaque",
	}
	for got, want := range checks {
		if got != want {
			t.Errorf("confirmation=%q want %q", got, want)
		}
	}
}

func TestRotationConsentRejectsWrongPhraseAndPropagatesCancellation(t *testing.T) {
	reads := 0
	if err := rotationConsent(func(string) ([]byte, error) {
		reads++
		return []byte("ARCHIVE wrong"), nil
	}, "confirm: ", "ARCHIVE expected"); err == nil || reads != 1 {
		t.Fatalf("wrong phrase accepted or reads=%d", reads)
	}
	if err := rotationConsent(func(string) ([]byte, error) {
		return []byte("ARCHIVE expected"), nil
	}, "confirm: ", "ARCHIVE expected"); err != nil {
		t.Fatalf("exact phrase refused: %v", err)
	}
	cancelled := errors.New("terminal cancelled")
	calls := 0
	err := rotationConsent(func(string) ([]byte, error) {
		calls++
		return nil, cancelled
	}, "confirm: ", "ARCHIVE expected")
	if !errors.Is(err, cancelled) || calls != 1 {
		t.Fatalf("cancel result=%v calls=%d", err, calls)
	}
}

func TestRotationTerminalRequiresBothFilesToBeTerminals(t *testing.T) {
	if rotationTerminal(nil, os.Stdout) || rotationTerminal(os.Stdin, nil) {
		t.Fatal("nil terminal accepted")
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	if rotationTerminal(reader, writer) {
		t.Fatal("pipe accepted as terminal")
	}
}

func TestValidateRotationReceiptPinsIdentityScopeAndEvidence(t *testing.T) {
	original := vault.RotationInfo{
		ID: "0123456789abcdef0123456789abcdef", PlanID: 7, BaseRevision: 4,
		Phase: vault.RotationPrepared, ServerID: "server-opaque", Account: "deploy",
		Profile: "profile", Address: "host.example:22", User: "operator", Usage: "both",
		HostKeys: []string{"pin"}, OldPublic: []byte("old-public"), NewPublic: []byte("new-public"),
	}
	before := ownerrotation.Plan{Info: original, Revision: 5, Digest: [32]byte{1}}
	afterInfo := original
	afterInfo.Phase = vault.RotationUnknown
	afterInfo.HostKeys = append([]string(nil), original.HostKeys...)
	after := ownerrotation.Plan{Info: afterInfo, Revision: 6, Digest: [32]byte{2}}
	if err := validateRotationTransition(before, after, vault.RotationUnknown); err != nil {
		t.Fatalf("valid transition rejected: %v", err)
	}
	changed := after
	changed.Info.Address = "other.example:22"
	if err := validateRotationTransition(before, changed, vault.RotationUnknown); err == nil {
		t.Fatal("accepted changed endpoint")
	}
	changed = after
	changed.Info.HostKeys = []string{"other-pin"}
	if err := validateRotationTransition(before, changed, vault.RotationUnknown); err == nil {
		t.Fatal("accepted changed pins")
	}
	changed = after
	changed.Revision = before.Revision
	if err := validateRotationTransition(before, changed, vault.RotationUnknown); err == nil {
		t.Fatal("accepted stale revision")
	}
	readOnly := before
	readOnly.Info.Phase = vault.RotationPrepared
	if err := validateRotationReceipt(before, readOnly, vault.RotationPrepared, true); err != nil {
		t.Fatalf("same-revision receipt rejected: %v", err)
	}
	readOnly.Digest[0] = 3
	if err := validateRotationReceipt(before, readOnly, vault.RotationPrepared, true); err == nil {
		t.Fatal("read-only receipt changed ciphertext evidence")
	}
}

func archiveFixture() (ownerrotation.Plan, ownerrotation.Plan) {
	complete := vault.RotationInfo{
		ID: "0123456789abcdef0123456789abcdef", PlanID: 8, BaseRevision: 40,
		Phase: vault.RotationComplete, ServerID: "fedcba9876543210fedcba9876543210",
		Account: "deploy", Profile: "profile", Address: "host.example:22", User: "operator",
		Usage: "both", CommitDigest: strings.Repeat("a", 64), HostKeys: []string{"host-key"},
		OldPublic: []byte("old-public"), NewPublic: []byte("new-public"),
	}
	var oldCipher [32]byte
	for i := range oldCipher {
		oldCipher[i] = 1
	}
	before := ownerrotation.Plan{Info: complete, Revision: 42, Digest: oldCipher}
	archived := complete
	archived.Phase = vault.RotationArchived
	archived.Address, archived.User, archived.Usage = "", "", ""
	archived.HostKeys, archived.OldPublic, archived.NewPublic = nil, nil, nil
	archived.RecoveryPath = "vault.rotation-archive.ssjack.ktav"
	archived.RecoveryDigest = strings.Repeat("01", 32)
	var liveCipher [32]byte
	for i := range liveCipher {
		liveCipher[i] = 2
	}
	return before, ownerrotation.Plan{Info: archived, Revision: 43, Digest: liveCipher}
}

func TestValidateRotationArchiveReceiptBindsPreviousCopiedCipher(t *testing.T) {
	before, after := archiveFixture()
	if err := validateRotationArchiveReceipt(before, after); err != nil {
		t.Fatalf("valid archive receipt rejected: %v", err)
	}
	if after.Info.CommitDigest == after.Info.RecoveryDigest ||
		hex.EncodeToString(before.Digest[:]) != after.Info.RecoveryDigest ||
		hex.EncodeToString(after.Digest[:]) == after.Info.RecoveryDigest {
		t.Fatal("fixture does not distinguish historical commit, archived copy and post-transition ciphertext")
	}
	cases := []struct {
		name   string
		change func(*ownerrotation.Plan)
	}{
		{"operation", func(p *ownerrotation.Plan) { p.Info.ID = "ffffffffffffffffffffffffffffffff" }},
		{"server", func(p *ownerrotation.Plan) { p.Info.ServerID = "other-server" }},
		{"account", func(p *ownerrotation.Plan) { p.Info.Account = "other-account" }},
		{"profile", func(p *ownerrotation.Plan) { p.Info.Profile = "other-profile" }},
		{"phase", func(p *ownerrotation.Plan) { p.Info.Phase = vault.RotationComplete }},
		{"path", func(p *ownerrotation.Plan) { p.Info.RecoveryPath = "" }},
		{"path-control", func(p *ownerrotation.Plan) { p.Info.RecoveryPath = "bad\npath" }},
		{"copied-cipher-digest", func(p *ownerrotation.Plan) { p.Info.RecoveryDigest = strings.Repeat("03", 32) }},
		{"commit-digest", func(p *ownerrotation.Plan) { p.Info.CommitDigest = "" }},
		{"key-material", func(p *ownerrotation.Plan) { p.Info.NewPublic = []byte("key") }},
		{"host-pin", func(p *ownerrotation.Plan) { p.Info.HostKeys = []string{"pin"} }},
		{"stale-revision", func(p *ownerrotation.Plan) { p.Revision = 42 }},
		{"same-live-cipher", func(p *ownerrotation.Plan) { p.Digest = before.Digest }},
		{"zero-live-cipher", func(p *ownerrotation.Plan) { p.Digest = [32]byte{} }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			candidate := after
			candidate.Info = after.Info
			test.change(&candidate)
			if err := validateRotationArchiveReceipt(before, candidate); err == nil {
				t.Fatal("invalid archive receipt accepted")
			}
		})
	}
}

func TestValidateArchivedSnapshotRetainsSelectionAndDistinctProofs(t *testing.T) {
	_, archived := archiveFixture()
	info := archived.Info
	if err := validateArchivedSnapshot(info); err != nil {
		t.Fatalf("valid archived receipt rejected: %v", err)
	}
	info.Account = ""
	if err := validateArchivedSnapshot(info); err == nil {
		t.Fatal("archived receipt dropped selected identity")
	}
}

func TestArchivedSnapshotAllowsEpochZeroAndDifferentDigests(t *testing.T) {
	info := vault.RotationInfo{
		ID: "0123456789abcdef0123456789abcdef", PlanID: 8, Phase: vault.RotationArchived,
		ServerID: "fedcba9876543210fedcba9876543210", Account: "deploy", Profile: "profile",
		CommitDigest: strings.Repeat("a", 64), RecoveryPath: "vault.rotation-archive.ssjack.ktav",
		RecoveryDigest: strings.Repeat("b", 64),
	}
	if err := validateArchivedSnapshot(info); err != nil {
		t.Fatalf("zero historical commit revision rejected: %v", err)
	}
}

func TestArchiveFixtureBindsCopiedCipherDifferentFromCommitProof(t *testing.T) {
	before, archived := archiveFixture()
	if err := validateRotationArchiveReceipt(before, archived); err != nil {
		t.Fatalf("archive receipt rejected: %v", err)
	}
	if before.Info.CommitDigest == archived.Info.RecoveryDigest {
		t.Fatal("expected the copied current ciphertext digest to differ from prior commit proof")
	}
}

func TestArchivedSnapshotAcceptsEpochZeroAndDistinctProof(t *testing.T) {
	info := vault.RotationInfo{ID: "0123456789abcdef0123456789abcdef", PlanID: 8, Phase: vault.RotationArchived, ServerID: "fedcba9876543210fedcba9876543210", Account: "deploy", Profile: "profile", CommitDigest: strings.Repeat("a", 64), RecoveryPath: "vault.rotation-archive.ssjack.ktav", RecoveryDigest: strings.Repeat("b", 64)}
	if err := validateArchivedSnapshot(info); err != nil {
		t.Fatalf("archived metadata rejected: %v", err)
	}
}

func TestRotationSnapshotAllowsInitialZeroRevision(t *testing.T) {
	snapshot := ownerdb.Snapshot{
		Status:       ownerdb.Status{Database: vault.SessionStatus{Revision: 0, SavedRevision: 0}},
		CipherDigest: [32]byte{1},
	}
	if err := rotationSnapshotReady(snapshot); err != nil {
		t.Fatalf("healthy initial revision rejected: %v", err)
	}
}

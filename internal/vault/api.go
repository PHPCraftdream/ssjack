package vault

import (
	"context"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/ownerarchive"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/approval"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/core"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/record"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/recovery"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/session"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/store"
)

func New() *Vault { return core.New() }

// NewDirectory creates an empty current-schema database.
func NewDirectory() *Vault { return core.NewDirectory() }

func ValidateName(name string) error { return record.ValidateName(name) }

// MaxApplicationApprovals bounds one vault's application approval set.
const MaxApplicationApprovals = approval.MaxApprovals

// ValidateApprovalName applies the descriptor application-name rule.
func ValidateApprovalName(name string) error { return approval.ValidateName(name) }

// ListApplicationApprovals returns owner application approvals sorted by name.
func ListApplicationApprovals(v *Vault) ([]Approval, error) { return v.ListApplicationApprovals() }

func ParseHostKey(data []byte) (ssh.PublicKey, error) { return record.ParseHostKey(data) }

func Load(path string, password []byte) (*Vault, error) { return core.Load(path, password) }

// NewUnlocked prepares one master for generation and initial database storage.
func NewUnlocked(password []byte) (*Vault, error) { return core.NewUnlocked(password) }

func CreateUnlocked(ctx context.Context, path string, v *Vault) error {
	return core.CreateUnlocked(ctx, path, v)
}

func Create(path string, password []byte) error { return core.Create(path, password) }

func CreateContext(ctx context.Context, path string, password []byte) error {
	return core.CreateContext(ctx, path, password)
}

func CreateWithRecords(ctx context.Context, path string, v *Vault, password []byte) error {
	return core.CreateWithRecords(ctx, path, v, password)
}

func Save(path string, v *Vault, password []byte) error { return core.Save(path, v, password) }

func SaveContext(ctx context.Context, path string, v *Vault, password []byte) error {
	return core.SaveContext(ctx, path, v, password)
}

// SaveUnlocked uses only the master retained by Load, never the password again.
func SaveUnlocked(ctx context.Context, path string, v *Vault) error {
	return core.SaveUnlocked(ctx, path, v)
}

// Snapshot preserves the revision previously authenticated by Load.
func Snapshot(path string, v *Vault) (string, error) { return core.Snapshot(path, v) }

// RotationActive reports whether a journal still blocks edits and legacy rotate.
func RotationActive(j *RotationJournal) bool { return core.RotationActive(j) }

// LiveRotationPhase reports phases of a journal that still needs owner action.
func LiveRotationPhase(phase string) bool { return core.LiveRotationPhase(phase) }

// RotationAwaitsVerification reports phases that admit only new-key-only
// verification; the remote addition is never replayed from them.
func RotationAwaitsVerification(phase string) bool { return core.RotationAwaitsVerification(phase) }

func RecoveryPath(path, label string) (string, error) { return store.RecoveryPath(path, label) }

// PruneSnapshots removes oldest recovery files, keeping the newest keep.
func PruneSnapshots(path, label string, keep int) error {
	return store.PruneRecovery(path, label, keep)
}

// Backup copies exactly the ciphertext that was authenticated and validated.
func Backup(ctx context.Context, source, destination string, password []byte) error {
	return recovery.Backup(ctx, source, destination, password)
}

func Verify(path string, password []byte) error { return recovery.Verify(path, password) }

func Restore(ctx context.Context, destination, source string, sourcePassword, currentPassword []byte) (string, error) {
	return recovery.Restore(ctx, destination, source, sourcePassword, currentPassword)
}

func PrepareRestore(destination, source string, sourcePassword, currentPassword []byte) (*RestorePlan, error) {
	return recovery.PrepareRestore(destination, source, sourcePassword, currentPassword)
}

func PrepareUpgrade(ctx context.Context, path string, password []byte) (*UpgradePlan, error) {
	return recovery.PrepareUpgrade(ctx, path, password)
}

// OpenSession unlocks once. Close or explicit Discard must join its worker.
func OpenSession(ctx context.Context, path string, password []byte) (*Session, error) {
	return session.OpenSession(ctx, path, password)
}

// StartSession takes ownership of an unchanged authenticated vault, including on
// error. Callers must not retain or mutate its buffers after handing it over.
func StartSession(ctx context.Context, path string, v *Vault) (*Session, error) {
	return session.StartSession(ctx, path, v)
}

func OpenOwnerUnlock(path string, password []byte, binding [32]byte) (*OwnerUnlock, error) {
	return session.OpenOwnerUnlock(path, password, binding)
}

// AdoptOwnerUnlock consumes a read-only authenticated vault without another KDF.
func AdoptOwnerUnlock(loaded *Vault, binding [32]byte) (*OwnerUnlock, error) {
	return session.AdoptOwnerUnlock(loaded, binding)
}

// ParseOwnerImport deep-copies everything it needs; the caller still closes
// opened. Archived secret refs are intentionally dropped.
func ParseOwnerImport(opened *ownerarchive.Opened) (*OwnerImport, error) {
	return session.ParseOwnerImport(opened)
}

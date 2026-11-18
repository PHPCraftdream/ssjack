package core

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/keyfile"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/record"
)

// OwnerStore keeps linked unlock material inside the encrypted database only.
type OwnerStore struct {
	Directory string       `json:"directory"`
	StoreID   string       `json:"store_id"`
	Master    []byte       `json:"master"`
	Pending   *OwnerIntent `json:"pending"`
}

// OwnerIntent preserves one bounded change before external mutation is possible.
type OwnerIntent struct {
	ID                string            `json:"id"`
	Phase             string            `json:"phase"`
	TransactionID     string            `json:"transaction_id"`
	SnapshotID        string            `json:"snapshot_id"`
	PreviousStateHash string            `json:"previous_state_hash"`
	Versions          map[string]string `json:"versions"`
	Change            OwnerChange       `json:"change"`
}

type OwnerChange struct {
	Action            string `json:"action"`
	AliasID           string `json:"alias_id"`
	Name              string `json:"name"`
	ServerID          string `json:"server_id"`
	ObjectID          string `json:"object_id"`
	PreviousReference string `json:"previous_ref"`
	MediaType         string `json:"media_type"`
	Value             []byte `json:"value"`
}

func (o *OwnerStore) clear() {
	if o == nil {
		return
	}
	clear(o.Master)
	if o.Pending != nil {
		clear(o.Pending.Change.Value)
	}
}

func (v *Vault) validateOwnerStore() error {
	o := v.OwnerStore
	if o == nil {
		return nil
	}
	if len(o.Directory) == 0 || len(o.Directory) > 4096 || !utf8.ValidString(o.Directory) || strings.ContainsAny(o.Directory, "\x00\r\n") || !ValidDirectoryID(o.StoreID) || len(o.Master) == 0 || len(o.Master) > 16384 || !utf8.Valid(o.Master) || bytes.IndexByte(o.Master, 0) >= 0 {
		return errors.New("invalid owner-store binding")
	}
	for _, alias := range v.Secrets {
		reference, err := appstoreplaceholder.Parse([]byte(alias.Ref))
		store := reference.StoreID()
		if err != nil || hex.EncodeToString(store[:]) != o.StoreID {
			return errors.New("named secrets must belong to the linked owner store")
		}
	}
	if o.Pending == nil {
		return nil
	}
	p := o.Pending
	if !ValidDirectoryID(p.ID) || len(p.Versions) > 128 || len(p.Change.Value) > 16384 {
		return errors.New("invalid pending owner intent")
	}
	if err := v.validateOwnerChange(p.Change, p.Phase); err != nil {
		return err
	}
	switch p.Phase {
	case "draft":
		if p.TransactionID != "" || p.SnapshotID != "" || p.PreviousStateHash != "" || len(p.Versions) != 0 {
			return errors.New("draft owner intent contains a dispatched proposal")
		}
	case "prepared":
		if !ValidDirectoryID(p.TransactionID) || !ValidDirectoryID(p.SnapshotID) || !ValidOwnerHash(p.PreviousStateHash) {
			return errors.New("invalid prepared owner proposal")
		}
		for object, version := range p.Versions {
			if !ValidDirectoryID(object) || !ValidDirectoryID(version) {
				return errors.New("invalid owner proposal version")
			}
		}
		for aliasID, alias := range v.Secrets {
			if aliasID == p.Change.AliasID {
				continue
			}
			reference, err := appstoreplaceholder.Parse([]byte(alias.Ref))
			if err != nil {
				return errors.New("invalid existing owner alias")
			}
			object := reference.ObjectID()
			if _, exists := p.Versions[hex.EncodeToString(object[:])]; !exists {
				return errors.New("owner proposal would lose an unrelated named secret")
			}
		}
		_, present := p.Versions[p.Change.ObjectID]
		if p.Change.Action != "remove" && !present {
			return errors.New("owner proposal omits the selected secret")
		}
	default:
		return errors.New("unknown owner intent phase")
	}
	return nil
}

func ValidOwnerHash(text string) bool {
	decoded, err := hex.DecodeString(text)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == text && !bytes.Equal(decoded, make([]byte, 32))
}

func (v *Vault) validateOwnerChange(change OwnerChange, phase string) error {
	if !ValidDirectoryID(change.AliasID) || record.ValidateName(change.Name) != nil {
		return errors.New("invalid owner secret alias")
	}
	if change.ServerID != "" {
		if _, exists := v.Servers[change.ServerID]; !exists {
			return errors.New("owner secret scope does not exist")
		}
	}
	for id, alias := range v.Secrets {
		if id != change.AliasID && alias.Name == change.Name && alias.ServerID == change.ServerID {
			return errors.New("owner secret name already exists in scope")
		}
	}
	previous, exists := v.Secrets[change.AliasID]
	switch change.Action {
	case "add":
		if exists || len(v.Secrets) >= 128 || change.PreviousReference != "" {
			return errors.New("owner add would overwrite an existing alias")
		}
	case "update", "remove":
		if !exists || change.PreviousReference != previous.Ref {
			return errors.New("owner alias changed before the requested edit")
		}
		reference, err := appstoreplaceholder.Parse([]byte(previous.Ref))
		object := reference.ObjectID()
		if err != nil || ((phase == "draft" || change.Action == "remove") && change.ObjectID != hex.EncodeToString(object[:])) {
			return errors.New("owner change selects the wrong existing object")
		}
		if change.Action == "remove" && (change.Name != previous.Name || change.ServerID != previous.ServerID || len(change.Value) != 0) {
			return errors.New("invalid owner removal intent")
		}
	default:
		return errors.New("unknown owner secret action")
	}
	if phase == "prepared" || change.Action != "add" || change.ObjectID != "" {
		if !ValidDirectoryID(change.ObjectID) {
			return errors.New("invalid owner secret object identity")
		}
	}
	if change.Action != "remove" && !validOwnerMedia(change.MediaType) {
		return errors.New("invalid owner secret media label")
	}
	return nil
}

func validOwnerMedia(media string) bool {
	if len(media) < 1 || len(media) > 15 {
		return false
	}
	slash := false
	for i, c := range []byte(media) {
		if c == '/' {
			if slash || i == 0 || i == len(media)-1 {
				return false
			}
			slash = true
		} else if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '.' && c != '+' && c != '-' {
			return false
		}
	}
	return true
}

// LinkOwnerStore stores owned material; the caller must authenticate the actual
// installation first. Schema validation is not installation authority.
func (v *Vault) LinkOwnerStore(link OwnerStore) error {
	if err := v.validate(); err != nil {
		return err
	}
	if v.Version != 2 || v.OwnerStore != nil || link.Pending != nil {
		return errors.New("owner-store linking requires an unlinked directory database")
	}
	owned := link
	owned.Master = append([]byte(nil), link.Master...)
	candidate := *v
	candidate.OwnerStore = &owned
	if err := candidate.validate(); err != nil {
		clear(owned.Master)
		return err
	}
	v.OwnerStore = &owned
	return nil
}

func (v *Vault) StageOwnerChange(change OwnerChange) (string, error) {
	if err := v.validate(); err != nil {
		return "", err
	}
	if v.Version != 2 || v.OwnerStore == nil || v.OwnerStore.Pending != nil {
		return "", errors.New("owner store is unlinked or already has a pending change")
	}
	var err error
	if change.Action == "add" && change.AliasID == "" {
		change.AliasID, err = directoryID()
		if err != nil {
			return "", err
		}
	}
	if change.Action != "add" && change.ObjectID == "" {
		reference, err := appstoreplaceholder.Parse([]byte(change.PreviousReference))
		if err != nil {
			return "", err
		}
		object := reference.ObjectID()
		change.ObjectID = hex.EncodeToString(object[:])
	}
	id, err := directoryID()
	if err != nil {
		return "", err
	}
	change.Value = append([]byte{}, change.Value...)
	pending := &OwnerIntent{ID: id, Phase: "draft", Versions: make(map[string]string), Change: change}
	link := *v.OwnerStore
	link.Pending = pending
	candidate := *v
	candidate.OwnerStore = &link
	if err := candidate.validate(); err != nil {
		clear(change.Value)
		return "", err
	}
	v.OwnerStore.Pending = pending
	return id, nil
}

// PrepareOwnerChange records exact proposal metadata, not a success receipt.
func (v *Vault) PrepareOwnerChange(id, transaction, snapshot, previousHash, object string, versions map[string]string) error {
	if err := v.validate(); err != nil {
		return err
	}
	if v.OwnerStore == nil || v.OwnerStore.Pending == nil || v.OwnerStore.Pending.ID != id || v.OwnerStore.Pending.Phase != "draft" {
		return errors.New("owner draft does not match the proposal")
	}
	pending := *v.OwnerStore.Pending
	pending.Phase, pending.TransactionID, pending.SnapshotID, pending.PreviousStateHash = "prepared", transaction, snapshot, previousHash
	pending.Change.ObjectID = object
	pending.Versions = make(map[string]string, len(versions))
	for object, version := range versions {
		pending.Versions[object] = version
	}
	link := *v.OwnerStore
	link.Pending = &pending
	candidate := *v
	candidate.OwnerStore = &link
	if err := candidate.validate(); err != nil {
		return err
	}
	v.OwnerStore.Pending = &pending
	return nil
}

// CancelOwnerDraft cannot erase an intent that may have reached the anchor.
func (v *Vault) CancelOwnerDraft(id string) error {
	if err := v.validate(); err != nil {
		return err
	}
	if v.OwnerStore == nil || v.OwnerStore.Pending == nil || v.OwnerStore.Pending.ID != id || v.OwnerStore.Pending.Phase != "draft" {
		return errors.New("prepared owner intents require verified reconciliation")
	}
	clear(v.OwnerStore.Pending.Change.Value)
	v.OwnerStore.Pending = nil
	return nil
}

// ReopenOwnerDraft requires verified no-commit evidence from the owner runtime.
// It preserves the input; it does not authorize resubmission by itself.
func (v *Vault) ReopenOwnerDraft(id, transaction, snapshot string) error {
	if err := v.validate(); err != nil {
		return err
	}
	if v.OwnerStore == nil || v.OwnerStore.Pending == nil {
		return errors.New("owner proposal is missing")
	}
	pending := *v.OwnerStore.Pending
	if pending.Phase != "prepared" || pending.ID != id || pending.TransactionID != transaction || pending.SnapshotID != snapshot {
		return errors.New("owner recovery does not match the prepared intent")
	}
	pending.Phase, pending.TransactionID, pending.SnapshotID, pending.PreviousStateHash = "draft", "", "", ""
	pending.Versions = make(map[string]string)
	pending.Change.ObjectID = ""
	if pending.Change.Action != "add" {
		reference, err := appstoreplaceholder.Parse([]byte(pending.Change.PreviousReference))
		if err != nil {
			return err
		}
		object := reference.ObjectID()
		pending.Change.ObjectID = hex.EncodeToString(object[:])
	}
	link := *v.OwnerStore
	link.Pending = &pending
	candidate := *v
	candidate.OwnerStore = &link
	if err := candidate.validate(); err != nil {
		return err
	}
	v.OwnerStore.Pending = &pending
	return nil
}

// FinishOwnerChange checks correlation only. The caller must authenticate the
// actual committed receipt before changing database reference metadata.
func (v *Vault) FinishOwnerChange(id, transaction, snapshot string, references []appstoreref.Ref) error {
	if err := v.validate(); err != nil {
		return err
	}
	if v.OwnerStore == nil || v.OwnerStore.Pending == nil {
		return errors.New("owner proposal is missing")
	}
	pending := v.OwnerStore.Pending
	if pending.Phase != "prepared" || pending.ID != id || pending.TransactionID != transaction || pending.SnapshotID != snapshot || len(references) != len(pending.Versions) {
		return errors.New("owner receipt does not match the prepared proposal")
	}
	byObject := make(map[string]appstoreref.Ref)
	for _, reference := range references {
		store, object, version, selected := reference.StoreID(), reference.ObjectID(), reference.VersionID(), reference.SnapshotID()
		key := hex.EncodeToString(object[:])
		if _, duplicate := byObject[key]; duplicate || !reference.Valid() || hex.EncodeToString(store[:]) != v.OwnerStore.StoreID || hex.EncodeToString(selected[:]) != snapshot || pending.Versions[key] != hex.EncodeToString(version[:]) {
			return errors.New("owner receipt contains an unexpected reference")
		}
		byObject[key] = reference
	}
	candidate, err := v.directoryCopy()
	if err != nil {
		return err
	}
	change := pending.Change
	if change.Action == "remove" {
		delete(candidate.Secrets, change.AliasID)
	} else {
		candidate.Secrets[change.AliasID] = SecretBinding{Name: change.Name, ServerID: change.ServerID}
	}
	for aliasID, alias := range candidate.Secrets {
		objectID := change.ObjectID
		if aliasID != change.AliasID {
			reference, err := appstoreplaceholder.Parse([]byte(alias.Ref))
			if err != nil {
				return err
			}
			object := reference.ObjectID()
			objectID = hex.EncodeToString(object[:])
		}
		reference, exists := byObject[objectID]
		if !exists {
			return errors.New("owner receipt would lose an alias")
		}
		encoded, err := appstoreplaceholder.Encode(reference)
		if err != nil {
			return err
		}
		alias.Ref = string(encoded)
		candidate.Secrets[aliasID] = alias
	}
	link := *v.OwnerStore
	link.Pending = nil
	candidate.OwnerStore = &link
	if err := candidate.validate(); err != nil {
		return err
	}
	v.Secrets = candidate.Secrets
	clear(pending.Change.Value)
	v.OwnerStore.Pending = nil
	return nil
}

// RotationJournal retains the encrypted state needed to recover a key change.
type RotationJournal struct {
	ID             string `json:"id"`
	PlanID         uint64 `json:"plan_id"`
	BaseRevision   uint64 `json:"base_revision"`
	Phase          string `json:"phase"`
	ServerID       string `json:"server_id"`
	Account        string `json:"account"`
	Profile        string `json:"profile"`
	Original       Target `json:"original"`
	NewPrivate     []byte `json:"new_private"`
	NewPublic      []byte `json:"new_public"`
	OldPublic      []byte `json:"old_public"`
	CommitRevision uint64 `json:"commit_revision"`
	CommitDigest   string `json:"commit_digest"`
	RecoveryPath   string `json:"recovery_path"`
	RecoveryDigest string `json:"recovery_digest"`
}

func ClearJournal(j *RotationJournal) {
	if j == nil {
		return
	}
	clear(j.Original.PrivateKey)
	clear(j.Original.Password)
	j.Original.Proxy.Clear()
	clear(j.NewPrivate)
	clear(j.NewPublic)
	clear(j.OldPublic)
}

func RotationID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil || id == ([16]byte{}) {
		return "", errors.New("cannot create rotation identity")
	}
	return hex.EncodeToString(id[:]), nil
}

func RotationTargetEmpty(target Target) bool {
	return target.Address == "" && target.User == "" && len(target.PrivateKey) == 0 && len(target.Password) == 0 && len(target.HostKeys) == 0 && target.Usage == "" && target.SSHPolicy.Empty() && target.Proxy == nil
}

func rotationPublic(private []byte) ([]byte, error) { return keyfile.PublicSSH(private) }
func RotationScopeEqual(a, b Target) bool {
	a.PrivateKey, b.PrivateKey, a.Password, b.Password = nil, nil, nil, nil
	return record.SameTarget(a, b)
}
func ValidateRotation(v *Vault) error { return validateRotationVault(v) }

// RotationActive reports whether a journal still blocks edits and legacy rotate.
func RotationActive(j *RotationJournal) bool {
	return j != nil && j.Phase != RotationCancelled && j.Phase != RotationComplete && j.Phase != RotationArchived
}

func validateRotationVault(v *Vault) error {
	j := v.Rotation
	if j == nil {
		return nil
	}
	if v.Version != 2 || !ValidDirectoryID(j.ID) || j.PlanID == 0 || j.Profile == "" || j.Account == "" || j.ServerID == "" {
		return errors.New("invalid key rotation binding")
	}
	if j.Phase == RotationCancelled {
		if !RotationTargetEmpty(j.Original) || len(j.NewPrivate)+len(j.NewPublic)+len(j.OldPublic) != 0 || j.CommitRevision != 0 || j.CommitDigest != "" || j.RecoveryPath != "" || j.RecoveryDigest != "" {
			return errors.New("cancelled key rotation retains material")
		}
		return nil
	}
	if j.Phase == RotationArchived {
		if !RotationTargetEmpty(j.Original) || len(j.NewPrivate)+len(j.NewPublic)+len(j.OldPublic) != 0 || !ValidOwnerHash(j.CommitDigest) || j.RecoveryPath == "" || len(j.RecoveryPath) > 4096 || !ValidOwnerHash(j.RecoveryDigest) {
			return errors.New("invalid archived rotation evidence")
		}
		return nil
	}
	if j.RecoveryPath != "" || j.RecoveryDigest != "" || j.Original.Validate() != nil || len(j.Original.Password) != 0 || j.Original.Proxy != nil || len(j.NewPrivate) == 0 || len(j.NewPublic) == 0 {
		return errors.New("invalid key rotation recovery material")
	}
	oldPublic, err := rotationPublic(j.Original.PrivateKey)
	newPublic, newErr := rotationPublic(j.NewPrivate)
	if err != nil || newErr != nil || !bytes.Equal(oldPublic, j.OldPublic) || !bytes.Equal(newPublic, j.NewPublic) || bytes.Equal(oldPublic, j.NewPublic) {
		return errors.New("invalid replacement key in rotation journal")
	}
	if j.Phase == RotationComplete {
		if !ValidOwnerHash(j.CommitDigest) {
			return errors.New("invalid completed rotation evidence")
		}
		return nil // Completed recovery evidence survives unrelated later edits.
	}
	if !LiveRotationPhase(j.Phase) {
		return errors.New("invalid key rotation phase")
	}
	if j.CommitRevision != 0 || j.CommitDigest != "" {
		return errors.New("incomplete rotation contains completion evidence")
	}
	server, exists := v.Servers[j.ServerID]
	if !exists || server.Accounts[j.Account] != j.Profile {
		return errors.New("key rotation selection changed")
	}
	current, exists := v.Targets[j.Profile]
	if !exists || len(current.Password) != 0 || current.Proxy != nil || !RotationScopeEqual(current, j.Original) {
		return errors.New("key rotation scope changed")
	}
	if j.Phase == RotationCommitted {
		if !bytes.Equal(current.PrivateKey, j.NewPrivate) {
			return errors.New("committed rotation key mismatch")
		}
	} else if !bytes.Equal(current.PrivateKey, j.Original.PrivateKey) {
		return errors.New("uncommitted rotation changed the target")
	}
	return nil
}

const (
	RotationPrepared   = "prepared"
	RotationAttempting = "attempting"
	RotationUnknown    = "unknown"
	RotationAdded      = "added"
	RotationVerified   = "verified"
	RotationCommitted  = "committed"
	RotationComplete   = "complete"
	RotationCancelled  = "cancelled"
	RotationArchived   = "archived"
)

// LiveRotationPhase reports phases of a journal that still needs owner action.
func LiveRotationPhase(phase string) bool {
	switch phase {
	case RotationPrepared, RotationAttempting, RotationUnknown, RotationAdded, RotationVerified, RotationCommitted:
		return true
	}
	return false
}

// RotationAwaitsVerification reports phases that admit only new-key-only
// verification; the remote addition is never replayed from them.
func RotationAwaitsVerification(phase string) bool {
	switch phase {
	case RotationAttempting, RotationUnknown, RotationAdded:
		return true
	}
	return false
}

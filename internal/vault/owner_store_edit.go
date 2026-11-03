package vault

import (
	"encoding/hex"
	"errors"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
)

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

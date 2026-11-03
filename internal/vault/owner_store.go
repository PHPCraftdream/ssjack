package vault

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
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
	if len(o.Directory) == 0 || len(o.Directory) > 4096 || !utf8.ValidString(o.Directory) || strings.ContainsAny(o.Directory, "\x00\r\n") || !validDirectoryID(o.StoreID) || len(o.Master) == 0 || len(o.Master) > 16384 || !utf8.Valid(o.Master) || bytes.IndexByte(o.Master, 0) >= 0 {
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
	if !validDirectoryID(p.ID) || len(p.Versions) > 128 || len(p.Change.Value) > 16384 {
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
		if !validDirectoryID(p.TransactionID) || !validDirectoryID(p.SnapshotID) || !validOwnerHash(p.PreviousStateHash) {
			return errors.New("invalid prepared owner proposal")
		}
		for object, version := range p.Versions {
			if !validDirectoryID(object) || !validDirectoryID(version) {
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

func validOwnerHash(text string) bool {
	decoded, err := hex.DecodeString(text)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == text && !bytes.Equal(decoded, make([]byte, 32))
}

func (v *Vault) validateOwnerChange(change OwnerChange, phase string) error {
	if !validDirectoryID(change.AliasID) || ValidateName(change.Name) != nil {
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
		if !validDirectoryID(change.ObjectID) {
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

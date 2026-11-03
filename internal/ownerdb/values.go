package ownerdb

import (
	"encoding/hex"
	"errors"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

var errAliasOnly = errors.New("remove only the shared secret binding")

func (m *Manager) applyValue(change vault.OwnerChange) (string, error) {
	if change.Action == "add" {
		id, err := m.resources.editor.Add(change.MediaType, change.Value)
		return hex.EncodeToString(id[:]), err
	}
	previous, err := appstoreplaceholder.Parse([]byte(change.PreviousReference))
	if err != nil {
		return "", err
	}
	object := previous.ObjectID()
	found := false
	for _, metadata := range m.resources.editor.Objects() {
		if metadata.ObjectID == object {
			if metadata.Reference != previous || metadata.Pending {
				return "", appstorecrypto.ErrOwnerChanged
			}
			found = true
		}
	}
	if !found {
		return "", appstorecrypto.ErrOwnerChanged
	}
	metadata, err := m.db.Metadata()
	if err != nil {
		return "", err
	}
	shared := false
	for aliasID, alias := range metadata.Secrets {
		if aliasID == change.AliasID {
			continue
		}
		reference, err := appstoreplaceholder.Parse([]byte(alias.Ref))
		if err != nil {
			return "", err
		}
		if reference.StoreID() == previous.StoreID() && reference.ObjectID() == object {
			shared = true
		}
	}
	switch change.Action {
	case "update":
		if shared {
			id, err := m.resources.editor.Add(change.MediaType, change.Value)
			return hex.EncodeToString(id[:]), err
		}
		err = m.resources.editor.Update(object, change.Value)
	case "remove":
		if shared {
			return "", errAliasOnly
		}
		err = m.resources.editor.Remove(object)
	default:
		return "", errors.New("unsupported owner value change")
	}
	return hex.EncodeToString(object[:]), err
}

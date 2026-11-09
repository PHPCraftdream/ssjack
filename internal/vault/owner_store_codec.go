package vault

import "errors"

func ownerStoreRecord(owner *OwnerStore) map[string]any {
	var pending any
	if owner.Pending != nil {
		p := owner.Pending
		versions := make(map[string]any)
		for object, version := range p.Versions {
			versions[object] = version
		}
		c := p.Change
		change := map[string]any{"action": c.Action, "alias_id": c.AliasID, "name": c.Name, "server_id": c.ServerID, "object_id": c.ObjectID, "previous_ref": c.PreviousReference, "media_type": c.MediaType, "value": c.Value}
		pending = map[string]any{"id": p.ID, "phase": p.Phase, "transaction_id": p.TransactionID, "snapshot_id": p.SnapshotID, "previous_state_hash": p.PreviousStateHash, "versions": versions, "change": change}
	}
	return map[string]any{"directory": owner.Directory, "store_id": owner.StoreID, "master": owner.Master, "pending": pending}
}

func ownerFields(value any, fields ...string) (map[string]any, error) {
	record, ok := value.(map[string]any)
	if !ok || len(record) != len(fields) {
		return nil, errors.New("invalid closed owner-store fields")
	}
	for _, field := range fields {
		if _, exists := record[field]; !exists {
			return nil, errors.New("missing owner-store field")
		}
	}
	return record, nil
}

func ownerStringFields(record map[string]any, fields ...string) error {
	for _, field := range fields {
		if _, ok := record[field].(string); !ok {
			return errors.New("invalid owner-store string field")
		}
	}
	return nil
}

func validateOwnerStoreFields(value any) error {
	owner, err := ownerFields(value, "directory", "store_id", "master", "pending")
	if err != nil {
		return err
	}
	if err := ownerStringFields(owner, "directory", "store_id"); err != nil {
		return err
	}
	if owner["master"] == nil {
		return errors.New("owner-store unlock material is missing")
	}
	if owner["pending"] == nil {
		return nil
	}
	pending, err := ownerFields(owner["pending"], "id", "phase", "transaction_id", "snapshot_id", "previous_state_hash", "versions", "change")
	if err != nil {
		return err
	}
	if err := ownerStringFields(pending, "id", "phase", "transaction_id", "snapshot_id", "previous_state_hash"); err != nil {
		return err
	}
	versions, ok := pending["versions"].(map[string]any)
	if !ok || len(versions) > 128 {
		return errors.New("invalid owner-store version set")
	}
	for _, version := range versions {
		if _, ok := version.(string); !ok {
			return errors.New("invalid owner-store version value")
		}
	}
	change, err := ownerFields(pending["change"], "action", "alias_id", "name", "server_id", "object_id", "previous_ref", "media_type", "value")
	if err != nil {
		return err
	}
	return ownerStringFields(change, "action", "alias_id", "name", "server_id", "object_id", "previous_ref", "media_type")
}

// Package appstoreplaceholder encodes exact reference metadata, never secret values or authority.
package appstoreplaceholder

import (
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
)

const Format = "ssjack-secret-ref-v1"
const MaxInput = 1024

var ErrInvalid = errors.New("invalid exact secret placeholder")

// Encode returns canonical JSON containing only the four immutable reference IDs.
func Encode(reference appstoreref.Ref) ([]byte, error) {
	if !reference.Valid() {
		return nil, ErrInvalid
	}
	fields := map[string]string{
		"format":      Format,
		"store_id":    encodeID(reference.StoreID()),
		"object_id":   encodeID(reference.ObjectID()),
		"version_id":  encodeID(reference.VersionID()),
		"snapshot_id": encodeID(reference.SnapshotID()),
	}
	raw, err := json.Marshal(map[string]any{"$ssjack": fields})
	if err != nil {
		return nil, ErrInvalid
	}
	canonical, err := canonicaljson.Canonicalize(raw)
	if err != nil || len(canonical) > MaxInput {
		return nil, ErrInvalid
	}
	return canonical, nil
}

// Parse accepts one bounded closed placeholder. It resolves neither versions nor permissions.
func Parse(raw []byte) (appstoreref.Ref, error) {
	if len(raw) == 0 || len(raw) > MaxInput {
		return appstoreref.Ref{}, ErrInvalid
	}
	canonical, err := canonicaljson.Canonicalize(raw)
	if err != nil {
		return appstoreref.Ref{}, ErrInvalid
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(canonical, &envelope) != nil || len(envelope) != 1 {
		return appstoreref.Ref{}, ErrInvalid
	}
	body, present := envelope["$ssjack"]
	if !present {
		return appstoreref.Ref{}, ErrInvalid
	}
	var fields map[string]string
	if json.Unmarshal(body, &fields) != nil || len(fields) != 5 || fields["format"] != Format {
		return appstoreref.Ref{}, ErrInvalid
	}
	for key := range fields {
		switch key {
		case "format", "store_id", "object_id", "version_id", "snapshot_id":
		default:
			return appstoreref.Ref{}, ErrInvalid
		}
	}
	store, err := decodeID(fields["store_id"])
	if err != nil {
		return appstoreref.Ref{}, ErrInvalid
	}
	object, err := decodeID(fields["object_id"])
	if err != nil {
		return appstoreref.Ref{}, ErrInvalid
	}
	version, err := decodeID(fields["version_id"])
	if err != nil {
		return appstoreref.Ref{}, ErrInvalid
	}
	snapshot, err := decodeID(fields["snapshot_id"])
	if err != nil {
		return appstoreref.Ref{}, ErrInvalid
	}
	reference, err := appstoreref.New(store, object, version, snapshot)
	if err != nil {
		return appstoreref.Ref{}, ErrInvalid
	}
	return reference, nil
}

func encodeID(id [16]byte) string { return hex.EncodeToString(id[:]) }
func decodeID(text string) ([16]byte, error) {
	var id [16]byte
	if len(text) != 32 {
		return id, ErrInvalid
	}
	decoded, err := hex.DecodeString(text)
	if err != nil || hex.EncodeToString(decoded) != text {
		return id, ErrInvalid
	}
	copy(id[:], decoded)
	if id == ([16]byte{}) {
		return [16]byte{}, ErrInvalid
	}
	return id, nil
}

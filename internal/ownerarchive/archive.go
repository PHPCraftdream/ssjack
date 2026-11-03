package ownerarchive

import (
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/keyfile"
)

var ErrArchive = errors.New("invalid or incomplete owner export")

type Archive struct {
	database []byte
	refs     map[string]string
	values   map[string][]byte
	closed   bool
}

func New(database []byte) (*Archive, error) {
	if len(database) == 0 || len(database) > keyfile.MaxPlaintext {
		return nil, ErrArchive
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(database, &fields); err != nil {
		return nil, ErrArchive
	}
	if _, exists := fields["owner_store"]; exists {
		return nil, ErrArchive
	}
	var directory struct {
		Version int `json:"version"`
		Secrets map[string]struct {
			Ref string `json:"ref"`
		} `json:"secrets"`
	}
	if err := json.Unmarshal(database, &directory); err != nil || directory.Version != 2 || len(directory.Secrets) > 128 {
		return nil, ErrArchive
	}
	refs := make(map[string]string, len(directory.Secrets))
	for id, binding := range directory.Secrets {
		if !validID(id) {
			return nil, ErrArchive
		}
		if _, err := appstoreplaceholder.Parse([]byte(binding.Ref)); err != nil {
			return nil, ErrArchive
		}
		refs[id] = binding.Ref
	}
	return &Archive{database: append([]byte(nil), database...), refs: refs, values: make(map[string][]byte)}, nil
}

func validID(id string) bool {
	decoded, err := hex.DecodeString(id)
	return err == nil && len(decoded) == 16 && hex.EncodeToString(decoded) == id && id != "00000000000000000000000000000000"
}

func (a *Archive) Add(alias string, reference appstoreref.Ref, value []byte) error {
	if a == nil || a.closed || len(value) > 16384 {
		return ErrArchive
	}
	encoded, err := appstoreplaceholder.Encode(reference)
	if err != nil || a.refs[alias] != string(encoded) {
		return ErrArchive
	}
	if _, exists := a.values[alias]; exists {
		return ErrArchive
	}
	a.values[alias] = append([]byte{}, value...)
	return nil
}

func (a *Archive) Close() {
	if a == nil || a.closed {
		return
	}
	clear(a.database)
	a.database = nil
	for id, value := range a.values {
		clear(value)
		delete(a.values, id)
	}
	clear(a.refs)
	a.closed = true
}

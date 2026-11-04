package ownerarchive

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/ktav-lang/golang/pure"

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
	refs, err := parseDatabase(database)
	if err != nil {
		return nil, err
	}
	return &Archive{database: append([]byte(nil), database...), refs: refs, values: make(map[string][]byte)}, nil
}

// parseDatabase is shared by the writer (New) and the reader so both enforce
// the same database rules; it returns secret id -> placeholder reference.
func parseDatabase(database []byte) (map[string]string, error) {
	if len(database) == 0 || len(database) > keyfile.MaxPlaintext {
		return nil, ErrArchive
	}
	value, err := pure.LoadsStrict(string(database))
	if err != nil {
		return nil, ErrArchive
	}
	fields, ok := value.(map[string]any)
	if !ok {
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
	if err := pure.LoadsInto(string(database), &directory); err != nil || directory.Version != 2 || len(directory.Secrets) > 128 {
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
	return refs, nil
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

func suffixFor(encrypted bool) string {
	if encrypted {
		return ".ktav"
	}
	return ""
}

func databaseName(encrypted bool) string {
	if encrypted {
		return "database.ssjack.ktav"
	}
	return "database.ktav"
}

// validName is the exact entry whitelist. It already excludes traversal,
// absolute, backslash, drive and NUL names and directory entries.
func validName(name string, encrypted bool) bool {
	if name == "manifest.json"+suffixFor(encrypted) || name == databaseName(encrypted) {
		return true
	}
	id, ok := strings.CutPrefix(name, "secrets/")
	if !ok {
		return false
	}
	id, ok = strings.CutSuffix(id, ".bin"+suffixFor(encrypted))
	return ok && validID(id)
}

// matches checks the exact stored bytes against a manifest record.
func matches(raw []byte, record fileRecord) bool {
	want, err := hex.DecodeString(record.SHA256)
	if err != nil || len(want) != sha256.Size || hex.EncodeToString(want) != record.SHA256 || record.Length != len(raw) {
		return false
	}
	got := sha256.Sum256(raw)
	return subtle.ConstantTimeCompare(got[:], want) == 1
}

func parseManifest(raw []byte, encrypted bool) (*manifest, error) {
	if len(raw) == 0 || len(raw) > keyfile.MaxPlaintext {
		return nil, ErrArchive
	}
	if err := walkJSON(json.NewDecoder(bytes.NewReader(raw)), 0); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var m manifest
	if err := decoder.Decode(&m); err != nil {
		return nil, ErrArchive
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, ErrArchive
	}
	// encoding/json matches keys case-insensitively; the writer's output is
	// canonical, so a byte-exact re-encoding closes that gap.
	canonical, err := json.Marshal(m)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, ErrArchive
	}
	if m.Format != formatName || m.Database.Name != databaseName(encrypted) || len(m.Secrets) > maxSecrets {
		return nil, ErrArchive
	}
	for id, record := range m.Secrets {
		if !validID(id) || record.Name != "secrets/"+id+".bin"+suffixFor(encrypted) {
			return nil, ErrArchive
		}
	}
	return &m, nil
}

// walkJSON rejects duplicate object keys (case-folded), which encoding/json
// silently accepts, and over-deep nesting.
func walkJSON(decoder *json.Decoder, depth int) error {
	token, err := decoder.Token()
	if err != nil || depth > 8 {
		return ErrArchive
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return nil
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		if delim == '{' {
			keyToken, err := decoder.Token()
			key, isString := keyToken.(string)
			if err != nil || !isString {
				return ErrArchive
			}
			if _, dup := seen[strings.ToLower(key)]; dup {
				return ErrArchive
			}
			seen[strings.ToLower(key)] = struct{}{}
		}
		if err := walkJSON(decoder, depth+1); err != nil {
			return err
		}
	}
	if _, err := decoder.Token(); err != nil {
		return ErrArchive
	}
	return nil
}

// classify validates the ZIP entry table and reports whether it is encrypted.
func classify(entries []*zip.File) (bool, map[string]*zip.File, error) {
	if len(entries) < 2 || len(entries) > maxEntries {
		return false, nil, ErrArchive
	}
	files := make(map[string]*zip.File, len(entries))
	for _, f := range entries {
		// Duplicates are rejected; case-folded collisions cannot pass the
		// all-lowercase whitelist below.
		if _, dup := files[f.Name]; dup {
			return false, nil, ErrArchive
		}
		// Bit 3 (data descriptor) is expected from Go's writer; 0x1/0x40 mean encryption.
		if f.Flags&0x41 != 0 || f.Method != zip.Store || !f.Mode().IsRegular() ||
			f.CompressedSize64 != f.UncompressedSize64 {
			return false, nil, ErrArchive
		}
		files[f.Name] = f
	}
	_, plain := files["manifest.json"]
	_, sealed := files["manifest.json.ktav"]
	if plain == sealed {
		return false, nil, ErrArchive
	}
	for name := range files {
		if !validName(name, sealed) {
			return false, nil, ErrArchive
		}
	}
	if files[databaseName(sealed)] == nil {
		return false, nil, ErrArchive
	}
	return sealed, files, nil
}

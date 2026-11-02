//go:build linux && amd64

package declarativeauthority

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
)

const (
	textAdapterName   = "text-adapter-grants.json"
	textAdapterFormat = "ssjack-text-adapter-grants-v1"
)

// TextAdapterGrant is explicitly registered root-owned metadata. It does not
// authorize credential release.
type TextAdapterGrant struct {
	ID                 string   `json:"id"`
	RecipientUID       int      `json:"recipient_uid"`
	StorePath          string   `json:"store_path"`
	DirectoryDev       uint64   `json:"directory_dev"`
	DirectoryIno       uint64   `json:"directory_ino"`
	InstallationSHA256 string   `json:"installation_sha256"`
	EncodedHash        string   `json:"encoded_hash"`
	References         []string `json:"references"`
	Profile            string   `json:"profile"`
	CredentialSHA256   string   `json:"credential_sha256"`
	Command            string   `json:"command"`
	File               string   `json:"file"`
	Mode               string   `json:"mode"`
	ExpiresAt          string   `json:"expires_at"`
	Revoked            bool     `json:"revoked"`
}

type textAdapterDisk struct {
	Format string             `json:"format"`
	Grants []TextAdapterGrant `json:"grants"`
}

// ValidateTextAdapterGrant checks immutable, caller-supplied registration metadata.
func ValidateTextAdapterGrant(g TextAdapterGrant, now time.Time) error {
	return validateTextAdapter(g, true, now)
}

func validateTextAdapter(g TextAdapterGrant, active bool, now time.Time) error {
	id, err := base64.RawURLEncoding.DecodeString(g.ID)
	if err != nil || len(id) != 16 || base64.RawURLEncoding.EncodeToString(id) != g.ID {
		return ErrAuthority
	}
	if g.RecipientUID <= 0 || !filepath.IsAbs(g.StorePath) || filepath.Clean(g.StorePath) != g.StorePath || len(g.StorePath) > 4096 {
		return ErrAuthority
	}
	if g.DirectoryDev == 0 || g.DirectoryIno == 0 || !digestPattern.MatchString(g.InstallationSHA256) || !digestPattern.MatchString(g.EncodedHash) {
		return ErrAuthority
	}
	if len(g.References) < 1 || len(g.References) > 16 || g.Profile == "" || len(g.Profile) > 64 || !digestPattern.MatchString(g.CredentialSHA256) {
		return ErrAuthority
	}
	if g.Command == "" || len(g.Command) > 8192 || strings.IndexByte(g.Command, 0) >= 0 {
		return ErrAuthority
	}
	if g.File == "" || len(g.File) > 4096 || !filepath.IsAbs(g.File) || filepath.Clean(g.File) != g.File || g.Mode != "hydrate-v1" && g.Mode != "reverse-copy-v1" {
		return ErrAuthority
	}

	var firstStoreID, firstSnapshotID [16]byte
	for i, ref := range g.References {
		r, err := appstoreplaceholder.Parse([]byte(ref))
		if err != nil || !r.Valid() {
			return ErrAuthority
		}
		canonical, err := appstoreplaceholder.Encode(r)
		if err != nil || string(canonical) != ref {
			return ErrAuthority
		}
		if i == 0 {
			firstStoreID = r.StoreID()
			firstSnapshotID = r.SnapshotID()
		} else if r.StoreID() != firstStoreID || r.SnapshotID() != firstSnapshotID {
			return ErrAuthority
		}
		for _, prior := range g.References[:i] {
			if prior == ref {
				return ErrAuthority
			}
		}
	}

	exp, err := time.Parse(time.RFC3339, g.ExpiresAt)
	if err != nil || exp.UTC().Format(time.RFC3339) != g.ExpiresAt {
		return ErrAuthority
	}
	if active && (g.Revoked || !exp.After(now) || exp.Sub(now) > 24*time.Hour) {
		return ErrAuthority
	}
	return nil
}

// RegisterTextAdapter requires an explicit root invocation; caller-supplied
// metadata is not authority by itself.
func RegisterTextAdapter(g TextAdapterGrant) error {
	if os.Geteuid() != 0 || LoadSetup() != nil || validateTextAdapter(g, true, time.Now()) != nil {
		return ErrAuthority
	}
	d, err := readTextAdapters()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return ErrAuthority
	}
	if errors.Is(err, os.ErrNotExist) {
		d = textAdapterDisk{textAdapterFormat, []TextAdapterGrant{}}
	}
	for _, old := range d.Grants {
		if old.ID == g.ID {
			return ErrAuthority
		}
	}
	if len(d.Grants) >= 128 {
		return ErrAuthority
	}
	d.Grants = append(d.Grants, g)
	return writeTextAdapters(d)
}

func RevokeTextAdapter(id string) error {
	if os.Geteuid() != 0 || LoadSetup() != nil {
		return ErrAuthority
	}
	decoded, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil || len(decoded) != 16 || base64.RawURLEncoding.EncodeToString(decoded) != id {
		return ErrAuthority
	}
	d, err := readTextAdapters()
	if err != nil {
		return ErrAuthority
	}
	found := false
	for i := range d.Grants {
		if d.Grants[i].ID == id {
			d.Grants[i].Revoked = true
			found = true
		}
	}
	if !found {
		return ErrAuthority
	}
	return writeTextAdapters(d)
}

// LoadTextAdapter returns one uniquely matching active grant for this UID.
func LoadTextAdapter(id string, uid int, now time.Time) (TextAdapterGrant, error) {
	if LoadSetup() != nil || uid <= 0 {
		return TextAdapterGrant{}, ErrAuthority
	}
	d, err := readTextAdapters()
	if errors.Is(err, os.ErrNotExist) {
		return TextAdapterGrant{}, ErrAuthority
	}
	if err != nil {
		return TextAdapterGrant{}, ErrAuthority
	}
	var found *TextAdapterGrant
	for i := range d.Grants {
		g := &d.Grants[i]
		if g.ID == id && g.RecipientUID == uid && validateTextAdapter(*g, true, now) == nil {
			if found != nil {
				return TextAdapterGrant{}, ErrAuthority
			}
			found = g
		}
	}
	if found == nil {
		return TextAdapterGrant{}, ErrAuthority
	}
	return *found, nil
}

func readTextAdapters() (textAdapterDisk, error) {
	var d textAdapterDisk
	b, err := readTrusted(filepath.Join(RegistryPath, textAdapterName), maxFile)
	if err != nil {
		return d, err
	}
	canonical, err := canonicaljson.Canonicalize(b)
	if err != nil || string(canonical) != string(b) {
		return d, ErrAuthority
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if dec.Decode(&d) != nil || d.Format != textAdapterFormat || d.Grants == nil || len(d.Grants) > 128 || dec.Decode(new(any)) != io.EOF {
		return textAdapterDisk{}, ErrAuthority
	}
	for i, g := range d.Grants {
		if validateTextAdapter(g, false, time.Now()) != nil {
			return textAdapterDisk{}, ErrAuthority
		}
		for _, prior := range d.Grants[:i] {
			if prior.ID == g.ID {
				return textAdapterDisk{}, ErrAuthority
			}
		}
	}
	return d, nil
}

func writeTextAdapters(d textAdapterDisk) error {
	if d.Format != textAdapterFormat || d.Grants == nil || len(d.Grants) > 128 {
		return ErrAuthority
	}
	for i, g := range d.Grants {
		if validateTextAdapter(g, false, time.Now()) != nil {
			return ErrAuthority
		}
		for _, prior := range d.Grants[:i] {
			if prior.ID == g.ID {
				return ErrAuthority
			}
		}
	}
	b, err := json.Marshal(d)
	if err != nil {
		return ErrAuthority
	}
	b, err = canonicaljson.Canonicalize(b)
	if err != nil || len(b) > maxFile {
		return ErrAuthority
	}
	return atomicNamed(textAdapterName, b)
}

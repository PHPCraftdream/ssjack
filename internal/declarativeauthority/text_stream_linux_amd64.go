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

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
)

const (
	textStreamName   = "text-stream-grants-v2.json"
	textStreamFormat = "ssjack-text-stream-grants-v2"
)

func ValidateTextStreamGrant(grant TextAdapterGrant, now time.Time) error {
	return validateTextStream(grant, true, now)
}

func validateTextStream(grant TextAdapterGrant, active bool, now time.Time) error {
	switch grant.Mode {
	case "hydrate-stream-v2":
		grant.Mode = "hydrate-v1"
	case "reverse-copy-stream-v2":
		grant.Mode = "reverse-copy-v1"
	default:
		return ErrAuthority
	}
	return validateTextAdapter(grant, active, now)
}

func RegisterTextStream(grant TextAdapterGrant) error {
	if os.Geteuid() != 0 || LoadSetup() != nil || validateTextStream(grant, true, time.Now()) != nil {
		return ErrAuthority
	}
	disk, err := readTextStreams()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return ErrAuthority
	}
	if errors.Is(err, os.ErrNotExist) {
		disk = textAdapterDisk{Format: textStreamFormat, Grants: []TextAdapterGrant{}}
	}
	for _, previous := range disk.Grants {
		if previous.ID == grant.ID {
			return ErrAuthority
		}
	}
	if len(disk.Grants) >= 128 {
		return ErrAuthority
	}
	disk.Grants = append(disk.Grants, grant)
	return writeTextStreams(disk)
}

func RevokeTextStream(id string) error {
	if os.Geteuid() != 0 || LoadSetup() != nil {
		return ErrAuthority
	}
	decoded, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil || len(decoded) != 16 || base64.RawURLEncoding.EncodeToString(decoded) != id {
		return ErrAuthority
	}
	disk, err := readTextStreams()
	if err != nil {
		return ErrAuthority
	}
	found := false
	for i := range disk.Grants {
		if disk.Grants[i].ID == id {
			disk.Grants[i].Revoked, found = true, true
		}
	}
	if !found {
		return ErrAuthority
	}
	return writeTextStreams(disk)
}

func LoadTextStream(id string, uid int, now time.Time) (TextAdapterGrant, error) {
	if LoadSetup() != nil || uid <= 0 {
		return TextAdapterGrant{}, ErrAuthority
	}
	disk, err := readTextStreams()
	if err != nil {
		return TextAdapterGrant{}, ErrAuthority
	}
	var found *TextAdapterGrant
	for i := range disk.Grants {
		grant := &disk.Grants[i]
		if grant.ID == id && grant.RecipientUID == uid && validateTextStream(*grant, true, now) == nil {
			if found != nil {
				return TextAdapterGrant{}, ErrAuthority
			}
			found = grant
		}
	}
	if found == nil {
		return TextAdapterGrant{}, ErrAuthority
	}
	return *found, nil
}

func readTextStreams() (textAdapterDisk, error) {
	var disk textAdapterDisk
	encoded, err := readTrusted(filepath.Join(RegistryPath, textStreamName), maxFile)
	if err != nil {
		return disk, err
	}
	canonical, err := canonicaljson.Canonicalize(encoded)
	if err != nil || string(canonical) != string(encoded) {
		return disk, ErrAuthority
	}
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&disk) != nil || disk.Format != textStreamFormat || disk.Grants == nil || len(disk.Grants) > 128 || decoder.Decode(new(any)) != io.EOF {
		return textAdapterDisk{}, ErrAuthority
	}
	if err := validateTextStreamDisk(disk); err != nil {
		return textAdapterDisk{}, err
	}
	return disk, nil
}

func validateTextStreamDisk(disk textAdapterDisk) error {
	if disk.Format != textStreamFormat || disk.Grants == nil || len(disk.Grants) > 128 {
		return ErrAuthority
	}
	for i, grant := range disk.Grants {
		if validateTextStream(grant, false, time.Now()) != nil {
			return ErrAuthority
		}
		for _, previous := range disk.Grants[:i] {
			if previous.ID == grant.ID {
				return ErrAuthority
			}
		}
	}
	return nil
}

func writeTextStreams(disk textAdapterDisk) error {
	if err := validateTextStreamDisk(disk); err != nil {
		return err
	}
	encoded, err := json.Marshal(disk)
	if err != nil {
		return ErrAuthority
	}
	encoded, err = canonicaljson.Canonicalize(encoded)
	if err != nil || len(encoded) > maxFile {
		return ErrAuthority
	}
	return atomicNamed(textStreamName, encoded)
}

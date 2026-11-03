package ownerarchive

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"sort"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
)

type fileRecord struct {
	Name   string `json:"name"`
	Length int    `json:"length"`
	SHA256 string `json:"sha256"`
}

type manifest struct {
	Format   string                `json:"format"`
	Database fileRecord            `json:"database"`
	Secrets  map[string]fileRecord `json:"secrets"`
}

func (a *Archive) WriteEncrypted(ctx context.Context, destination string, key *keyfile.Unlocked) error {
	if key == nil {
		return ErrArchive
	}
	return a.write(ctx, destination, key.Seal, true)
}

func (a *Archive) WritePlaintext(ctx context.Context, destination, confirmation string) error {
	if confirmation != "EXPORT PLAINTEXT" {
		return errors.New("explicit plaintext owner confirmation is required")
	}
	return a.write(ctx, destination, func(value []byte) ([]byte, error) { return append([]byte(nil), value...), nil }, false)
}

func (a *Archive) write(ctx context.Context, destination string, seal func([]byte) ([]byte, error), encrypted bool) error {
	if ctx == nil || a == nil || a.closed || len(a.values) != len(a.refs) || destination == "" {
		return ErrArchive
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		return errors.New("owner export requires a supported private-file runtime")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var output bytes.Buffer
	defer func() { clear(output.Bytes()) }()
	writer := zip.NewWriter(&output)
	defer writer.Close()
	index := manifest{Format: "ssjack-owner-export-v1", Secrets: make(map[string]fileRecord)}
	add := func(name string, value []byte) (fileRecord, error) {
		if err := ctx.Err(); err != nil {
			return fileRecord{}, err
		}
		body, err := seal(value)
		if err != nil {
			return fileRecord{}, err
		}
		defer clear(body)
		if encrypted {
			name += ".ktav"
		}
		entry, err := writer.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if err != nil {
			return fileRecord{}, err
		}
		if _, err := entry.Write(body); err != nil {
			return fileRecord{}, err
		}
		digest := sha256.Sum256(body)
		return fileRecord{Name: name, Length: len(body), SHA256: hex.EncodeToString(digest[:])}, nil
	}
	var err error
	databaseName := "database.ktav"
	if encrypted {
		databaseName = "database.ssjack"
	}
	index.Database, err = add(databaseName, a.database)
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(a.refs))
	for id := range a.refs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		value := a.values[id]
		if encrypted {
			framed := make([]byte, len(value)+1)
			framed[0] = 1
			copy(framed[1:], value)
			value = framed
		}
		record, err := add("secrets/"+id+".bin", value)
		if encrypted {
			clear(value)
		}
		if err != nil {
			return err
		}
		index.Secrets[id] = record
	}
	encoded, err := json.Marshal(index)
	if err != nil {
		return ErrArchive
	}
	defer clear(encoded)
	if len(encoded) > keyfile.MaxPlaintext {
		return ErrArchive
	}
	if _, err := add("manifest.json", encoded); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return publish(ctx, destination, output.Bytes())
}

func publish(ctx context.Context, destination string, encoded []byte) error {
	file, err := newPrivateFile(destination)
	if err != nil {
		return errors.New("owner export destination must be new and privately writable")
	}
	defer file.Close()
	identity, err := file.Stat()
	if err != nil {
		return errors.New("cannot verify the new owner export file")
	}
	complete := false
	defer func() {
		if !complete {
			file.Close()
			current, err := os.Lstat(destination)
			if err == nil && os.SameFile(identity, current) {
				_ = os.Remove(destination)
			}
		}
	}()
	if err := checkPrivateFile(file, identity); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := file.Write(encoded); err != nil {
		return errors.New("owner export write failed; inspect the selected destination")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return errors.New("owner export sync failed; inspect the selected destination")
	}
	if err := file.Close(); err != nil {
		return errors.New("owner export close failed; inspect the selected destination")
	}
	complete = true
	return nil
}

package main

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/ownerarchive"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
)

// tamperedArchive rewrites the archive with one flipped bit inside a value
// entry. The ZIP checksum stays valid, so only the manifest digest can object.
func tamperedArchive(t *testing.T, source string) string {
	t.Helper()
	reader, err := zip.OpenReader(source)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var out bytes.Buffer
	writer := zip.NewWriter(&out)
	flipped := false
	for _, entry := range reader.File {
		input, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(io.LimitReader(input, 1024*1024))
		input.Close()
		if err != nil {
			t.Fatal(err)
		}
		if !flipped && strings.HasPrefix(entry.Name, "secrets/") && len(body) > 0 {
			body[len(body)/2] ^= 1
			flipped = true
		}
		target, err := writer.CreateHeader(&zip.FileHeader{Name: entry.Name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := target.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil || !flipped {
		t.Fatal("could not build a tampered archive")
	}
	path := filepath.Join(t.TempDir(), "tampered.zip")
	if err := os.WriteFile(path, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// requireRejectedArchives runs damaged inputs through the idle manager.
func requireRejectedArchives(t *testing.T, ctx context.Context, manager *ownerdb.Manager, database string, fixture importFixture, password []byte) {
	t.Helper()
	encoded := importBytes(t, fixture.encrypted)
	dir := t.TempDir()
	truncated, garbage := filepath.Join(dir, "truncated.zip"), filepath.Join(dir, "garbage.zip")
	if err := os.WriteFile(truncated, encoded[:len(encoded)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(garbage, bytes.Repeat([]byte("not a zip archive "), 64), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		path     string
		password []byte
		want     error
	}{
		{truncated, nil, ownerarchive.ErrArchive},
		{garbage, nil, ownerarchive.ErrArchive},
		{tamperedArchive(t, fixture.encrypted), password, ownerarchive.ErrAuthentication},
	}
	for _, c := range cases {
		before := importBytes(t, database)
		if err := manager.InspectImport(c.path, c.password); err != nil {
			t.Fatal(err)
		}
		if err := manager.Flush(ctx); err != nil {
			t.Fatal("rejected archive poisoned the owner manager")
		}
		if status := manager.ImportStatus(); !errors.Is(status.Err, c.want) {
			t.Fatal("damaged archive failed with an unexpected error class")
		}
		requireUntouched(t, manager, database, before, fixture)
	}
}

package ownerarchivetest

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/ownerarchive"
)

type file struct {
	name string
	body []byte
}

type inventory struct {
	Format string `json:"format"`
}

func database(withMCP bool) []byte {
	value := `{"version":2,"targets":{},"servers":{},"secrets":{}}`
	if withMCP {
		value = `{"version":2,"targets":{},"servers":{},"secrets":{},"remote_mcp":{"servers":{},"accounts":{},"last":{}}}`
	}
	return []byte(value)
}

func export(t *testing.T, withMCP bool) []byte {
	t.Helper()
	a, err := ownerarchive.New(database(withMCP))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	path := filepath.Join(t.TempDir(), "owner.zip")
	if err := a.WritePlaintext(context.Background(), path, "EXPORT PLAINTEXT"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func entries(t *testing.T, raw []byte) []file {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	var result []file
	for _, entry := range reader.File {
		input, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(input)
		input.Close()
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, file{name: entry.Name, body: body})
	}
	return result
}

func rewriteManifest(t *testing.T, raw []byte, format string) []byte {
	t.Helper()
	all := entries(t, raw)
	var out bytes.Buffer
	writer := zip.NewWriter(&out)
	found := false
	for _, entry := range all {
		if entry.name == "manifest.json" {
			var manifest inventory
			if err := json.Unmarshal(entry.body, &manifest); err != nil {
				t.Fatal(err)
			}
			old := []byte(`"format":"` + manifest.Format + `"`)
			updated := []byte(`"format":"` + format + `"`)
			entry.body = bytes.Replace(entry.body, old, updated, 1)
			found = true
		}
		header := &zip.FileHeader{Name: entry.name, Method: zip.Store}
		output, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := output.Write(entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("manifest missing")
	}
	return out.Bytes()
}

func TestLegacyAndMCPArchiveFormatSignaling(t *testing.T) {
	legacy := export(t, false)
	mcp := export(t, true)
	for _, test := range []struct {
		name   string
		data   []byte
		format string
	}{
		{"legacy", legacy, "ssjack-owner-export-v1"},
		{"MCP", mcp, "ssjack-owner-export-v2"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var manifest inventory
			for _, entry := range entries(t, test.data) {
				if entry.name == "manifest.json" {
					if err := json.Unmarshal(entry.body, &manifest); err != nil {
						t.Fatal(err)
					}
				}
			}
			if manifest.Format != test.format {
				t.Fatalf("format %q, want %q", manifest.Format, test.format)
			}
			opened, err := ownerarchive.Read(context.Background(), test.data, nil)
			if err != nil {
				t.Fatal(err)
			}
			opened.Close()
		})
	}
	for _, test := range []struct {
		data   []byte
		format string
	}{
		{mcp, "ssjack-owner-export-v1"},
		{legacy, "ssjack-owner-export-v2"},
	} {
		opened, err := ownerarchive.Read(context.Background(), rewriteManifest(t, test.data, test.format), nil)
		if opened != nil || !errors.Is(err, ownerarchive.ErrArchive) {
			t.Fatalf("format mismatch accepted: %v", err)
		}
	}
}

func TestRejectsMalformedRemoteMCPArchiveData(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte(`{"version":2,"targets":{},"servers":{},"secrets":{},"remote_mcp":{"servers":{},"accounts":{},"last":{},"extra":true}}`),
		[]byte(`{"version":2,"targets":{},"servers":{},"secrets":{},"remote_mcp":{"servers":{"02000000000000000000000000000000":{"name":"s","url":"http://example.com","enabled":true,"revision":1}},"accounts":{},"last":{}}}`),
	} {
		if archive, err := ownerarchive.New(raw); archive != nil || !errors.Is(err, ownerarchive.ErrArchive) {
			t.Fatalf("malformed remote MCP accepted: %v", err)
		}
	}
}

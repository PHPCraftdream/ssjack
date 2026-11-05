package ownerpublication

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreparedPublicationReplacementAndFlush(t *testing.T) {
	for _, long := range []bool{false, true} {
		root := t.TempDir()
		if long {
			root = filepath.Join(root, strings.Repeat("a", 140), strings.Repeat("b", 140))
			if err := os.MkdirAll(root, 0700); err != nil {
				t.Fatal(err)
			}
		}
		stage, destination, sibling := filepath.Join(root, "prepared"), filepath.Join(root, "database"), filepath.Join(root, "unrelated")
		for _, path := range []string{destination, sibling} {
			if err := os.WriteFile(path, []byte("old synthetic encrypted bytes"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		file, err := os.OpenFile(stage, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		value := []byte("new synthetic encrypted bytes")
		if _, err := file.Write(value); err != nil {
			file.Close()
			t.Fatal(err)
		}
		if err := file.Sync(); err != nil {
			file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if err := Replace(stage, destination); err != nil {
			t.Fatal(err)
		}
		if err := Sync(destination); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(destination)
		if err != nil || !bytes.Equal(got, value) {
			t.Fatal("publication changed prepared encrypted bytes")
		}
		if _, err := os.Stat(stage); !os.IsNotExist(err) {
			t.Fatal("replacement retained the staging name")
		}
		got, err = os.ReadFile(sibling)
		if err != nil || string(got) != "old synthetic encrypted bytes" {
			t.Fatal("publication changed an unrelated sibling")
		}
		if err := Replace(stage, destination); err == nil {
			t.Fatal("missing staging source reported success")
		}
		got, err = os.ReadFile(destination)
		if err != nil || !bytes.Equal(got, value) {
			t.Fatal("failed replacement changed the destination")
		}
	}
}

func TestPublicationFlushRefusesMissingAndDirectoryEntries(t *testing.T) {
	root := t.TempDir()
	if err := Sync(root); err == nil {
		t.Fatal("directory was accepted as an encrypted publication")
	}
	if err := Sync(filepath.Join(root, "missing")); err == nil {
		t.Fatal("missing encrypted publication reported a successful flush")
	}
}

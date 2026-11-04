//go:build linux || darwin

package ownerlocal

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUnixOwnerSocketPrivateModesAndForeignReplacement(t *testing.T) {
	path := endpointFixture(t)
	endpoint, err := Identity(path)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	for name, permission := range map[string]os.FileMode{filepath.Dir(endpoint.Address): 0700, endpoint.Address: 0600} {
		info, err := os.Lstat(name)
		if err != nil || info.Mode().Perm() != permission {
			t.Fatal("owner endpoint permissions are not private")
		}
	}
	backup := endpoint.Address + ".owned"
	if err := os.Rename(endpoint.Address, backup); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(backup)
	foreign := []byte("foreign replacement; never remove")
	if err := os.WriteFile(endpoint.Address, foreign, 0600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(endpoint.Address)
	listener.Close()
	got, err := os.ReadFile(endpoint.Address)
	if err != nil || string(got) != string(foreign) {
		t.Fatal("socket close removed a replacement it did not own")
	}
}

func TestUnixOwnerSocketNeverUnlinksStaleEndpointsOrAcceptsPublicPermissions(t *testing.T) {
	path := endpointFixture(t)
	endpoint, err := Identity(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := privateSocketDirectory(filepath.Dir(endpoint.Address), true); err != nil {
		t.Fatal(err)
	}
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: endpoint.Address, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	stale.Close()
	defer os.Remove(endpoint.Address)
	if listener, err := Listen(path); !errors.Is(err, ErrBusy) {
		if listener != nil {
			listener.Close()
		}
		t.Fatal("stale socket was silently reclaimed")
	}
	if err := os.Chmod(endpoint.Address, 0666); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if connection, err := Dial(ctx, path); !errors.Is(err, ErrUnavailable) {
		if connection != nil {
			connection.Close()
		}
		t.Fatal("public socket permissions were accepted")
	}
	if err := os.Chmod(filepath.Dir(endpoint.Address), 0755); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(filepath.Dir(endpoint.Address), 0700)
	if err := privateSocketDirectory(filepath.Dir(endpoint.Address), true); !errors.Is(err, ErrUnavailable) {
		t.Fatal("unsafe runtime directory was accepted or repaired silently")
	}
	info, err := os.Stat(filepath.Dir(endpoint.Address))
	if err != nil || info.Mode().Perm() != 0755 {
		t.Fatal("existing runtime permissions were modified")
	}
}

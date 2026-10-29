//go:build linux

package appstoreintentio

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorrequest"
)

func testID(b byte) [16]byte { return [16]byte(bytes.Repeat([]byte{b}, 16)) }

func testIntent(t *testing.T, store, transaction byte) appstoreanchorrequest.Intent {
	t.Helper()
	b := make([]byte, 312)
	copy(b[:8], "SSAPCMT1")
	copy(b[8:24], bytes.Repeat([]byte{transaction}, 16))
	copy(b[24:56], bytes.Repeat([]byte{6}, 32))
	state := b[56:248]
	copy(state[:4], "SSAS")
	binary.BigEndian.PutUint16(state[4:6], 1)
	copy(state[8:24], bytes.Repeat([]byte{store}, 16))
	binary.BigEndian.PutUint64(state[24:32], 1)
	copy(state[32:48], bytes.Repeat([]byte{2}, 16))
	copy(state[48:80], bytes.Repeat([]byte{3}, 32))
	copy(state[80:96], bytes.Repeat([]byte{transaction}, 16))
	binary.BigEndian.PutUint64(state[96:104], 1)
	copy(state[104:136], bytes.Repeat([]byte{5}, 32))
	copy(b[280:312], state[48:80])
	message := append([]byte("SSAPP-COMMIT-v1"), state[8:24]...)
	message = append(message, state[80:96]...)
	message = append(message, state[48:80]...)
	key := sha256.Sum256(message)
	copy(b[248:280], key[:])
	intent, err := appstoreanchorrequest.ParseIntent(b, testID(store))
	if err != nil {
		t.Fatal(err)
	}
	return intent
}

func testDirectory(t *testing.T) (*Directory, *os.File, string) {
	t.Helper()
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { file.Close() })
	d, err := New(file, testID(1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d, file, path
}

func TestCreateAndRestartLoadExactIntent(t *testing.T) {
	d, original, path := testDirectory(t)
	intent := testIntent(t, 1, 4)
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	if err := d.Create(intent); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(path, name(testID(4)))
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	raw := intent.Bytes()
	if !bytes.Equal(b, raw[:]) {
		t.Fatal("persisted different bytes")
	}
	st, err := os.Stat(file)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("file mode", err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	next, err := New(reopened, testID(1))
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	loaded, err := next.Load(testID(4))
	if err != nil || loaded.Bytes() != raw {
		t.Fatal("restart intent changed", err)
	}
	want, _ := intent.Request()
	got, ok := loaded.Request()
	if !ok || !bytes.Equal(want.Bytes(), got.Bytes()) {
		t.Fatal("CAS reconstruction changed")
	}
	if err := next.Create(intent); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate accepted: %v", err)
	}
	b, err = os.ReadFile(file)
	if err != nil || !bytes.Equal(b, raw[:]) {
		t.Fatal("duplicate modified record")
	}
}

func TestIndependentDirectoryLockAndSharedLifecycle(t *testing.T) {
	d, file, _ := testDirectory(t)
	other, err := New(file, testID(1))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := unix.Flock(d.state.fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := other.Create(testIntent(t, 1, 4)); !errors.Is(err, ErrBusy) {
		t.Fatalf("independent FD lock bypassed: %v", err)
	}
	if err := unix.Flock(d.state.fd, unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := other.Create(testIntent(t, 1, 4)); err != nil {
		t.Fatal(err)
	}
	d.state.mu.Lock()
	err = d.Create(testIntent(t, 1, 7))
	d.state.mu.Unlock()
	if !errors.Is(err, ErrBusy) {
		t.Fatal("in-process contention accepted")
	}
	alias := *d
	if err := alias.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Load(testID(4)); !errors.Is(err, ErrClosed) {
		t.Fatal("alias close not shared")
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	var empty Directory
	for _, value := range []*Directory{nil, &empty} {
		if err := value.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := value.Load(testID(4)); !errors.Is(err, ErrClosed) {
			t.Fatal("zero directory accepted")
		}
	}
}

func TestScopeAndInvalidDirectory(t *testing.T) {
	d, file, path := testDirectory(t)
	if _, err := New(nil, testID(1)); !errors.Is(err, ErrInvalid) {
		t.Fatal("nil accepted")
	}
	if _, err := New(file, [16]byte{}); !errors.Is(err, ErrInvalid) {
		t.Fatal("zero store accepted")
	}
	if err := d.Create(appstoreanchorrequest.Intent{}); !errors.Is(err, ErrInvalid) {
		t.Fatal("zero intent accepted")
	}
	if err := d.Create(testIntent(t, 2, 4)); !errors.Is(err, ErrInvalid) {
		t.Fatal("cross-store accepted")
	}
	if _, err := d.Load([16]byte{}); !errors.Is(err, ErrInvalid) {
		t.Fatal("zero transaction accepted")
	}
	if _, err := d.Load(testID(4)); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing intent accepted")
	}
	if err := os.Chmod(path, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := New(file, testID(1)); !errors.Is(err, ErrInvalid) {
		t.Fatal("public directory accepted")
	}
	if err := d.Create(testIntent(t, 1, 4)); !errors.Is(err, ErrInvalid) {
		t.Fatal("changed directory mode accepted")
	}
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	regular, err := os.CreateTemp(path, "not-directory-")
	if err != nil {
		t.Fatal(err)
	}
	defer regular.Close()
	if _, err := New(regular, testID(1)); !errors.Is(err, ErrInvalid) {
		t.Fatal("regular FD accepted")
	}
}

//go:build linux

package appstoreintentio

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestInvalidRecordsNeverBecomeIntents(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "fifo", "directory", "mode", "short", "long", "corrupt", "transaction", "scope"} {
		t.Run(kind, func(t *testing.T) {
			d, _, path := testDirectory(t)
			intent := testIntent(t, 1, 4)
			raw := intent.Bytes()
			target := filepath.Join(path, name(testID(4)))
			switch kind {
			case "symlink":
				outside := filepath.Join(t.TempDir(), "synthetic-record")
				if err := os.WriteFile(outside, raw[:], 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, target); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := d.Create(intent); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(target, filepath.Join(path, "other-link")); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := unix.Mkfifo(target, 0600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(target, 0700); err != nil {
					t.Fatal(err)
				}
			default:
				data := raw[:]
				mode := os.FileMode(0600)
				switch kind {
				case "mode":
					mode = 0644
				case "short":
					data = data[:311]
				case "long":
					data = append(append([]byte(nil), data...), 0)
				case "corrupt":
					data[0] ^= 1
				case "transaction":
					other := testIntent(t, 1, 7)
					b := other.Bytes()
					data = b[:]
				case "scope":
					other := testIntent(t, 2, 4)
					b := other.Bytes()
					data = b[:]
				}
				if err := os.WriteFile(target, data, mode); err != nil {
					t.Fatal(err)
				}
			}
			loaded, err := d.Load(testID(4))
			if !errors.Is(err, ErrInvalid) || loaded.Valid() {
				t.Fatalf("invalid record accepted: %v", err)
			}
			if err := d.Create(intent); !errors.Is(err, ErrExists) {
				t.Fatalf("existing bad record replaced: %v", err)
			}
			if _, err := os.Lstat(target); err != nil {
				t.Fatal("failed record deleted")
			}
		})
	}
}

func TestSyncFailuresLeaveRecordButNeverAcknowledgeCreate(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		t.Run(string(rune('0'+failAt)), func(t *testing.T) {
			d, _, path := testDirectory(t)
			calls := 0
			d.state.syncFile = func(fd int) error {
				calls++
				if calls == failAt {
					return errors.New("private filesystem failure")
				}
				return unix.Fsync(fd)
			}
			intent := testIntent(t, 1, 4)
			if err := d.Create(intent); err != ErrUnavailable {
				t.Fatalf("sync failure acknowledged/leaked: %v", err)
			}
			if calls != failAt {
				t.Fatal("unexpected sync sequence")
			}
			if _, err := os.Stat(filepath.Join(path, name(testID(4)))); err != nil {
				t.Fatal("failed publication removed")
			}
			if err := d.Create(intent); !errors.Is(err, ErrExists) {
				t.Fatal("failed operation silently retried")
			}
		})
	}
}

func TestReopenComparisonDetectsChangedBytes(t *testing.T) {
	d, _, path := testDirectory(t)
	intent := testIntent(t, 1, 4)
	calls := 0
	d.state.syncFile = func(fd int) error {
		calls++
		if calls == 2 {
			raw := intent.Bytes()
			raw[24] ^= 1
			if err := os.WriteFile(filepath.Join(path, name(testID(4))), raw[:], 0600); err != nil {
				return err
			}
		}
		return unix.Fsync(fd)
	}
	if err := d.Create(intent); !errors.Is(err, ErrInvalid) {
		t.Fatalf("changed record acknowledged: %v", err)
	}
	if calls != 2 {
		t.Fatal("missing file/directory sync")
	}
}

func TestStatOwnershipAndSpecialModes(t *testing.T) {
	uid := uint32(os.Geteuid())
	directory := unix.Stat_t{Mode: unix.S_IFDIR | 0700, Uid: uid, Nlink: 1}
	if !validDirectory(&directory) {
		t.Fatal("private directory rejected")
	}
	directory.Uid = uid + 1
	if validDirectory(&directory) {
		t.Fatal("foreign owner accepted")
	}
	directory.Uid = uid
	directory.Mode |= unix.S_ISGID
	if validDirectory(&directory) {
		t.Fatal("special directory mode accepted")
	}
	file := unix.Stat_t{Mode: unix.S_IFREG | 0600, Uid: uid, Nlink: 1, Size: 312}
	if !validFile(&file, 312) {
		t.Fatal("private record rejected")
	}
	file.Uid = uid + 1
	if validFile(&file, 312) {
		t.Fatal("foreign file owner accepted")
	}
	file.Uid = uid
	file.Mode |= unix.S_ISUID
	if validFile(&file, 312) {
		t.Fatal("special file mode accepted")
	}
}

//go:build linux

package appstoreanchorledger

import (
	"errors"
	"os"
	"runtime"

	"golang.org/x/sys/unix"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorcore"
)

func privateDirectory(st *unix.Stat_t) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Mode&07777 == 0700 && st.Uid == uint32(os.Geteuid()) && st.Nlink > 0
}
func privateFile(st *unix.Stat_t) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&07777 == 0600 && st.Uid == uint32(os.Geteuid()) && st.Nlink == 1
}

func openBackend(directory *os.File, store [16]byte, capacity int) (*Backend, error) {
	if directory == nil || store == ([16]byte{}) || capacity < 1 || capacity > MaxRecords {
		return nil, ErrInvalid
	}
	defer runtime.KeepAlive(directory)
	var before unix.Stat_t
	if unix.Fstat(int(directory.Fd()), &before) != nil || !privateDirectory(&before) {
		return nil, ErrInvalid
	}
	fd, err := unix.Openat(int(directory.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	root := os.NewFile(uintptr(fd), "anchor-ledger-directory")
	var log *os.File
	success := false
	defer func() {
		if !success {
			if log != nil {
				log.Close()
			}
			root.Close()
		}
	}()
	var after unix.Stat_t
	if unix.Fstat(fd, &after) != nil || !privateDirectory(&after) || before.Dev != after.Dev || before.Ino != after.Ino {
		return nil, ErrInvalid
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, ErrBusy
		}
		return nil, ErrUnavailable
	}
	flags := unix.O_RDWR | unix.O_APPEND | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
	fileFD, err := unix.Openat(fd, "anchor.bin", flags|unix.O_CREAT|unix.O_EXCL, 0600)
	created := err == nil
	if errors.Is(err, unix.EEXIST) {
		fileFD, err = unix.Openat(fd, "anchor.bin", flags, 0)
	}
	if err != nil {
		return nil, ErrUnavailable
	}
	log = os.NewFile(uintptr(fileFD), "anchor-ledger")
	var st unix.Stat_t
	if unix.Fstat(fileFD, &st) != nil || !privateFile(&st) {
		return nil, ErrInvalid
	}
	current, _ := appstoreanchorcore.Missing(store)
	s := &backendState{root: root, log: log, store: store, limit: capacity, current: current,
		records: make([]record, 0, capacity), requests: make(map[requestKey]int, capacity), mutations: make(map[mutationKey]int, capacity),
		write: log.Write, syncFile: (*os.File).Sync}
	if created {
		initial := header(store, capacity)
		if n, err := log.Write(initial[:]); err != nil || n != len(initial) {
			return nil, ErrUnavailable
		}
		st.Size = headerSize
	}
	if err := recoverRecords(s, st.Size); err != nil {
		return nil, err
	}
	if s.syncFile(log) != nil || s.syncFile(root) != nil {
		return nil, ErrUnavailable
	}
	if err := checkFiles(s, st.Size); err != nil {
		return nil, err
	}
	success = true
	return &Backend{state: s}, nil
}

func checkFiles(s *backendState, size int64) error {
	var root, file unix.Stat_t
	if unix.Fstat(int(s.root.Fd()), &root) != nil || unix.Fstat(int(s.log.Fd()), &file) != nil {
		return ErrUnavailable
	}
	if !privateDirectory(&root) || !privateFile(&file) || file.Size != size {
		return ErrInvalid
	}
	return nil
}

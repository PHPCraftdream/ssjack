//go:build linux && amd64

package declarativeauthority

import (
	"encoding/json"
	"errors"
	"os"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
	"golang.org/x/sys/unix"
)

func PrepareState(uid int) error {
	if unix.Geteuid() != 0 || uid <= 0 {
		return ErrAuthority
	}
	fd, err := openStateParent(true)
	if err != nil {
		return ErrAuthority
	}
	defer unix.Close(fd)
	dir, e := unix.Openat(fd, "synthetic", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	createdDir := false
	if e == unix.ENOENT {
		if unix.Mkdirat(fd, "synthetic", 0700) != nil {
			return ErrAuthority
		}
		createdDir = true
		dir, e = unix.Openat(fd, "synthetic", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	}
	if e != nil {
		return ErrAuthority
	}
	defer unix.Close(dir)
	var dst unix.Stat_t
	if unix.Fstat(dir, &dst) != nil {
		return ErrAuthority
	}
	if dst.Uid == 0 {
		if !createdDir || dst.Mode&0077 != 0 || unix.Fchown(dir, uid, int(dst.Gid)) != nil || unix.Fchmod(dir, 0700) != nil {
			return ErrAuthority
		}
	} else if dst.Uid != uint32(uid) || dst.Mode&0077 != 0 {
		return ErrAuthority
	}
	lock, created := openOrCreate(dir, ".lock", 0600)
	if lock < 0 {
		return ErrAuthority
	}
	var lst unix.Stat_t
	if unix.Fstat(lock, &lst) != nil || lst.Mode&unix.S_IFMT != unix.S_IFREG || lst.Nlink != 1 || lst.Mode&0777 != 0600 {
		unix.Close(lock)
		return ErrAuthority
	}
	if created {
		if lst.Uid != 0 || unix.Fchown(lock, uid, int(dst.Gid)) != nil {
			unix.Close(lock)
			return ErrAuthority
		}
	}
	if unix.Fstat(lock, &lst) != nil || lst.Uid != uint32(uid) {
		unix.Close(lock)
		return ErrAuthority
	}
	_ = unix.Close(lock)
	statefd, e := unix.Openat(dir, "state.json", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e == nil {
		var st unix.Stat_t
		se := unix.Fstat(statefd, &st)
		unix.Close(statefd)
		if se != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != uint32(uid) || st.Mode&0777 != 0600 || st.Size < 1 || st.Size > 4096 {
			return ErrAuthority
		}
		return nil
	}
	if e != unix.ENOENT {
		return ErrAuthority
	}
	initial := struct {
		Enabled     bool   `json:"enabled"`
		Ref         string `json:"ref"`
		Revision    string `json:"revision"`
		OperationID string `json:"operation_id"`
		PlanDigest  string `json:"plan_digest"`
	}{false, "", "r0", "", strings.Repeat("0", 64)}
	b, e := json.Marshal(initial)
	if e != nil {
		return ErrAuthority
	}
	b, e = canonicaljson.Canonicalize(b)
	if e != nil {
		return ErrAuthority
	}
	pending, e := unix.Openat(dir, ".initial", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return ErrAuthority
	}
	f := os.NewFile(uintptr(pending), "initial")
	var pst unix.Stat_t
	if unix.Fstat(pending, &pst) != nil || pst.Mode&unix.S_IFMT != unix.S_IFREG || pst.Nlink != 1 || pst.Uid != 0 || pst.Mode&0777 != 0600 || f.Chown(uid, int(dst.Gid)) != nil {
		f.Close()
		_ = unix.Unlinkat(dir, ".initial", 0)
		return ErrAuthority
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		_ = unix.Unlinkat(dir, ".initial", 0)
		return ErrAuthority
	}
	if unix.Renameat2(dir, ".initial", dir, "state.json", unix.RENAME_NOREPLACE) != nil {
		_ = unix.Unlinkat(dir, ".initial", 0)
		return ErrAuthority
	}
	if unix.Fsync(dir) != nil {
		return ErrAuthority
	}
	return nil
}

func openStateParent(create bool) (int, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	var root unix.Stat_t
	if unix.Fstat(fd, &root) != nil || root.Uid != 0 || root.Mode&0022 != 0 {
		unix.Close(fd)
		return -1, errors.New("unsafe state root")
	}
	for _, part := range []string{"var", "lib", "ssjack"} {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e == unix.ENOENT && create && part == "ssjack" {
			if unix.Mkdirat(fd, part, 0755) == nil {
				next, e = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			}
		}
		_ = unix.Close(fd)
		if e != nil {
			return -1, e
		}
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&0022 != 0 {
			unix.Close(fd)
			return -1, errors.New("unsafe state ancestor")
		}
	}
	return fd, nil
}
func openOrCreate(dir int, name string, mode uint32) (int, bool) {
	fd, e := unix.Openat(dir, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if e == nil {
		return fd, true
	}
	if e != unix.EEXIST {
		return -1, false
	}
	fd, e = unix.Openat(dir, name, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, false
	}
	return fd, false
}

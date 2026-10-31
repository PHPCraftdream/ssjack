//go:build linux && amd64

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
	"golang.org/x/sys/unix"
)

func openStateDir() (int, error) {
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, e
	}
	for _, name := range []string{"var", "lib", "ssjack"} {
		next, x := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if x != nil {
			return -1, x
		}
		fd = next
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Uid != 0 || st.Mode&0022 != 0 {
			unix.Close(fd)
			return -1, errors.New("unsafe state ancestor")
		}
	}
	dir, e := unix.Openat(fd, "synthetic", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	_ = unix.Close(fd)
	if e != nil {
		return -1, e
	}
	var st unix.Stat_t
	if unix.Fstat(dir, &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 {
		unix.Close(dir)
		return -1, errors.New("unsafe state directory")
	}
	return dir, nil
}
func openRegular(dir int, name string, flags int) (*os.File, error) {
	fd, e := unix.Openat(dir, name, flags|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), name)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) || st.Mode&0777 != 0600 {
		_ = f.Close()
		return nil, errors.New("unsafe metadata file")
	}
	return f, nil
}
func acquire(f *os.File, deadline int64) bool {
	for time.Now().UnixMilli() < deadline {
		e := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if e == nil {
			return true
		}
		if e != unix.EWOULDBLOCK && e != unix.EAGAIN && e != unix.EINTR {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}
func readStateAt(dir int) (state, error) {
	var s state
	f, e := openRegular(dir, "state.json", unix.O_RDONLY)
	if e != nil {
		return s, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || info.Size() < 1 || info.Size() > maxState {
		return s, errors.New("invalid state size")
	}
	b, e := io.ReadAll(io.LimitReader(f, maxState+1))
	if e != nil || len(b) > maxState {
		return s, errors.New("invalid state size")
	}
	canon, e := canonicaljson.Canonicalize(b)
	if e != nil || !bytes.Equal(canon, b) {
		return s, errors.New("invalid canonical state")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if dec.Decode(&s) != nil || dec.Decode(new(any)) != io.EOF || s.Revision == "" || len(s.Revision) > 128 || !digest(s.PlanDigest) {
		return s, errors.New("invalid state values")
	}
	if s.Ref == "" {
		if s.Revision != "r0" || s.Enabled || s.OperationID != "" || s.PlanDigest != strings.Repeat("0", 64) {
			return s, errors.New("invalid initial state")
		}
	} else if !validDesired(map[string]any{"enabled": s.Enabled, "ref": s.Ref}) || s.OperationID == "" || s.Revision == "r0" {
		return s, errors.New("invalid persisted state")
	}
	return s, nil
}
func writeStateAt(dir int, s state) error {
	b, e := json.Marshal(s)
	if e == nil {
		b, e = canonicaljson.Canonicalize(b)
	}
	if e != nil || len(b) > maxState {
		return errors.New("invalid state write")
	}
	fd, e := unix.Openat(dir, ".pending", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fd), "pending")
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) || st.Mode&0777 != 0600 {
		_ = f.Close()
		_ = unix.Unlinkat(dir, ".pending", 0)
		return errors.New("unsafe pending state")
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		_ = unix.Unlinkat(dir, ".pending", 0)
		return errors.New("state sync failed")
	}
	if e = unix.Renameat(dir, ".pending", dir, "state.json"); e != nil {
		_ = unix.Unlinkat(dir, ".pending", 0)
		return e
	}
	return unix.Fsync(dir)
}

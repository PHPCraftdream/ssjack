//go:build linux && amd64

package declarativeauthority

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
	"golang.org/x/sys/unix"
)

var targetRevisionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type TargetLease struct {
	mu                                         sync.Mutex
	fd                                         int
	file                                       *os.File
	uid                                        uint32
	closed                                     bool
	admitted                                   bool
	expected, operation, digest, revision, ref string
	dirDev, dirIno                             uint64
}

func AcquireTarget(ctx context.Context) (*TargetLease, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrAuthority
	}
	deadline, ok := ctx.Deadline()
	if !ok || !deadline.After(time.Now()) || time.Until(deadline) > time.Minute {
		return nil, ErrAuthority
	}
	parent, err := openStateParent(false)
	if err != nil {
		return nil, ErrAuthority
	}
	defer unix.Close(parent)
	fd, err := unix.Openat(parent, "synthetic", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrAuthority
	}
	f := os.NewFile(uintptr(fd), "synthetic")
	if f == nil {
		unix.Close(fd)
		return nil, ErrAuthority
	}
	okay := false
	defer func() {
		if !okay {
			_ = f.Close()
		}
	}()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Uid == 0 || st.Mode&0777 != 0700 || st.Nlink == 0 {
		return nil, ErrAuthority
	}
	for {
		if ctx.Err() != nil {
			return nil, ErrAuthority
		}
		e := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if e == nil {
			okay = true
			return &TargetLease{fd: fd, file: f, uid: st.Uid, dirDev: uint64(st.Dev), dirIno: st.Ino}, nil
		}
		if e != unix.EWOULDBLOCK && e != unix.EAGAIN && e != unix.EINTR {
			return nil, ErrAuthority
		}
		t := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ErrAuthority
		case <-t.C:
		}
	}
}

type targetState struct {
	Enabled     bool   `json:"enabled"`
	Ref         string `json:"ref"`
	Revision    string `json:"revision"`
	OperationID string `json:"operation_id"`
	PlanDigest  string `json:"plan_digest"`
}

func sameTargetStateStat(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func (l *TargetLease) read(ctx context.Context) (targetState, error) {
	var s targetState
	if ctx == nil || ctx.Err() != nil || l == nil || l.closed || l.fd < 0 {
		return s, ErrAuthority
	}
	var d unix.Stat_t
	if unix.Fstat(l.fd, &d) != nil || d.Uid != l.uid || d.Dev != uint64(l.dirDev) || d.Ino != l.dirIno || d.Mode&unix.S_IFMT != unix.S_IFDIR || d.Mode&0777 != 0700 || d.Nlink == 0 {
		return s, ErrAuthority
	}
	parent, e := openStateParent(false)
	if e != nil {
		return s, ErrAuthority
	}
	defer unix.Close(parent)
	current, e := unix.Openat(parent, "synthetic", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return s, ErrAuthority
	}
	defer unix.Close(current)
	var currentStat unix.Stat_t
	if unix.Fstat(current, &currentStat) != nil || currentStat.Dev != d.Dev || currentStat.Ino != d.Ino || currentStat.Uid != l.uid || currentStat.Mode&unix.S_IFMT != unix.S_IFDIR || currentStat.Mode&0777 != 0700 {
		return s, ErrAuthority
	}
	fd, e := unix.Openat(l.fd, "state.json", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return s, ErrAuthority
	}
	var st unix.Stat_t
	f := os.NewFile(uintptr(fd), "state.json")
	if f == nil {
		unix.Close(fd)
		return s, ErrAuthority
	}
	defer f.Close()
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != l.uid || st.Mode&0777 != 0600 || st.Size < 1 || st.Size > 4096 {
		return s, ErrAuthority
	}
	b, e := io.ReadAll(io.LimitReader(f, 4097))
	if e != nil || len(b) > 4096 {
		return s, ErrAuthority
	}
	var after unix.Stat_t
	var named unix.Stat_t
	if unix.Fstat(fd, &after) != nil || unix.Fstatat(l.fd, "state.json", &named, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameTargetStateStat(st, after) || !sameTargetStateStat(st, named) {
		return s, ErrAuthority
	}
	c, e := canonicaljson.Canonicalize(b)
	if e != nil || !bytes.Equal(c, b) {
		return s, ErrAuthority
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if dec.Decode(&s) != nil || dec.Decode(new(any)) != io.EOF || !targetRevisionPattern.MatchString(s.Revision) || !digestPattern.MatchString(s.PlanDigest) {
		return targetState{}, ErrAuthority
	}
	return s, nil
}
func (l *TargetLease) Admit(ctx context.Context, expectedRevision, operationID, planDigest string) error {
	if l == nil || ctx == nil || ctx.Err() != nil || !targetRevisionPattern.MatchString(expectedRevision) || operationID == "" || len(operationID) > 128 || !digestPattern.MatchString(planDigest) {
		return ErrAuthority
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.admitted {
		return ErrAuthority
	}
	s, e := l.read(ctx)
	if e != nil || !s.Enabled || ValidateReference(s.Ref) != nil || s.OperationID != operationID || s.PlanDigest != planDigest || s.Revision == expectedRevision {
		return ErrAuthority
	}
	l.expected, l.operation, l.digest, l.revision, l.ref, l.admitted = expectedRevision, operationID, planDigest, s.Revision, s.Ref, true
	return nil
}
func (l *TargetLease) Check(ctx context.Context, expectedRevision, operationID, planDigest string) error {
	if l == nil {
		return ErrAuthority
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.admitted || l.closed || expectedRevision != l.expected || operationID != l.operation || planDigest != l.digest {
		return ErrAuthority
	}
	s, e := l.read(ctx)
	if e != nil || !s.Enabled || s.Ref != l.ref || s.Revision != l.revision || s.OperationID != l.operation || s.PlanDigest != l.digest {
		return ErrAuthority
	}
	return nil
}
func (l *TargetLease) CheckReference(ctx context.Context, expectedRevision, operationID, planDigest, ref string) error {
	if err := l.Check(ctx, expectedRevision, operationID, planDigest); err != nil {
		return ErrAuthority
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.admitted || l.closed || ref == "" || ref != l.ref {
		return ErrAuthority
	}
	return nil
}

func (l *TargetLease) Close() error {
	if l == nil {
		return ErrAuthority
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	fd := l.fd
	file := l.file
	l.fd = -1
	l.file = nil
	if fd < 0 || file == nil {
		return ErrAuthority
	}
	e := unix.Flock(fd, unix.LOCK_UN)
	ce := file.Close()
	if e != nil || ce != nil {
		return ErrAuthority
	}
	return nil
}

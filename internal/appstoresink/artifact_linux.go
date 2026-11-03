//go:build linux

package appstoresink

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"golang.org/x/sys/unix"
)

type cancelSlot struct{ cancel context.CancelFunc }
type consumerState struct {
	mu       sync.Mutex
	program  *os.File
	binding  Binding
	expires  time.Time
	consumed bool
	revoked  atomic.Bool
	cancel   atomic.Pointer[cancelSlot]
	active   atomic.Pointer[deliveryState]
}

type artifactRevision struct {
	device, inode     uint64
	size              int64
	modified, changed unix.Timespec
	mode, owner       uint32
}

func newConsumer(config Config) (*Consumer, error) {
	if config.Program == nil || !validBinding(config.Binding) {
		return nil, ErrInvalid
	}
	if _, err := programRevision(config.Program); err != nil {
		return nil, err
	}
	fd, err := unix.FcntlInt(config.Program.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	program := os.NewFile(uintptr(fd), "fixed-consumer-program")
	if _, err = programRevision(program); err != nil {
		_ = program.Close()
		return nil, err
	}
	now := time.Now()
	ttl := config.Binding.ExpiresAt.Sub(now)
	if ttl <= 0 || ttl > 24*time.Hour {
		_ = program.Close()
		return nil, ErrInvalid
	}
	return &Consumer{state: &consumerState{program: program, binding: config.Binding, expires: now.Add(ttl)}}, nil
}
func consumerBinding(c *Consumer) Binding {
	if c == nil || c.state == nil {
		return Binding{}
	}
	return c.state.binding
}
func checkConsumer(c *Consumer, ref appstoreref.Ref, hash [32]byte) error {
	if c == nil || c.state == nil {
		return ErrDenied
	}
	s := c.state
	if s.revoked.Load() || !time.Now().Before(s.expires) || !validBinding(s.binding) || ref != s.binding.Reference || hash != s.binding.EncodedHash {
		return ErrDenied
	}
	return nil
}
func closeConsumer(c *Consumer) error {
	if c == nil || c.state == nil {
		return nil
	}
	s := c.state
	s.revoked.Store(true)
	if slot := s.cancel.Load(); slot != nil {
		slot.cancel()
	}
	s.mu.Lock()
	var err error
	if s.program != nil {
		err = s.program.Close()
		s.program = nil
	}
	active := s.active.Load()
	s.mu.Unlock()
	if active != nil {
		_ = closeDelivery(&Delivery{state: active})
	}
	if err != nil {
		return ErrUnavailable
	}
	return nil
}
func programRevision(f *os.File) (artifactRevision, error) {
	var st unix.Stat_t
	if f == nil || unix.Fstat(int(f.Fd()), &st) != nil {
		return artifactRevision{}, ErrUnavailable
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0022 != 0 || st.Mode&0111 == 0 || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || st.Size < 64 || st.Size > maxProgram || st.Nlink == 0 {
		return artifactRevision{}, ErrInvalid
	}
	return artifactRevision{uint64(st.Dev), st.Ino, st.Size, st.Mtim, st.Ctim, st.Mode, st.Uid}, nil
}

func freezeProgram(ctx context.Context, source *os.File, expected [32]byte) (*os.File, [2]uint64, error) {
	var identity [2]uint64
	before, err := programRevision(source)
	if err != nil {
		return nil, identity, err
	}
	fd, err := unix.MemfdCreate("ssjack-fixed-consumer", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING|unix.MFD_EXEC)
	if err != nil {
		return nil, identity, ErrUnsupported
	}
	frozen := os.NewFile(uintptr(fd), "fixed-consumer-code")
	keep := false
	defer func() {
		if !keep {
			_ = frozen.Close()
		}
	}()
	buffer := make([]byte, 32768)
	defer clear(buffer)
	hash := sha256.New()
	for offset := int64(0); offset < before.size; {
		if err := ctx.Err(); err != nil {
			return nil, identity, err
		}
		n := int64(len(buffer))
		if n > before.size-offset {
			n = before.size - offset
		}
		if got, err := source.ReadAt(buffer[:n], offset); err != nil || int64(got) != n {
			return nil, identity, ErrUnavailable
		}
		if got, err := frozen.Write(buffer[:n]); err != nil || int64(got) != n {
			return nil, identity, ErrUnavailable
		}
		_, _ = hash.Write(buffer[:n])
		offset += n
	}
	after, err := programRevision(source)
	if err != nil || before != after {
		return nil, identity, ErrDenied
	}
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	if digest != expected {
		return nil, identity, ErrDenied
	}
	if err := staticNative(frozen, before.size); err != nil {
		return nil, identity, err
	}
	if frozen.Chmod(0500) != nil {
		return nil, identity, ErrUnavailable
	}
	seals := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if _, err := unix.FcntlInt(frozen.Fd(), unix.F_ADD_SEALS, seals); err != nil {
		return nil, identity, ErrUnsupported
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil {
		return nil, identity, ErrUnavailable
	}
	identity = [2]uint64{uint64(st.Dev), st.Ino}
	keep = true
	return frozen, identity, nil
}

func staticNative(f *os.File, size int64) error {
	var header [64]byte
	if _, err := f.ReadAt(header[:], 0); err != nil {
		return ErrUnsupported
	}
	if string(header[:4]) != "\x7fELF" || header[4] != 2 || header[5] != 1 || header[6] != 1 {
		return ErrUnsupported
	}
	kind, machine := binary.LittleEndian.Uint16(header[16:18]), binary.LittleEndian.Uint16(header[18:20])
	if (kind != 2 && kind != 3) || !((runtime.GOARCH == "amd64" && machine == 62) || (runtime.GOARCH == "arm64" && machine == 183)) {
		return ErrUnsupported
	}
	offset := binary.LittleEndian.Uint64(header[32:40])
	count := uint64(binary.LittleEndian.Uint16(header[56:58]))
	if binary.LittleEndian.Uint32(header[20:24]) != 1 || binary.LittleEndian.Uint16(header[52:54]) != 64 || binary.LittleEndian.Uint16(header[54:56]) != 56 || count == 0 || count > 128 || offset < 64 || offset > uint64(size) || count*56 > uint64(size)-offset {
		return ErrUnsupported
	}
	for index := uint64(0); index < count; index++ {
		var program [56]byte
		if _, err := f.ReadAt(program[:], int64(offset+index*56)); err != nil {
			return ErrUnsupported
		}
		typeID := binary.LittleEndian.Uint32(program[:4])
		if typeID == 2 || typeID == 3 {
			return ErrUnsupported
		}
	}
	return nil
}

func peerCredentials(pid int) bool {
	status, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return false
	}
	defer status.Close()
	raw, err := io.ReadAll(io.LimitReader(status, 8193))
	if err != nil || len(raw) > 8192 {
		return false
	}
	var seen [2]bool
	for _, line := range bytes.Split(raw, []byte{'\n'}) {
		fields := bytes.Fields(line)
		if len(fields) == 0 {
			continue
		}
		index, expected := -1, uint64(0)
		if string(fields[0]) == "Uid:" {
			index, expected = 0, uint64(os.Geteuid())
		}
		if string(fields[0]) == "Gid:" {
			index, expected = 1, uint64(os.Getegid())
		}
		if index < 0 {
			continue
		}
		if seen[index] || len(fields) != 5 {
			return false
		}
		seen[index] = true
		for _, field := range fields[1:] {
			value, err := strconv.ParseUint(string(field), 10, 32)
			if err != nil || value != expected {
				return false
			}
		}
	}
	return seen[0] && seen[1]
}

func checkPeer(pid int, identity [2]uint64) error {
	if pid <= 0 {
		return ErrUnavailable
	}
	f, err := os.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ErrUnavailable
	}
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil || [2]uint64{uint64(st.Dev), st.Ino} != identity || st.Uid != uint32(os.Geteuid()) || !peerCredentials(pid) {
		return ErrDenied
	}
	return nil
}

//go:build linux

package immutableexec

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/driverframe"
	"github.com/PHPCraftdream/ssjack/internal/driverprotocol"
	"golang.org/x/sys/unix"
)

const MaxExecutableBytes int64 = 64 << 20

// Runner owns sealed bytes. Digest must be authenticated and trusted by caller;
// binding establishes neither provenance, authorization nor process identity.
// Caller trusts source filesystem during snapshot, kernel/procfs, args/env/dir.
// Runtime shared-library dependencies, artifact provenance and process identity
// are not established. This is not a sandbox. x/sys/unix supplies Linux syscalls.
type Runner struct {
	file *os.File
	args []string
	mu   sync.Mutex
}

func Bind(name string, digest [32]byte, args ...string) (*Runner, error) {
	return bind(name, digest, nil, args...)
}

type bindHooks struct {
	afterOpen  func(*os.File) error
	afterMemfd func(*os.File) error
}

func bind(name string, digest [32]byte, hooks *bindHooks, args ...string) (*Runner, error) {
	if runtime.GOARCH != "amd64" {
		return nil, errors.New("unsupported architecture")
	}
	if len(name) < 2 || name[0] != '/' || strings.ContainsRune(name, 0) || strings.Contains(name, "//") || strings.Contains(name, "/../") || strings.HasSuffix(name, "/..") || strings.Contains(name, "/./") || strings.HasSuffix(name, "/.") {
		return nil, errors.New("path must be absolute and clean")
	}
	parts := strings.Split(name[1:], "/")
	if len(parts) < 2 {
		return nil, errors.New("invalid executable path")
	}
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	for i, p := range parts {
		if p == "" || p == "." || p == ".." {
			unix.Close(fd)
			return nil, errors.New("invalid component")
		}
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		next, err := unix.Openat(fd, p, flags, 0)
		unix.Close(fd)
		if err != nil {
			return nil, err
		}
		fd = next
	}
	src := os.NewFile(uintptr(fd), name)
	defer src.Close()
	if hooks != nil && hooks.afterOpen != nil {
		if e := hooks.afterOpen(src); e != nil {
			return nil, e
		}
	}
	st, e := src.Stat()
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Size() < 64 || st.Size() > MaxExecutableBytes {
		return nil, errors.New("unsafe executable type or size")
	}
	m, e := unix.MemfdCreate("immutable-exec", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if e != nil {
		return nil, e
	}
	mem := os.NewFile(uintptr(m), "immutable-exec")
	fail := func(err error) (*Runner, error) { mem.Close(); return nil, err }
	if hooks != nil && hooks.afterMemfd != nil {
		if e := hooks.afterMemfd(mem); e != nil {
			return fail(e)
		}
	}
	n, e := io.Copy(mem, io.LimitReader(src, MaxExecutableBytes+1))
	if e != nil {
		return fail(e)
	}
	if n != st.Size() || n > MaxExecutableBytes {
		return fail(errors.New("executable size changed or too large"))
	}
	if e = unix.Fchmod(m, 0500); e != nil {
		return fail(e)
	}
	seals := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if _, e = unix.FcntlInt(uintptr(m), unix.F_ADD_SEALS, seals); e != nil {
		return fail(e)
	}
	if _, e = mem.Seek(0, 0); e != nil {
		return fail(e)
	}
	h := sha256.New()
	if _, e = io.Copy(h, io.LimitReader(mem, MaxExecutableBytes+1)); e != nil {
		return fail(e)
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	if sum != digest {
		return fail(errors.New("sealed digest mismatch"))
	}
	if e = validateELF(mem, n); e != nil {
		return fail(e)
	}
	if _, e = mem.Seek(0, 0); e != nil {
		return fail(e)
	}
	return &Runner{file: mem, args: append([]string(nil), args...)}, nil
}

func validateELF(f *os.File, size int64) error {
	var h [64]byte
	if _, e := f.ReadAt(h[:], 0); e != nil {
		return e
	}
	if string(h[:4]) != "\x7fELF" || h[4] != 2 || h[5] != 1 || h[6] != 1 || binary.LittleEndian.Uint16(h[16:]) != 2 || binary.LittleEndian.Uint16(h[52:]) != 64 {
		return errors.New("unsupported ELF header")
	}
	if binary.LittleEndian.Uint16(h[18:]) != 62 || binary.LittleEndian.Uint32(h[20:]) != 1 {
		return errors.New("unsupported ELF machine")
	}
	shoff := binary.LittleEndian.Uint64(h[40:48])
	shentsize, shnum, shstr := binary.LittleEndian.Uint16(h[58:]), binary.LittleEndian.Uint16(h[60:]), binary.LittleEndian.Uint16(h[62:])
	if shoff != 0 || shentsize != 0 || shnum != 0 || shstr != 0 {
		return errors.New("ELF sections unsupported")
	}
	entry := binary.LittleEndian.Uint64(h[24:32])
	off, ent, count := binary.LittleEndian.Uint64(h[32:40]), uint64(binary.LittleEndian.Uint16(h[54:])), uint64(binary.LittleEndian.Uint16(h[56:]))
	if ent != 56 || count == 0 || count > 128 || off > uint64(size) || count > (uint64(size)-off)/ent {
		return errors.New("invalid or unbounded program headers")
	}
	loads := 0
	entryOK := false
	for i := uint64(0); i < count; i++ {
		var p [56]byte
		if _, e := f.ReadAt(p[:], int64(off+i*ent)); e != nil {
			return e
		}
		typ, flags := binary.LittleEndian.Uint32(p[:4]), binary.LittleEndian.Uint32(p[4:8])
		po, va := binary.LittleEndian.Uint64(p[8:16]), binary.LittleEndian.Uint64(p[16:24])
		filesz, memsz, align := binary.LittleEndian.Uint64(p[32:40]), binary.LittleEndian.Uint64(p[40:48]), binary.LittleEndian.Uint64(p[48:56])
		if typ == 2 || typ == 3 {
			return errors.New("dynamic executable rejected")
		}
		if typ == 1 {
			loads++
			if po > uint64(size) || filesz > uint64(size)-po || filesz > memsz || va > ^uint64(0)-memsz || (align > 1 && (align&(align-1) != 0 || (va-po)&(align-1) != 0)) {
				return errors.New("invalid load segment")
			}
			if flags&1 != 0 && entry >= va && entry-va < filesz {
				entryOK = true
			}
		}
	}
	if loads == 0 || !entryOK {
		return errors.New("missing executable entry load segment")
	}
	return nil
}

func (r *Runner) Run(ctx context.Context, env []string, dir string) error {
	return r.run(ctx, env, dir, nil)
}

func (r *Runner) run(ctx context.Context, env []string, dir string, started func(int)) error {
	if ctx == nil {
		return errors.New("explicit deadline context required")
	}
	if _, ok := ctx.Deadline(); !ok {
		return errors.New("explicit deadline required")
	}
	if err := validateEnvironment(env); err != nil {
		return err
	}
	if r == nil {
		return errors.New("closed binding")
	}
	if !r.mu.TryLock() {
		return errors.New("runner is already executing or closing")
	}
	defer r.mu.Unlock()
	if r.file == nil {
		return errors.New("closed binding")
	}
	c := exec.CommandContext(ctx, "/proc/self/fd/3", r.args...)
	c.ExtraFiles = []*os.File{r.file}
	c.Env = append([]string{}, env...)
	c.Dir = dir
	if err := c.Start(); err != nil {
		return err
	}
	if started != nil {
		started(c.Process.Pid)
	}
	return c.Wait()
}

// Observe accepts one unframed structural observe request and returns only a
// structural response marker. A protocol-valid failure outcome also returns
// the marker; nil error does not imply success or authorization.
func (r *Runner) Observe(ctx context.Context, env []string, dir string, requestBytes []byte) (driverprotocol.StructuralResponse, error) {
	return r.observe(ctx, env, dir, requestBytes, nil)
}

func (r *Runner) observe(ctx context.Context, env []string, dir string, requestBytes []byte, started func(int)) (driverprotocol.StructuralResponse, error) {
	request, err := validateObserveRequest(ctx, env, requestBytes)
	if err != nil {
		return driverprotocol.StructuralResponse{}, err
	}
	if r == nil || !r.mu.TryLock() {
		return driverprotocol.StructuralResponse{}, errors.New("closed binding or runner busy")
	}
	defer r.mu.Unlock()
	if r.file == nil {
		return driverprotocol.StructuralResponse{}, errors.New("closed binding")
	}
	if err := ctx.Err(); err != nil {
		return driverprotocol.StructuralResponse{}, err
	}
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3", r.args...)
	cmd.WaitDelay = 2 * time.Second
	cmd.ExtraFiles = []*os.File{r.file}
	cmd.Env, cmd.Dir = append([]string{}, env...), dir
	var stdin bytes.Buffer
	if err := driverframe.Write(&stdin, requestBytes); err != nil {
		return driverprotocol.StructuralResponse{}, driverprotocol.ErrInvalid
	}
	cmd.Stdin = bytes.NewReader(stdin.Bytes())
	var stdout bytes.Buffer
	writers := &observeWriters{cmd: cmd, stdout: &stdout}
	cmd.Stdout, cmd.Stderr = observeStream{writers, false}, observeStream{writers, true}
	if err := cmd.Start(); err != nil {
		if ctx.Err() != nil {
			return driverprotocol.StructuralResponse{}, ctx.Err()
		}
		return driverprotocol.StructuralResponse{}, errors.New("observe child could not start")
	}
	if started != nil {
		started(cmd.Process.Pid)
	}
	writers.publishStarted()
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return driverprotocol.StructuralResponse{}, ctx.Err()
	}
	if writers.overflow {
		return driverprotocol.StructuralResponse{}, errors.New("observe output limit exceeded")
	} else if waitErr != nil {
		return driverprotocol.StructuralResponse{}, errors.New("observe child failed")
	}
	response, err := driverprotocol.ReadStructuralResponse(request, bytes.NewReader(stdout.Bytes()))
	if err != nil {
		return driverprotocol.StructuralResponse{}, errors.New("invalid observe response")
	}
	return response, nil
}

func (r *Runner) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file == nil {
		return nil
	}
	e := r.file.Close()
	r.file = nil
	return e
}

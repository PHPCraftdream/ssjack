//go:build linux

package immutableexec

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func (r *Runner) fd() uintptr {
	if r == nil || r.file == nil {
		return ^uintptr(0)
	}
	return r.file.Fd()
}
func fakeELF(code, extra []byte) []byte {
	b := make([]byte, 120+len(code)+len(extra))
	copy(b, "\x7fELF")
	b[4] = 2
	b[5] = 1
	b[6] = 1
	binary.LittleEndian.PutUint16(b[16:], 2)
	binary.LittleEndian.PutUint16(b[18:], 62)
	binary.LittleEndian.PutUint32(b[20:], 1)
	binary.LittleEndian.PutUint64(b[24:], 0x400078)
	binary.LittleEndian.PutUint64(b[32:], 64)
	binary.LittleEndian.PutUint16(b[52:], 64)
	binary.LittleEndian.PutUint16(b[54:], 56)
	binary.LittleEndian.PutUint16(b[56:], 1)
	binary.LittleEndian.PutUint32(b[64:], 1)
	binary.LittleEndian.PutUint32(b[68:], 5)
	binary.LittleEndian.PutUint64(b[80:], 0x400000)
	binary.LittleEndian.PutUint64(b[96:], uint64(len(b)))
	binary.LittleEndian.PutUint64(b[104:], uint64(len(b)))
	binary.LittleEndian.PutUint64(b[112:], 0x1000)
	copy(b[120:], code)
	copy(b[120+len(code):], extra)
	return b
}
func closeUnexpected(t *testing.T, r *Runner) {
	t.Helper()
	if r != nil {
		if err := r.Close(); err != nil {
			t.Errorf("close unexpected runner: %v", err)
		}
		t.Error("rejection returned an unexpected runner")
	}
}
func writeExec(t *testing.T, p string, b []byte) {
	t.Helper()
	if e := os.WriteFile(p, b, 0700); e != nil {
		t.Fatal(e)
	}
}
func TestSealedSnapshotAgainstSourceReplacement(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("synthetic ELF is amd64")
	}
	pass := fakeELF([]byte{0xb8, 60, 0, 0, 0, 0xbf, 0, 0, 0, 0, 0x0f, 0x05}, nil)
	fail := fakeELF([]byte{0xb8, 60, 0, 0, 0, 0xbf, 1, 0, 0, 0, 0x0f, 0x05}, nil)
	p := filepath.Join(t.TempDir(), "program")
	writeExec(t, p, pass)
	r, e := Bind(p, sha256.Sum256(pass))
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	if e = os.Rename(p, p+".old"); e != nil {
		t.Fatal(e)
	}
	writeExec(t, p, fail)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Second))
	defer cancel()
	if e = r.Run(ctx, []string{}, ""); e != nil {
		t.Fatalf("bound child did not exit zero: %v", e)
	}
	for name, mutate := range map[string]func() error{
		"write":  func() error { _, err := unix.Pwrite(int(r.fd()), []byte{1}, 120); return err },
		"grow":   func() error { return unix.Ftruncate(int(r.fd()), int64(len(pass)+1)) },
		"shrink": func() error { return unix.Ftruncate(int(r.fd()), int64(len(pass)-1)) },
	} {
		if err := mutate(); !errors.Is(err, unix.EPERM) {
			t.Errorf("%s mutation error = %v", name, err)
		}
	}
	seals, e := unix.FcntlInt(r.fd(), unix.F_GET_SEALS, 0)
	if e != nil || seals&(unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK) != (unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK) {
		t.Fatalf("seals=%x err=%v", seals, e)
	}
	fd := r.fd()
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = unix.FcntlInt(fd, unix.F_GETFD, 0); e == nil {
		t.Fatal("descriptor leaked")
	} else if !errors.Is(e, unix.EBADF) {
		t.Fatalf("closed descriptor error = %v, want EBADF", e)
	}
}
func TestRejectPathsBoundsAndFormats(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("amd64 only")
	}
	d := t.TempDir()
	dir := filepath.Join(d, "dir")
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	data := fakeELF([]byte{0x90}, nil)
	p := filepath.Join(dir, "x")
	writeExec(t, p, data)
	good, err := Bind(p, sha256.Sum256(data))
	if err != nil {
		t.Fatalf("correct digest baseline: %v", err)
	}
	if err := good.Close(); err != nil {
		t.Fatal(err)
	}
	emptyRunner, emptyErr := Bind("", [32]byte{})
	closeUnexpected(t, emptyRunner)
	if emptyErr == nil {
		t.Fatal("empty accepted")
	}
	linkdir := filepath.Join(d, "symdir")
	if e := os.Symlink(dir, linkdir); e != nil {
		t.Fatal(e)
	}
	linkRunner, linkErr := Bind(filepath.Join(linkdir, "x"), sha256.Sum256(data))
	closeUnexpected(t, linkRunner)
	if !errors.Is(linkErr, unix.ENOTDIR) {
		t.Fatalf("intermediate symlink error = %v", linkErr)
	}
	if e := os.Symlink(p, filepath.Join(d, "final")); e != nil {
		t.Fatal(e)
	}
	finalRunner, finalErr := Bind(filepath.Join(d, "final"), sha256.Sum256(data))
	closeUnexpected(t, finalRunner)
	if !errors.Is(finalErr, unix.ELOOP) {
		t.Fatalf("final symlink error = %v", finalErr)
	}
	wrong, e := Bind(p, [32]byte{})
	closeUnexpected(t, wrong)
	if e == nil {
		t.Fatal("wrong digest")
	}
	if runtime.GOARCH == "amd64" && !strings.Contains(e.Error(), "digest") {
		t.Fatalf("wrong digest reached another rejection: %v", e)
	}
	script := []byte("#!/bin/sh\nexit 0\n")
	sp := filepath.Join(d, "script")
	writeExec(t, sp, script)
	scriptRunner, scriptErr := Bind(sp, sha256.Sum256(script))
	closeUnexpected(t, scriptRunner)
	if scriptErr == nil {
		t.Fatal("script accepted")
	}
	interp := make([]byte, 184)
	copy(interp, fakeELF([]byte{0x90}, nil))
	binary.LittleEndian.PutUint64(interp[96:], uint64(len(interp)))
	binary.LittleEndian.PutUint64(interp[104:], uint64(len(interp)))
	binary.LittleEndian.PutUint16(interp[56:], 2)
	binary.LittleEndian.PutUint32(interp[120:], uint32(elf.PT_INTERP))
	binary.LittleEndian.PutUint32(interp[124:], 4)
	binary.LittleEndian.PutUint64(interp[128:], 176)
	binary.LittleEndian.PutUint64(interp[152:], 8)
	binary.LittleEndian.PutUint64(interp[160:], 8)
	copy(interp[176:], "/ld.so\x00")
	if runtime.GOARCH == "amd64" {
		f, openErr := elf.NewFile(bytes.NewReader(interp))
		if openErr != nil {
			t.Fatalf("invalid PT_INTERP fixture: %v", openErr)
		}
		if f.Type != elf.ET_EXEC || f.Machine != elf.EM_X86_64 || len(f.Progs) != 2 || f.Progs[0].Type != elf.PT_LOAD || f.Progs[1].Type != elf.PT_INTERP {
			t.Fatal("fixture lacks expected native ET_EXEC/PT_INTERP")
		}
		f.Close()
	}
	ip := filepath.Join(d, "interp")
	writeExec(t, ip, interp)
	interpRunner, bindErr := Bind(ip, sha256.Sum256(interp))
	closeUnexpected(t, interpRunner)
	if bindErr == nil || !strings.Contains(bindErr.Error(), "dynamic executable rejected") {
		t.Fatalf("PT_INTERP rejection: %v", bindErr)
	}
	huge := filepath.Join(d, "huge")
	f, e := os.Create(huge)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if e = f.Truncate(MaxExecutableBytes + 1); e != nil {
		t.Fatal(e)
	}
	oversizeRunner, oversizeErr := Bind(huge, [32]byte{})
	closeUnexpected(t, oversizeRunner)
	if oversizeErr == nil {
		t.Fatal("oversize accepted")
	}
	fifo := filepath.Join(d, "fifo")
	if e = unix.Mkfifo(fifo, 0600); e != nil {
		t.Fatal(e)
	}
	fifoRunner, fifoErr := Bind(fifo, [32]byte{})
	closeUnexpected(t, fifoRunner)
	if fifoErr == nil {
		t.Fatal("fifo accepted")
	}
}
func TestExplicitEnvironmentAndValidation(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("synthetic ELF requires amd64")
	}
	marker := filepath.Join(t.TempDir(), "marker")
	pathBytes := append([]byte(marker), 0)
	code := []byte{0x48, 0x8d, 0x3d, 0, 0, 0, 0, 0xbe, 0x41, 0, 0, 0, 0xba, 0x80, 1, 0, 0, 0xb8, 2, 0, 0, 0, 0x0f, 0x05, 0xb8, 60, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05}
	binary.LittleEndian.PutUint32(code[3:], uint32(len(code)-7))
	data := fakeELF(code, pathBytes)
	path := filepath.Join(t.TempDir(), "env-child")
	writeExec(t, path, data)
	r, err := Bind(path, sha256.Sum256(data))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(30*time.Second))
	defer cancel()
	if err := r.Run(ctx, []string{}, ""); err != nil {
		t.Fatalf("positive control did not create marker: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("positive-control marker missing: %v", err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSJACK_TEST_PARENT_MARKER", "benign-marker")
	emptyEnvCode := []byte{
		0x48, 0x83, 0x7c, 0x24, 0x18, 0x00, // cmpq $0, 24(%rsp): first envp entry (one argv)
		0x75, 0x09, // jne nonempty
		0xb8, 60, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05, // exit(0)
		0xb8, 60, 0, 0, 0, 0xbf, 1, 0, 0, 0, 0x0f, 0x05, // exit(1)
	}
	emptyEnvData := fakeELF(emptyEnvCode, nil)
	emptyEnvPath := filepath.Join(t.TempDir(), "empty-env-child")
	writeExec(t, emptyEnvPath, emptyEnvData)
	emptyEnvRunner, err := Bind(emptyEnvPath, sha256.Sum256(emptyEnvData))
	if err != nil {
		t.Fatal(err)
	}
	defer emptyEnvRunner.Close()
	if err := emptyEnvRunner.Run(ctx, []string{}, ""); err != nil {
		t.Fatalf("empty-environment child found inherited environment: %v", err)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("marker unexpectedly present before rejection loop (stat error %v)", err)
	}
	for _, tc := range []struct {
		name string
		env  []string
	}{
		{"nil", nil}, {"unsafe key", []string{"PATH=/tmp"}}, {"malformed", []string{"LANG"}},
		{"duplicate", []string{"LANG=C", "LANG=C"}}, {"NUL", []string{"LANG=C\x00bad"}},
		{"parent marker", []string{"SSJACK_TEST_PARENT_MARKER=benign-marker"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := r.Run(ctx, tc.env, ""); !errors.Is(err, ErrInvalidEnvironment) {
				t.Fatalf("error = %v, want ErrInvalidEnvironment", err)
			}
			if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("rejected environment child created marker (stat error %v)", err)
			}
		})
	}
	if err := r.Run(nil, []string{}, ""); err == nil || errors.Is(err, ErrInvalidEnvironment) {
		t.Errorf("nil context error = %v, want distinct context error", err)
	}
	if err := r.Run(context.Background(), []string{}, ""); err == nil || errors.Is(err, ErrInvalidEnvironment) {
		t.Errorf("missing deadline error = %v, want distinct context error", err)
	}
}

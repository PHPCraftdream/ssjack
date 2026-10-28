//go:build linux

package immutableexectest

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/immutableexec"
	"golang.org/x/sys/unix"
)

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
func closeUnexpected(t *testing.T, r *immutableexec.Runner) {
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
	good, err := immutableexec.Bind(p, sha256.Sum256(data))
	if err != nil {
		t.Fatalf("correct digest baseline: %v", err)
	}
	if err := good.Close(); err != nil {
		t.Fatal(err)
	}
	emptyRunner, emptyErr := immutableexec.Bind("", [32]byte{})
	closeUnexpected(t, emptyRunner)
	if emptyErr == nil {
		t.Fatal("empty accepted")
	}
	linkdir := filepath.Join(d, "symdir")
	if e := os.Symlink(dir, linkdir); e != nil {
		t.Fatal(e)
	}
	linkRunner, linkErr := immutableexec.Bind(filepath.Join(linkdir, "x"), sha256.Sum256(data))
	closeUnexpected(t, linkRunner)
	if !errors.Is(linkErr, unix.ENOTDIR) {
		t.Fatalf("intermediate symlink error = %v", linkErr)
	}
	if e := os.Symlink(p, filepath.Join(d, "final")); e != nil {
		t.Fatal(e)
	}
	finalRunner, finalErr := immutableexec.Bind(filepath.Join(d, "final"), sha256.Sum256(data))
	closeUnexpected(t, finalRunner)
	if !errors.Is(finalErr, unix.ELOOP) {
		t.Fatalf("final symlink error = %v", finalErr)
	}
	wrong, e := immutableexec.Bind(p, [32]byte{})
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
	scriptRunner, scriptErr := immutableexec.Bind(sp, sha256.Sum256(script))
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
	interpRunner, bindErr := immutableexec.Bind(ip, sha256.Sum256(interp))
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
	if e = f.Truncate(immutableexec.MaxExecutableBytes + 1); e != nil {
		t.Fatal(e)
	}
	oversizeRunner, oversizeErr := immutableexec.Bind(huge, [32]byte{})
	closeUnexpected(t, oversizeRunner)
	if oversizeErr == nil {
		t.Fatal("oversize accepted")
	}
	fifo := filepath.Join(d, "fifo")
	if e = unix.Mkfifo(fifo, 0600); e != nil {
		t.Fatal(e)
	}
	fifoRunner, fifoErr := immutableexec.Bind(fifo, [32]byte{})
	closeUnexpected(t, fifoRunner)
	if fifoErr == nil {
		t.Fatal("fifo accepted")
	}
}

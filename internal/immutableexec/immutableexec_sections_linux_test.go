//go:build linux

package immutableexec

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A tiny section table advertises a huge compressed payload, but contains no
// compressed bytes. Binding must reject the malformed section table without
// attempting decompression or executing a synthetic payload.
func malformedHugeCompressedSection() []byte {
	b := fakeELF([]byte{0x90}, nil)
	const tableOff, dataOff = 128, 256
	b = append(b, make([]byte, dataOff+24-len(b))...)
	binary.LittleEndian.PutUint64(b[40:], tableOff)
	binary.LittleEndian.PutUint16(b[58:], 64)
	binary.LittleEndian.PutUint16(b[60:], 2)
	binary.LittleEndian.PutUint16(b[62:], 1)
	sh := b[tableOff+64 : tableOff+128]
	binary.LittleEndian.PutUint32(sh[4:], 3) // SHT_STRTAB
	binary.LittleEndian.PutUint64(sh[8:], 0x800)
	binary.LittleEndian.PutUint64(sh[24:], dataOff)
	binary.LittleEndian.PutUint64(sh[32:], 24+1)
	binary.LittleEndian.PutUint64(sh[40:], 1)
	binary.LittleEndian.PutUint32(b[dataOff:], 1)
	binary.LittleEndian.PutUint64(b[dataOff+8:], 1<<40)
	binary.LittleEndian.PutUint64(b[dataOff+16:], 1)
	return b
}

func TestMalformedHugeCompressedSectionRejected(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("amd64 only")
	}
	b := malformedHugeCompressedSection()
	if len(b) > 300 {
		t.Fatalf("fixture unexpectedly large: %d bytes", len(b))
	}
	p := filepath.Join(t.TempDir(), "compressed-sections")
	writeExec(t, p, b)
	runner, err := Bind(p, sha256.Sum256(b))
	closeUnexpected(t, runner)
	if err == nil || !strings.Contains(err.Error(), "sections") {
		t.Fatalf("Bind error = %v, want section rejection", err)
	}
}

func TestMalformedProgramTableRejected(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("amd64 only")
	}
	cases := []struct {
		name   string
		mutate func([]byte)
		want   string
	}{
		{"program table offset overflow", func(b []byte) {
			binary.LittleEndian.PutUint64(b[32:], ^uint64(0)-15)
			binary.LittleEndian.PutUint16(b[56:], 2)
		}, "program headers"},
		{"load segment file overflow", func(b []byte) { binary.LittleEndian.PutUint64(b[96:], ^uint64(0)) }, "load segment"},
		{"dynamic segment", func(b []byte) { binary.LittleEndian.PutUint32(b[64:], 2) }, "dynamic executable rejected"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := fakeELF([]byte{0x90}, nil)
			tc.mutate(b)
			p := filepath.Join(t.TempDir(), "malformed")
			writeExec(t, p, b)
			runner, err := Bind(p, sha256.Sum256(b))
			closeUnexpected(t, runner)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Bind error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestBindRefusesNonAMD64(t *testing.T) {
	if runtime.GOARCH == "amd64" {
		t.Skip("requires non-amd64 Linux")
	}
	p := filepath.Join(t.TempDir(), "program")
	b := fakeELF([]byte{0x90}, nil)
	writeExec(t, p, b)
	runner, err := Bind(p, sha256.Sum256(b))
	closeUnexpected(t, runner)
	if err == nil || !strings.Contains(err.Error(), "unsupported architecture") {
		t.Fatalf("non-amd64 Bind error = %v", err)
	}
}

func TestBindHooksSubstitutionAndRejectedDescriptorClosure(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("synthetic ELF is amd64")
	}
	original := fakeELF([]byte{0xb8, 60, 0, 0, 0, 0xbf, 0, 0, 0, 0, 0x0f, 0x05}, nil)
	replacement := fakeELF([]byte{0xb8, 60, 0, 0, 0, 0xbf, 1, 0, 0, 0, 0x0f, 0x05}, nil)

	runHook := func(t *testing.T, p string, hook func() error, modify func()) struct {
		r   *Runner
		err error
	} {
		t.Helper()
		entered, resume, cancel, done := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
		result := make(chan struct {
			r   *Runner
			err error
		})
		var releaseOnce sync.Once
		release := func() { releaseOnce.Do(func() { close(resume) }) }
		defer func() {
			release()
			close(cancel)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("bind goroutine did not finish")
			}
		}()
		go func() {
			defer close(done)
			r, err := bind(p, sha256.Sum256(original), &bindHooks{afterOpen: func(*os.File) error { close(entered); <-resume; return hook() }})
			select {
			case result <- struct {
				r   *Runner
				err error
			}{r, err}:
			case <-cancel:
				if r != nil {
					r.Close()
				}
			}
		}()
		select {
		case <-entered:
		case got := <-result:
			if got.r != nil {
				got.r.Close()
			}
			t.Fatalf("bind returned before hook entry: %v", got.err)
		case <-time.After(5 * time.Second):
			release()
			t.Fatal("hook entry timeout")
		}
		if modify != nil {
			modify()
		}
		release()
		select {
		case got := <-result:
			return got
		case <-time.After(5 * time.Second):
			t.Fatal("bind result timeout")
			return struct {
				r   *Runner
				err error
			}{}
		}
	}

	t.Run("rename substitution", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "program")
		writeExec(t, p, original)
		bound := runHook(t, p, func() error { return nil }, func() {
			if err := os.Rename(p, p+".old"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, replacement, 0700); err != nil {
				t.Fatal(err)
			}
		})
		if bound.r != nil {
			defer bound.r.Close()
		}
		if bound.err != nil {
			t.Fatal(bound.err)
		}
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Second))
		defer cancel()
		if err := bound.r.Run(ctx, []string{}, ""); err != nil {
			t.Fatalf("snapshot substitution: %v", err)
		}
	})

	t.Run("in-place substitution", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "program")
		writeExec(t, p, original)
		bound := runHook(t, p, func() error {
			mutator, err := os.OpenFile(p, os.O_WRONLY, 0)
			if err != nil {
				return err
			}
			defer mutator.Close()
			_, err = mutator.WriteAt([]byte{original[len(original)-1] ^ 1}, int64(len(original)-1))
			return err
		}, nil)
		if bound.r != nil {
			bound.r.Close()
			t.Fatal("rejected bind returned runner")
		}
		if bound.err == nil || !strings.Contains(bound.err.Error(), "digest") {
			t.Fatalf("in-place substitution: %v", bound.err)
		}
	})

	p := filepath.Join(t.TempDir(), "descriptor-check")
	writeExec(t, p, original)
	var fd uintptr
	captured := false
	if r, err := bind(p, [32]byte{}, &bindHooks{afterMemfd: func(mem *os.File) error { fd = mem.Fd(); captured = true; return nil }}); r != nil {
		closeUnexpected(t, r)
		t.Fatal("wrong digest returned runner")
	} else if err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("wrong digest: %v", err)
	}
	if !captured {
		t.Fatal("afterMemfd hook did not capture descriptor")
	}
	if _, err := unix.FcntlInt(fd, unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("rejected memfd descriptor check = %v, want EBADF", err)
	}
}

func TestCancelWaitsAndReapsDirectChild(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("synthetic ELF requires amd64")
	}
	data := fakeELF([]byte{0xb8, 34, 0, 0, 0, 0x0f, 0x05, 0xeb, 0xf7}, nil)
	path := filepath.Join(t.TempDir(), "pause-child")
	writeExec(t, path, data)
	r, err := Bind(path, sha256.Sum256(data))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(10*time.Second))
	pidCh, done := make(chan int, 1), make(chan error, 1)
	go func() {
		runErr := r.run(ctx, []string{}, "", func(pid int) { pidCh <- pid })
		closeErr := r.Close()
		if runErr == nil {
			runErr = closeErr
		}
		done <- runErr
	}()
	completed := false
	defer func() {
		cancel()
		if !completed {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
			}
		}
	}()
	var pid int
	select {
	case pid = <-pidCh:
	case earlyErr := <-done:
		completed = true
		t.Fatalf("Run ended before start: %v", earlyErr)
	case <-time.After(3 * time.Second):
		t.Fatal("child did not start")
	}
	if _, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid))); err != nil {
		t.Fatal("child absent after start:", err)
	}
	cancel()
	select {
	case runErr := <-done:
		completed = true
		if runErr == nil || ctx.Err() != context.Canceled {
			t.Fatalf("Run=%v context=%v", runErr, ctx.Err())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not wait after cancellation")
	}
	var status syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &status, syscall.WNOHANG, nil); !errors.Is(err, syscall.ECHILD) {
		t.Fatalf("Wait4 after Run = %v, want ECHILD", err)
	}
}

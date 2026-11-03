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
func TestObserveOverflowReapsExactPID(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("synthetic ELF is amd64")
	}
	request := []byte(`{"protocol":1,"request_id":"AAAAAAAAAAAAAAAAAAAAAA","action":"observe","target":"node","kind":"service","schema_id":"schema","resource_id":"service.one","desired":null,"expected_revision":null,"plan_digest":null,"allowed_effects":[],"deadline_unix_ms":0,"max_response_bytes":1024,"operation_id":null}`)
	framed := make([]byte, 4+len(request))
	binary.BigEndian.PutUint32(framed, uint32(len(request)))
	copy(framed[4:], request)
	if len(framed) > 4096 {
		t.Fatal("request frame exceeds child stack buffer")
	}
	code := make([]byte, 0, 180)
	labels, branches := map[string]int{}, map[string][]int{}
	mark := func(s string) { labels[s] = len(code) }
	branch := func(op []byte, target string) {
		code = append(code, op...)
		at := len(code)
		code = append(code, 0, 0, 0, 0)
		branches[target] = append(branches[target], at)
	}
	code = append(code, 0x48, 0x8d, 0xb4, 0x24, 0, 0xf0, 0xff, 0xff) // lea rsi,[rsp-4096]
	code = append(code, 0xba, byte(len(framed)), byte(len(framed)>>8), 0, 0)
	mark("read")
	code = append(code, 0x31, 0xff, 0xb8, 0, 0, 0, 0, 0x0f, 0x05, 0x85, 0xc0) // read; fail on <=0
	branch([]byte{0x0f, 0x8e}, "fail")
	code = append(code, 0x48, 0x01, 0xc6, 0x29, 0xc2)
	branch([]byte{0x0f, 0x85}, "read")
	code = append(code, 0x81, 0xbc, 0x24, 0, 0xf0, 0xff, 0xff)
	header := len(code)
	code = append(code, 0, 0, 0, 0)
	branch([]byte{0x0f, 0x85}, "fail")
	code = append(code, 0x48, 0x8d, 0x35, 0, 0, 0, 0)
	rip := len(code) - 4
	code = append(code, 0xba, 5, 0, 1, 0)
	mark("write")
	code = append(code, 0xbf, 1, 0, 0, 0, 0xb8, 1, 0, 0, 0, 0x0f, 0x05, 0x85, 0xc0)
	branch([]byte{0x0f, 0x8e}, "fail")
	code = append(code, 0x48, 0x01, 0xc6, 0x29, 0xc2, 0x85, 0xd2)
	branch([]byte{0x0f, 0x85}, "write")
	mark("pause")
	code = append(code, 0xb8, 34, 0, 0, 0, 0x0f, 0x05)
	branch([]byte{0xe9}, "pause")
	mark("fail")
	code = append(code, 0xbf, 1, 0, 0, 0, 0xb8, 60, 0, 0, 0, 0x0f, 0x05)
	for label, positions := range branches {
		for _, at := range positions {
			binary.LittleEndian.PutUint32(code[at:], uint32(int32(labels[label]-(at+4))))
		}
	}
	binary.LittleEndian.PutUint32(code[header:], binary.LittleEndian.Uint32(framed[:4]))
	payload := make([]byte, 65541)
	for i := range payload {
		payload[i] = 'x'
	}
	binary.LittleEndian.PutUint32(code[rip:], uint32(len(code)-rip-4))
	data := fakeELF(code, payload)
	path := filepath.Join(t.TempDir(), "overflow-child")
	writeExec(t, path, data)
	r, err := Bind(path, sha256.Sum256(data))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(10*time.Second))
	pidCh, done := make(chan int, 1), make(chan error, 1)
	var result error
	doneReceived := false
	defer func() {
		cancel()
		if !doneReceived {
			select {
			case result = <-done:
				doneReceived = true
			case <-time.After(3 * time.Second):
				t.Error("observe join timed out")
			}
		}
		closed := make(chan error, 1)
		go func() { closed <- r.Close() }()
		select {
		case err := <-closed:
			if err != nil {
				t.Errorf("close runner: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("runner close timed out")
		}
	}()
	go func() { _, err := r.observe(ctx, []string{}, "", request, func(pid int) { pidCh <- pid }); done <- err }()
	var pid int
	select {
	case pid = <-pidCh:
	case <-time.After(5 * time.Second):
		t.Fatal("child did not start")
	}
	select {
	case result = <-done:
		doneReceived = true
	case <-time.After(5 * time.Second):
		t.Fatal("observe did not finish")
	}
	if result == nil || result.Error() != "observe output limit exceeded" {
		t.Errorf("observe error = %v, want observe output limit exceeded", result)
	}
	if ctx.Err() != nil {
		t.Errorf("context unexpectedly ended: %v", ctx.Err())
	}
	var status unix.WaitStatus
	if got, waitErr := unix.Wait4(pid, &status, unix.WNOHANG, nil); got != -1 || !errors.Is(waitErr, unix.ECHILD) {
		t.Errorf("Wait4(%d) = (%d, %v), want ECHILD", pid, got, waitErr)
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

//go:build linux

package observepositive

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/driverprotocol"
	"github.com/PHPCraftdream/ssjack/internal/immutableexec"
)

// syntheticELF mirrors the small ET_EXEC fixture in immutableexec's Linux tests.
func syntheticELF(code, extra []byte) []byte {
	b := make([]byte, 120+len(code)+len(extra))
	copy(b, "\x7fELF")
	b[4], b[5], b[6] = 2, 1, 1
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

func TestObservePositiveControl(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("synthetic ELF is amd64")
	}
	request := []byte(`{"protocol":1,"request_id":"AAAAAAAAAAAAAAAAAAAAAA","action":"observe","target":"node","kind":"service","schema_id":"schema","resource_id":"service.one","desired":null,"expected_revision":null,"plan_digest":null,"allowed_effects":[],"deadline_unix_ms":0,"max_response_bytes":1024,"operation_id":null}`)
	if _, err := driverprotocol.ValidateStructuralRequest(request); err != nil {
		t.Fatal(err)
	}
	response := []byte(`{"protocol":1,"request_id":"AAAAAAAAAAAAAAAAAAAAAA","outcome":"ok","error_code":null,"data":{"state":"present","revision":"r1","projection":{}}}`)
	framedResponse := make([]byte, 4+len(response))
	binary.BigEndian.PutUint32(framedResponse, uint32(len(response)))
	copy(framedResponse[4:], response)
	// On the wire the header is big-endian. Read its first four bytes as a
	// little-endian amd64 dword to compare the exact byte pattern.
	framedRequest := make([]byte, 4+len(request))
	binary.BigEndian.PutUint32(framedRequest, uint32(len(request)))
	copy(framedRequest[4:], request)
	expectedHeader := binary.LittleEndian.Uint32(framedRequest[:4])

	if len(framedRequest) > 4096 {
		t.Fatal("framed request exceeds child stack buffer")
	}
	code := make([]byte, 0, 160)
	ripPatches := map[int]string{}
	labels := map[string]int{}
	branches := map[string][]int{}
	mark := func(name string) { labels[name] = len(code) }
	branch := func(op []byte, label string) {
		code = append(code, op...)
		at := len(code)
		code = append(code, 0, 0, 0, 0)
		branches[label] = append(branches[label], at)
	}
	// Read the complete bounded frame into writable stack memory. The loop
	// handles short reads; exact-length completion lets the parent finish its
	// stdin copy before this child exits, avoiding a broken pipe.
	code = append(code, 0x48, 0x8d, 0xb4, 0x24, 0x00, 0xf0, 0xff, 0xff) // lea rsi,[rsp-4096]
	code = append(code, 0xba, byte(len(framedRequest)), byte(len(framedRequest)>>8), 0, 0)
	mark("read")
	code = append(code, 0x31, 0xff, 0xb8, 0, 0, 0, 0, 0x0f, 0x05) // read(0,rsi,edx)
	code = append(code, 0x85, 0xc0)                               // test eax,eax
	branch([]byte{0x0f, 0x8e}, "fail")                            // <= 0
	code = append(code, 0x48, 0x01, 0xc6, 0x29, 0xc2)             // advance; remaining -= eax
	branch([]byte{0x0f, 0x85}, "read")                            // repeat short read
	code = append(code, 0x81, 0xbc, 0x24, 0x00, 0xf0, 0xff, 0xff) // cmp dword [rsp-4096], header
	headerImmediate := len(code)
	code = append(code, 0, 0, 0, 0)
	branch([]byte{0x0f, 0x85}, "fail")
	code = append(code, 0x48, 0x8d, 0x35, 0, 0, 0, 0) // lea rsi,[rip+response]
	responseDisp := len(code) - 4
	ripPatches[responseDisp] = "response"
	code = append(code, 0xbf, 1, 0, 0, 0, 0xba, 0, 0, 0, 0) // write(1, response, length)
	responseLen := len(code) - 4
	code = append(code, 0xb8, 1, 0, 0, 0, 0x0f, 0x05) // write syscall
	code = append(code, 0x85, 0xc0)                   // test eax,eax; syscall does not set flags
	branch([]byte{0x0f, 0x8e}, "fail")
	code = append(code, 0x31, 0xff, 0xb8, 60, 0, 0, 0, 0x0f, 0x05) // exit(0)
	mark("fail")
	code = append(code, 0xbf, 1, 0, 0, 0, 0xb8, 60, 0, 0, 0, 0x0f, 0x05) // exit(1)
	for label, positions := range branches {
		for _, at := range positions {
			delta := int32(labels[label] - (at + 4))
			binary.LittleEndian.PutUint32(code[at:], uint32(delta))
		}
	}
	binary.LittleEndian.PutUint32(code[headerImmediate:], expectedHeader)
	binary.LittleEndian.PutUint32(code[responseLen:], uint32(len(framedResponse)))
	for at, label := range ripPatches {
		if label != "response" {
			t.Fatalf("unknown RIP-relative target %q", label)
		}
		binary.LittleEndian.PutUint32(code[at:], uint32(len(code)-at-4))
	}
	data := syntheticELF(code, framedResponse)
	path := filepath.Join(t.TempDir(), "observe-child")
	if err := os.WriteFile(path, data, 0700); err != nil {
		t.Fatal(err)
	}
	runner, err := immutableexec.Bind(path, sha256.Sum256(data))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".bound"); err != nil {
		runner.Close()
		t.Fatal(err)
	}
	replacement := syntheticELF([]byte{0xb8, 60, 0, 0, 0, 0xbf, 1, 0, 0, 0, 0x0f, 0x05}, nil)
	if err := os.WriteFile(path, replacement, 0700); err != nil {
		runner.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(5*time.Second))
	defer cancel()
	_, observeErr := runner.Observe(ctx, []string{}, "", request)
	closeErr := runner.Close()
	if observeErr != nil || closeErr != nil {
		t.Fatalf("Observe error = %v, Close error = %v", observeErr, closeErr)
	}
}

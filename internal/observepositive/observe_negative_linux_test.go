//go:build linux

package observepositive

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/driverprotocol"
	"github.com/PHPCraftdream/ssjack/internal/immutableexec"
)

var negativeRequest = []byte(`{"protocol":1,"request_id":"AAAAAAAAAAAAAAAAAAAAAA","action":"observe","target":"node","kind":"service","schema_id":"schema","resource_id":"service.one","desired":null,"expected_revision":null,"plan_digest":null,"allowed_effects":[],"deadline_unix_ms":0,"max_response_bytes":1024,"operation_id":null}`)
var negativeResponse = []byte(`{"protocol":1,"request_id":"AAAAAAAAAAAAAAAAAAAAAA","outcome":"ok","error_code":null,"data":{"state":"present","revision":"r1","projection":{}}}`)

func responseFrame(response []byte) []byte {
	frame := make([]byte, 4+len(response))
	binary.BigEndian.PutUint32(frame, uint32(len(response)))
	copy(frame[4:], response)
	return frame
}

// responseELF reads the complete request frame before emitting output, so the
// parent can finish stdin without EPIPE. It has no loader or shared libraries.
func responseELF(payload []byte, exitStatus byte) []byte {
	return responseELFMode(payload, exitStatus, false)
}

func overflowResponseELF(payload []byte) []byte {
	return responseELFMode(payload, 0, true)
}

func responseELFMode(payload []byte, exitStatus byte, pauseAfterWrite bool) []byte {
	requestFrame := responseFrame(negativeRequest)
	if len(requestFrame) > 4096 {
		panic("request exceeds fixture stack buffer")
	}
	code := make([]byte, 0, 160)
	labels, branches := map[string]int{}, map[string][]int{}
	mark := func(s string) { labels[s] = len(code) }
	branch := func(op []byte, target string) {
		code = append(code, op...)
		at := len(code)
		code = append(code, 0, 0, 0, 0)
		branches[target] = append(branches[target], at)
	}
	code = append(code, 0x48, 0x8d, 0xb4, 0x24, 0, 0xf0, 0xff, 0xff) // lea rsi,[rsp-4096]
	code = append(code, 0xba, byte(len(requestFrame)), byte(len(requestFrame)>>8), 0, 0)
	mark("read")
	code = append(code, 0x31, 0xff, 0xb8, 0, 0, 0, 0, 0x0f, 0x05, 0x85, 0xc0)
	branch([]byte{0x0f, 0x8e}, "fail")
	code = append(code, 0x48, 0x01, 0xc6, 0x29, 0xc2)
	branch([]byte{0x0f, 0x85}, "read")
	code = append(code, 0x81, 0xbc, 0x24, 0, 0xf0, 0xff, 0xff)
	header := len(code)
	code = append(code, 0, 0, 0, 0)
	branch([]byte{0x0f, 0x85}, "fail")
	code = append(code, 0x48, 0x8d, 0x35, 0, 0, 0, 0)
	rip := len(code) - 4
	code = append(code, 0xba, 0, 0, 0, 0)
	length := len(code) - 4
	mark("write")
	code = append(code, 0xbf, 1, 0, 0, 0, 0xb8, 1, 0, 0, 0, 0x0f, 0x05) // write(1,rsi,rdx)
	code = append(code, 0x85, 0xc0)
	branch([]byte{0x0f, 0x8e}, "fail")
	code = append(code, 0x48, 0x01, 0xc6, 0x29, 0xc2) // advance pointer; subtract bytes written
	code = append(code, 0x85, 0xd2)
	branch([]byte{0x0f, 0x85}, "write")
	if pauseAfterWrite {
		mark("pause")
		code = append(code, 0xb8, 34, 0, 0, 0, 0x0f, 0x05) // pause()
		branch([]byte{0xe9}, "pause")                      // wait again if pause is interrupted
	}
	code = append(code, 0xbf, exitStatus, 0, 0, 0, 0xb8, 60, 0, 0, 0, 0x0f, 0x05)
	mark("fail")
	code = append(code, 0xbf, 1, 0, 0, 0, 0xb8, 60, 0, 0, 0, 0x0f, 0x05)
	for target, positions := range branches {
		for _, at := range positions {
			binary.LittleEndian.PutUint32(code[at:], uint32(int32(labels[target]-(at+4))))
		}
	}
	binary.LittleEndian.PutUint32(code[header:], binary.LittleEndian.Uint32(requestFrame[:4]))
	binary.LittleEndian.PutUint32(code[length:], uint32(len(payload)))
	binary.LittleEndian.PutUint32(code[rip:], uint32(len(code)-rip-4))
	return syntheticELF(code, payload)
}

func bindOverflowResponse(t *testing.T, payload []byte) *immutableexec.Runner {
	t.Helper()
	data := overflowResponseELF(payload)
	path := filepath.Join(t.TempDir(), "observe-overflow-child")
	if err := os.WriteFile(path, data, 0700); err != nil {
		t.Fatal(err)
	}
	r, err := immutableexec.Bind(path, sha256.Sum256(data))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return r
}

func bindResponse(t *testing.T, payload []byte, exitStatus byte) *immutableexec.Runner {
	t.Helper()
	if runtime.GOARCH != "amd64" {
		t.Skip("synthetic ELF is amd64")
	}
	data := responseELF(payload, exitStatus)
	path := filepath.Join(t.TempDir(), "observe-child")
	if err := os.WriteFile(path, data, 0700); err != nil {
		t.Fatal(err)
	}
	r, err := immutableexec.Bind(path, sha256.Sum256(data))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return r
}

func negativeContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestObserveNegativeResponses(t *testing.T) {
	good := responseFrame(negativeResponse)
	malformed := responseFrame([]byte("{"))
	noise := append(append([]byte(nil), good...), 'x')
	wrongID := append([]byte(nil), negativeResponse...)
	copy(wrongID[len(`{"protocol":1,"request_id":"`):], []byte("AAAAAAAAAAAAAAAAAAAAAQ"))
	cases := []struct {
		name    string
		payload []byte
	}{
		{"malformed-json", malformed}, {"extra-noise", noise}, {"wrong-correlation", responseFrame(wrongID)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := bindResponse(t, tc.payload, 0)
			_, err := r.Observe(negativeContext(t), []string{}, "", negativeRequest)
			if err == nil || err.Error() != "invalid observe response" {
				t.Fatalf("cause: got %v, want invalid observe response", err)
			}
		})
	}
}

func TestObserveOutputOverflow(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("synthetic ELF is amd64")
	}
	data := make([]byte, 65541)
	for i := range data {
		data[i] = 'x'
	}
	r := bindOverflowResponse(t, data)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := r.Observe(ctx, []string{}, "", negativeRequest)
	if err == nil || err.Error() != "observe output limit exceeded" {
		t.Fatalf("Observe error = %v, want observe output limit exceeded", err)
	}
	if ctx.Err() != nil {
		t.Fatalf("deadline expired before overflow was observed: %v", ctx.Err())
	}
}

func TestObserveNonzeroExit(t *testing.T) {
	r := bindResponse(t, responseFrame(negativeResponse), 7)
	_, err := r.Observe(negativeContext(t), []string{}, "", negativeRequest)
	if err == nil || err.Error() != "observe child failed" {
		t.Fatalf("cause: got %v, want observe child failed", err)
	}
}

func TestObservePrelaunchValidation(t *testing.T) {
	badAction := []byte(strings.Replace(strings.Replace(string(negativeRequest), `"observe"`, `"plan"`, 1), `"desired":null`, `"desired":{}`, 1))
	if _, err := driverprotocol.ValidateStructuralRequest(badAction); err != nil {
		t.Fatalf("non-observe fixture must be structurally valid: %v", err)
	}
	cases := []struct {
		name string
		env  []string
		ctx  context.Context
		req  []byte
		want error
	}{
		{"unsafe-env", []string{"SECRET=x"}, negativeContext(t), negativeRequest, immutableexec.ErrInvalidEnvironment},
		{"no-deadline", []string{}, context.Background(), negativeRequest, nil},
		{"non-observe", []string{}, negativeContext(t), badAction, driverprotocol.ErrInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := bindResponse(t, responseFrame(negativeResponse), 0)
			_, err := r.Observe(tc.ctx, tc.env, "", tc.req)
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("cause: got %v, want %v", err, tc.want)
			}
			if tc.name == "no-deadline" && (err == nil || err.Error() != "explicit deadline required") {
				t.Fatalf("cause: got %v", err)
			}
		})
	}
}

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
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/driverprotocol"
	"github.com/PHPCraftdream/ssjack/internal/immutableexec"
)

// markerELF creates a marker file using open, then closes it and exits.
// The absolute pathname is addressed by a RIP-relative pointer into ELF data.
func markerELF(path string) []byte {
	code := []byte{
		0x48, 0x8d, 0x3d, 0, 0, 0, 0, // lea rdi,[rip+path]
		0xbe, 0x41, 0x00, 0x00, 0x00, // mov esi,O_WRONLY|O_CREAT
		0xba, 0x80, 0x01, 0x00, 0x00, // mov edx,0600
		0xb8, 0x02, 0x00, 0x00, 0x00, // open
		0x0f, 0x05,
		0x85, 0xc0, // test eax,eax
		0x78, 0x12, // js exit(1)
		0x89, 0xc7, // mov edi,eax
		0xb8, 0x03, 0x00, 0x00, 0x00, // close
		0x0f, 0x05,
		0x31, 0xff, // exit(0)
		0xb8, 0x3c, 0x00, 0x00, 0x00,
		0x0f, 0x05,
		0xbf, 0x01, 0x00, 0x00, 0x00, // failure exit(1)
		0xb8, 0x3c, 0x00, 0x00, 0x00,
		0x0f, 0x05,
	}
	payload := append(append([]byte(nil), path...), 0)
	binary.LittleEndian.PutUint32(code[3:], uint32(len(code)-7))
	return syntheticELF(code, payload)
}

func bindMarker(t *testing.T, marker string) *immutableexec.Runner {
	t.Helper()
	data := markerELF(marker)
	path := filepath.Join(t.TempDir(), "marker-child")
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

func markerContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestObservePrelaunchValidationMarker(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("synthetic ELF is amd64")
	}
	observeRequest := []byte(`{"protocol":1,"request_id":"AAAAAAAAAAAAAAAAAAAAAA","action":"observe","target":"node","kind":"service","schema_id":"schema","resource_id":"service.one","desired":null,"expected_revision":null,"plan_digest":null,"allowed_effects":[],"deadline_unix_ms":0,"max_response_bytes":1024,"operation_id":null}`)
	planRequest := []byte(`{"protocol":1,"request_id":"AAAAAAAAAAAAAAAAAAAAAA","action":"plan","target":"node","kind":"service","schema_id":"schema","resource_id":"service.one","desired":{},"expected_revision":null,"plan_digest":null,"allowed_effects":[],"deadline_unix_ms":0,"max_response_bytes":1024,"operation_id":null}`)
	for name, request := range map[string][]byte{"observe": observeRequest, "plan": planRequest} {
		if _, err := driverprotocol.ValidateStructuralRequest(request); err != nil {
			t.Fatalf("%s request is not structurally valid: %v", name, err)
		}
	}
	const safeEnv = "LANG=C"
	positiveMarker := filepath.Join(t.TempDir(), "positive-marker")
	positive := bindMarker(t, positiveMarker)
	if err := positive.Run(markerContext(t), []string{safeEnv}, ""); err != nil {
		t.Fatalf("positive control Run: %v", err)
	}
	if _, err := os.Stat(positiveMarker); err != nil {
		t.Fatalf("positive control marker not created: %v", err)
	}

	cases := []struct {
		name    string
		env     []string
		ctx     context.Context
		want    error
		request []byte
	}{
		{"unsafe-env", []string{"SECRET=x"}, markerContext(t), immutableexec.ErrInvalidEnvironment, observeRequest},
		{"no-deadline", []string{safeEnv}, context.Background(), errors.New("explicit deadline required"), observeRequest},
		{"non-observe", []string{safeEnv}, markerContext(t), driverprotocol.ErrInvalid, planRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "invalid-marker")
			r := bindMarker(t, marker)
			_, err := r.Observe(tc.ctx, tc.env, "", tc.request)
			if tc.name == "no-deadline" {
				if err == nil || err.Error() != tc.want.Error() {
					t.Fatalf("Observe error = %v, want %q", err, tc.want.Error())
				}
			} else if !errors.Is(err, tc.want) {
				t.Fatalf("Observe error = %v, want %v", err, tc.want)
			}
			if _, statErr := os.Stat(marker); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("invalid input marker stat error = %v, want absent", statErr)
			}
		})
	}
}

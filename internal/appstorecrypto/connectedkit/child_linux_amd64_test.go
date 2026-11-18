//go:build linux && amd64

package connectedkit

import (
	"strings"
	"testing"
)

func TestBoundedSyntheticChildDiagnostics(t *testing.T) {
	t.Run("normal", func(t *testing.T) {
		log := &BoundedChildLog{}
		if n, err := log.Write([]byte("small diagnostic")); err != nil || n != len("small diagnostic") {
			t.Fatalf("Write() = %d, %v; want %d, nil", n, err, len("small diagnostic"))
		}
		if got := log.String(); got != "small diagnostic" {
			t.Fatalf("String() = %q, want %q", got, "small diagnostic")
		}
	})

	t.Run("truncated", func(t *testing.T) {
		log := &BoundedChildLog{}
		payload := strings.Repeat("x", maxChildLog+20)
		if n, err := log.Write([]byte(payload)); err != nil || n != len(payload) {
			t.Fatalf("Write() = %d, %v; want %d, nil", n, err, len(payload))
		}
		if n, err := log.Write([]byte("tail")); err != nil || n != len("tail") {
			t.Fatalf("Write() = %d, %v; want %d, nil", n, err, len("tail"))
		}
		log.mu.Lock()
		stored := len(log.data)
		log.mu.Unlock()
		if stored != maxChildLog {
			t.Fatalf("stored data length = %d, want %d", stored, maxChildLog)
		}
		got := log.String()
		if !strings.Contains(got, "[child diagnostics truncated at 16 KiB]") {
			t.Fatalf("String() missing truncation marker")
		}
		if strings.Contains(got, "tail") {
			t.Fatalf("String() contains data written after limit")
		}
	})
}

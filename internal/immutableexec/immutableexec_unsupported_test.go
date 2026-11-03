//go:build !linux

package immutableexec

import "testing"

func TestUnsupported(t *testing.T) {
	if _, err := Bind("/x", [32]byte{}); err != ErrUnsupported {
		t.Fatalf("got %v", err)
	}
}

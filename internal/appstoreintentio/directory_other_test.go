//go:build !linux

package appstoreintentio

import (
	"errors"
	"testing"
)

func TestUnsupportedPlatformDoesNotSelectWeakerIO(t *testing.T) {
	if d, err := New(nil, [16]byte{1}); d != nil || !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported platform accepted: %v", err)
	}
}

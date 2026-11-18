//go:build linux && amd64

package cli

import (
	"testing"
)

func TestNamedStartupCannotSilentlyScopeStreamRegistration(t *testing.T) {
	for _, command := range []string{"register-stream", "register-reverse-stream", "revoke-stream"} {
		if namedCommandAllowed([]string{"text-adapter", command}) {
			t.Fatal("named SSH selector was silently ignored by root registration")
		}
	}
}

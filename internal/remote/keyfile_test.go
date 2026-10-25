package remote

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
)

func TestUnlockRejectsMalformedContainer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.ssjack.ktav")
	if err := os.WriteFile(path, []byte(keyfile.Magic+"version: 99\n"), 0600); err != nil {
		t.Fatal(err)
	}
	config := Config{Keys: map[string]string{"key": path}}
	if _, err := Unlock(config, []byte("secret")); err == nil {
		t.Fatal("malformed encrypted container was accepted")
	}
}

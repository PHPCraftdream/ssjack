package vault

import (
	"bytes"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
)

func TestPasswordIdentityNormalizesVerifiedHostKeys(t *testing.T) {
	target := testTarget(t)
	defer clear(target.PrivateKey)
	if !strings.HasSuffix(target.HostKeys[0], "\n") {
		t.Fatal("fixture does not exercise a valid newline-terminated OpenSSH key")
	}
	first, err := passwordIdentityMetadata("selected", target)
	if err != nil {
		t.Fatal("valid OpenSSH host key could not form password identity metadata")
	}
	if _, err := canonicaljson.Canonicalize(first); err != nil {
		t.Fatal("password identity metadata is not canonicalizable")
	}
	target.HostKeys = []string{strings.TrimSpace(target.HostKeys[0])}
	second, err := passwordIdentityMetadata("selected", target)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("OpenSSH text newline changed the verified host identity")
	}
	target.User = "another-user"
	changed, err := passwordIdentityMetadata("selected", target)
	if err != nil || bytes.Equal(first, changed) {
		t.Fatal("selected SSH username was not bound")
	}
	target.HostKeys = []string{"invalid"}
	if _, err := passwordIdentityMetadata("selected", target); err == nil {
		t.Fatal("invalid host key produced password identity metadata")
	}
}

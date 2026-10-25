package remote

import (
	"bytes"
	"context"
	"encoding/pem"
	"io"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func TestCredentialRunnerRestrictsSelectedName(t *testing.T) {
	private, signer := testSigner(t)
	defer clear(private)
	address, host := testSSH(t, signer.PublicKey())
	block, err := ssh.MarshalPrivateKey(private, "test")
	if err != nil {
		t.Fatal(err)
	}
	v := vault.New()
	v.Targets["selected"] = vault.Target{Address: address, User: "test", PrivateKey: pem.EncodeToMemory(block), HostKeys: []string{string(ssh.MarshalAuthorizedKey(host))}}
	config, err := v.Targets["selected"].ClientConfig()
	v.Close()
	if err != nil {
		t.Fatal(err)
	}
	runner, err := NewCredentialRunner("selected", address, config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner(context.Background(), "other", "not allowed", io.Discard, io.Discard); err == nil {
		t.Fatal("runner accepted another credential name")
	}
	var stdout, stderr bytes.Buffer
	code, err := runner(context.Background(), "selected", "hello", &stdout, &stderr)
	if err != nil || code != 9 || stdout.String() != "stdout:hello" || stderr.String() != "stderr" {
		t.Fatalf("selected credentials failed: %d %v %q %q", code, err, stdout.String(), stderr.String())
	}
	config.HostKeyCallback = nil
	if _, err := NewCredentialRunner("selected", address, config); err == nil {
		t.Fatal("unverified host keys were accepted")
	}
}

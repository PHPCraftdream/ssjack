package remote

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/sshauth"
)

func TestCredentialStreamRunnerBinaryInput(t *testing.T) {
	_, signer := testSigner(t)
	address, host := testSSH(t, signer.PublicKey())
	config := &ssh.ClientConfig{User: "test", Auth: []ssh.AuthMethod{sshauth.PublicKey(signer)}, HostKeyCallback: ssh.FixedHostKey(host)}
	runner, err := NewCredentialStreamRunner("selected", address, config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	payload := bytes.Repeat([]byte{0, 255, 128, '\n'}, 256000)
	var stdout, stderr bytes.Buffer
	code, err := runner(ctx, "selected", "copy", bytes.NewReader(payload), &stdout, &stderr)
	if err != nil || code != 7 || !bytes.Equal(stdout.Bytes(), payload) || stderr.String() != "stderr" {
		t.Fatalf("stream failed: code=%d err=%v stdout=%d stderr=%q", code, err, stdout.Len(), stderr.String())
	}
	if _, err := runner(ctx, "other", "copy", bytes.NewReader(payload), io.Discard, io.Discard); err == nil {
		t.Fatal("stream runner accepted another profile")
	}
	wrong := *config
	_, otherHost := testSigner(t)
	wrong.HostKeyCallback = ssh.FixedHostKey(otherHost.PublicKey())
	untrusted, err := NewCredentialStreamRunner("selected", address, &wrong)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := untrusted(ctx, "selected", "copy", bytes.NewReader(payload), io.Discard, io.Discard); err == nil {
		t.Fatal("stream runner bypassed server trust")
	}
}

package remote

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ktav-lang/golang/pure"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func testSigner(t *testing.T) (ed25519.PrivateKey, ssh.Signer) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return key, signer
}

func testSSH(t *testing.T, allowed ssh.PublicKey) (string, ssh.PublicKey) {
	t.Helper()
	_, host := testSigner(t)
	config := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if !bytes.Equal(key.Marshal(), allowed.Marshal()) {
			return nil, io.EOF
		}
		return nil, nil
	}}
	config.AddHostKey(host)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				server, channels, requests, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				defer server.Close()
				closed := make(chan struct{})
				go func() { server.Wait(); close(closed) }()
				go ssh.DiscardRequests(requests)
				for next := range channels {
					if next.ChannelType() != "session" {
						next.Reject(ssh.UnknownChannelType, "")
						continue
					}
					channel, requests, err := next.Accept()
					if err != nil {
						return
					}
					go func() {
						defer channel.Close()
						for req := range requests {
							if req.Type != "exec" {
								req.Reply(false, nil)
								continue
							}
							var command struct{ Command string }
							if ssh.Unmarshal(req.Payload, &command) != nil {
								req.Reply(false, nil)
								return
							}
							req.Reply(true, nil)
							if command.Command == "wait" {
								<-closed
								return
							}
							if command.Command == "copy" {
								io.Copy(channel, channel)
								channel.Stderr().Write([]byte("stderr"))
								channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{7}))
								return
							}
							channel.Write([]byte("stdout:" + command.Command))
							channel.Stderr().Write([]byte("stderr"))
							channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{9}))
							return
						}
					}()
				}
			}()
		}
	}()
	return listener.Addr().String(), host.PublicKey()
}

func TestSSHChecksHostAndCapturesExit(t *testing.T) {
	_, signer := testSigner(t)
	address, host := testSSH(t, signer.PublicKey())
	known := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(known, []byte(knownhosts.Line([]string{address}, host)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	config := Config{Targets: map[string]Target{"test": {Address: address, User: "test", Key: "key", KnownHosts: known}}}
	runner, err := NewSSHRunner(config, map[string]ssh.Signer{"key": signer})
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	exit, err := runner(context.Background(), "test", "hello", &stdout, &stderr)
	if err != nil || exit != 9 || stdout.String() != "stdout:hello" || stderr.String() != "stderr" {
		t.Fatalf("SSH result: %d %v %q %q", exit, err, stdout.String(), stderr.String())
	}
	if _, err := runner(context.Background(), "other", "hello", io.Discard, io.Discard); err == nil {
		t.Fatal("unconfigured target was allowed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := runner(ctx, "test", "wait", io.Discard, io.Discard); err == nil {
		t.Fatal("SSH was not interrupted on cancellation")
	}
	_, wrongHost := testSigner(t)
	if err := os.WriteFile(known, []byte(knownhosts.Line([]string{address}, wrongHost.PublicKey())+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	runner, err = NewSSHRunner(config, map[string]ssh.Signer{"key": signer})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner(context.Background(), "test", "hello", io.Discard, io.Discard); err == nil {
		t.Fatal("accepted a changed host key")
	}
}

func TestUnlockRejectsPlaintextAndWrongPassword(t *testing.T) {
	key, _ := testSigner(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	block, err := ssh.MarshalPrivateKeyWithPassphrase(key, "test", []byte("test-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}
	config := Config{Keys: map[string]string{"key": path}}
	if _, err := Unlock(config, []byte("wrong")); err == nil {
		t.Fatal("incorrect passphrase was accepted")
	}
	if _, err := Unlock(config, []byte("test-passphrase")); err != nil {
		t.Fatal(err)
	}
	block, err = ssh.MarshalPrivateKey(key, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Unlock(config, []byte("test-passphrase")); err == nil {
		t.Fatal("unencrypted key was accepted")
	}
}

func TestConfigRelativePathsAndValidation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.ktav")
	config := Config{Keys: map[string]string{"key": "key"}, Targets: map[string]Target{"test": {Address: "localhost:22", User: "test", Key: "key", KnownHosts: "known_hosts"}}}
	data, err := pure.EmitCanonical(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadConfig(path)
	if err != nil || got.Keys["key"] != filepath.Join(dir, "key") || got.Targets["test"].KnownHosts != filepath.Join(dir, "known_hosts") {
		t.Fatalf("incorrect paths: %+v %v", got, err)
	}
	if err := os.WriteFile(path, []byte(`unknown: 1
`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("unknown fields were accepted")
	}
}

package remote

import (
	"bytes"
	"context"
	"encoding/pem"
	"io"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/sshauth"
	"github.com/PHPCraftdream/ssjack/internal/sshproxy"
	"github.com/PHPCraftdream/ssjack/internal/vault"
	"github.com/PHPCraftdream/ssjack/tests/fixtures/proxyserver"
)

func selectedProxy(t *testing.T, kind, target, upstream string, auth bool) (*sshproxy.Config, *proxyserver.Server) {
	t.Helper()
	options := proxyserver.Options{Protocol: kind, Target: target, Upstream: upstream}
	if auth {
		options.Username, options.Password = "operator", []byte("synthetic proxy password")
	}
	server, err := proxyserver.Start(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(server.Close)
	return &sshproxy.Config{Type: kind, Address: server.Address(), Username: options.Username, Password: options.Password}, server
}

func routedMethod(t *testing.T, method ssh.AuthMethod, route *sshproxy.Config) ssh.AuthMethod {
	t.Helper()
	selected, err := sshauth.WithProxy(method, route)
	if err != nil {
		t.Fatal(err)
	}
	return selected
}

func TestProxyStreamRunnerAndVaultClose(t *testing.T) {
	for _, kind := range []string{sshproxy.SOCKS5, sshproxy.HTTP} {
		for _, auth := range []bool{false, true} {
			t.Run(kind+map[bool]string{false: "anonymous", true: "authenticated"}[auth], func(t *testing.T) {
				private, signer := testSigner(t)
				upstream, host := testSSH(t, signer.PublicKey())
				const target = "ssh.target.invalid:22"
				route, server := selectedProxy(t, kind, target, upstream, auth)
				block, err := ssh.MarshalPrivateKey(private, "synthetic proxy client")
				if err != nil {
					t.Fatal(err)
				}
				defer clear(block.Bytes)
				v := vault.NewDirectory()
				id, err := v.AddServer("proxied", "main", vault.Target{Address: target, User: "test", PrivateKey: pem.EncodeToMemory(block), HostKeys: []string{string(ssh.MarshalAuthorizedKey(host))}, Proxy: route})
				if err != nil {
					t.Fatal(err)
				}
				profile, _ := v.AccountProfile(id, "main")
				config, err := v.Targets[profile].ClientConfig()
				if err != nil {
					t.Fatal(err)
				}
				v.Close()
				route.Clear()
				runner, err := NewCredentialStreamRunner(profile, target, config)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				input := []byte{'p', 0, 255, '\n'}
				var stdout, stderr bytes.Buffer
				code, err := runner(ctx, profile, "copy", bytes.NewReader(input), &stdout, &stderr)
				if err != nil || code != 7 || !bytes.Equal(stdout.Bytes(), input) || stderr.String() != "stderr" {
					t.Fatal("proxied SSH stream lost credentials or bytes after vault close")
				}
				if accepts, forwards := server.Counts(); accepts != 1 || forwards != 1 {
					t.Fatal("selected proxy was bypassed")
				}
			})
		}
	}
}

func TestProxyKeepsSSHPasswordEvidenceAndHostPins(t *testing.T) {
	for _, kind := range []string{sshproxy.SOCKS5, sshproxy.HTTP} {
		for _, mode := range []string{"correct", "wrong-pin", "none"} {
			t.Run(kind+mode, func(t *testing.T) {
				upstream, host, attempts := passwordEndpoint(t, mode == "none")
				const target = "ssh.target.invalid:22"
				route, _ := selectedProxy(t, kind, target, upstream, true)
				method := routedMethod(t, sshauth.Password([]byte("synthetic-password")), route)
				config := &ssh.ClientConfig{User: "selected", Auth: []ssh.AuthMethod{method}, HostKeyCallback: ssh.FixedHostKey(host.PublicKey())}
				if mode == "wrong-pin" {
					_, wrong := testSigner(t)
					config.HostKeyCallback = ssh.FixedHostKey(wrong.PublicKey())
				}
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				err := Check(ctx, target, config)
				if mode == "correct" {
					if err != nil || attempts.Load() != 1 {
						t.Fatal("proxied selected SSH password did not authenticate")
					}
				} else if err == nil || attempts.Load() != 0 {
					t.Fatal("proxy bypassed host pins or selected-auth evidence")
				}
			})
		}
	}
}

func TestProxyHumanShellUsesTheSamePinnedRoute(t *testing.T) {
	for _, kind := range []string{sshproxy.SOCKS5, sshproxy.HTTP} {
		_, signer := testSigner(t)
		upstream, host, _ := shellServer(t, signer.PublicKey(), false)
		const target = "ssh.target.invalid:22"
		route, server := selectedProxy(t, kind, target, upstream, true)
		config := shellClientConfig(signer, host)
		config.Auth[0] = routedMethod(t, config.Auth[0], route)
		resize := make(chan WindowSize, 1)
		resize <- WindowSize{Width: 100, Height: 30}
		close(resize)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		var stdout bytes.Buffer
		code, err := Shell(ctx, ShellOptions{Address: target, Config: config, Term: "xterm", Size: WindowSize{80, 24}, Resize: resize, Stdin: bytes.NewBufferString("typed"), Stdout: &stdout, Stderr: io.Discard})
		cancel()
		if err != nil || code != 7 || stdout.String() != "output:typed" {
			t.Fatal("human shell did not complete through the selected proxy")
		}
		if accepts, forwards := server.Counts(); accepts != 1 || forwards != 1 {
			t.Fatal("human shell bypassed proxy routing")
		}
	}
}

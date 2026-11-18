package remote

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ktav-lang/golang/pure"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/sshauth"
	"github.com/PHPCraftdream/ssjack/internal/sshproxy"
	"github.com/PHPCraftdream/ssjack/internal/vault"
	"github.com/PHPCraftdream/ssjack/tests/fixtures/proxyserver"
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
	// The 100ms cancellation bound is tight; dump goroutines if it trips.
	flakediag.OnFailure(t, func() string {
		return fmt.Sprintf("cancel probe: 100ms timeout; goroutine dump:\n%s", flakediag.GoroutineDump(64*1024))
	})
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

func TestCheckAuthenticatesWithoutRemoteRequests(t *testing.T) {
	_, clientKey := testSigner(t)
	_, host := testSigner(t)
	serverConfig := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if !bytes.Equal(key.Marshal(), clientKey.PublicKey().Marshal()) {
			return nil, errors.New("wrong client key")
		}
		return nil, nil
	}}
	serverConfig.AddHostKey(host)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	requestsSeen := make(chan int, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			requestsSeen <- -1
			return
		}
		defer conn.Close()
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		defer stop()
		server, channels, requests, err := ssh.NewServerConn(conn, serverConfig)
		if err != nil {
			requestsSeen <- -1
			return
		}
		defer server.Close()
		go ssh.DiscardRequests(requests)
		count := 0
		for next := range channels {
			channel, requests, err := next.Accept()
			if err != nil {
				break
			}
			for request := range requests {
				count++
				request.Reply(false, nil)
			}
			channel.Close()
		}
		requestsSeen <- count
	}()
	config := &ssh.ClientConfig{User: "test", Auth: []ssh.AuthMethod{sshauth.PublicKey(clientKey)}, HostKeyCallback: ssh.FixedHostKey(host.PublicKey())}
	if err := Check(ctx, listener.Addr().String(), config); err != nil {
		t.Fatal(err)
	}
	select {
	case count := <-requestsSeen:
		if count != 0 {
			t.Fatalf("check sent %d command/PTY/shell requests", count)
		}
	case <-ctx.Done():
		t.Fatal("check did not close its connection")
	}
}

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

func TestCheckRejectsNoneAuthEvenAfterPreviousKeySuccess(t *testing.T) {
	_, selected := testSigner(t)
	_, host := testSigner(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var allowNone atomic.Bool
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn, none bool) {
				defer conn.Close()
				stop := context.AfterFunc(ctx, func() { conn.Close() })
				defer stop()
				serverConfig := &ssh.ServerConfig{NoClientAuth: none}
				if !none {
					serverConfig.PublicKeyCallback = func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
						if !bytes.Equal(key.Marshal(), selected.PublicKey().Marshal()) {
							return nil, errors.New("wrong key")
						}
						return nil, nil
					}
				}
				serverConfig.AddHostKey(host)
				server, channels, requests, err := ssh.NewServerConn(conn, serverConfig)
				if err != nil {
					return
				}
				defer server.Close()
				go ssh.DiscardRequests(requests)
				for next := range channels {
					channel, requests, err := next.Accept()
					if err != nil {
						return
					}
					go func() { ssh.DiscardRequests(requests); channel.Close() }()
				}
			}(conn, allowNone.Load())
		}
	}()
	config := &ssh.ClientConfig{User: "test", Auth: []ssh.AuthMethod{sshauth.PublicKey(selected)}, HostKeyCallback: ssh.FixedHostKey(host.PublicKey())}
	address := listener.Addr().String()
	if err := Check(ctx, address, config); err != nil {
		t.Fatalf("selected key authentication failed: %v", err)
	}
	allowNone.Store(true)
	baseline, err := ssh.Dial("tcp", address, &ssh.ClientConfig{User: "test", Auth: []ssh.AuthMethod{ssh.PublicKeys(selected)}, HostKeyCallback: ssh.FixedHostKey(host.PublicKey()), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("fixture did not reproduce dependency none-auth acceptance: %v", err)
	}
	baselineSession, err := baseline.NewSession()
	if err != nil {
		baseline.Close()
		t.Fatalf("none-auth fixture refused session opening: %v", err)
	}
	baselineSession.Close()
	baseline.Close()
	if err := Check(ctx, address, config); err == nil || !strings.Contains(err.Error(), "selected private key") {
		t.Fatalf("none-auth was treated as proof of the selected key: %v", err)
	}
}

func passwordEndpoint(t *testing.T, none bool) (string, ssh.Signer, *atomic.Int32) {
	t.Helper()
	_, host := testSigner(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	done := make(chan struct{})
	var attempts atomic.Int32
	t.Cleanup(func() {
		cancel()
		listener.Close()
		<-done
	})
	go func() {
		defer close(done)
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		stop := context.AfterFunc(ctx, func() { connection.Close() })
		defer stop()
		serverConfig := &ssh.ServerConfig{NoClientAuth: none}
		if !none {
			serverConfig.PasswordCallback = func(metadata ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
				attempts.Add(1)
				if metadata.User() != "selected" || subtle.ConstantTimeCompare(password, []byte("synthetic-password")) != 1 {
					return nil, errors.New("synthetic credential mismatch")
				}
				return nil, nil
			}
		}
		serverConfig.AddHostKey(host)
		server, channels, _, err := ssh.NewServerConn(connection, serverConfig)
		if err != nil {
			return
		}
		defer server.Close()
		for next := range channels {
			if next.ChannelType() != "session" {
				next.Reject(ssh.UnknownChannelType, "session only")
				continue
			}
			channel, _, err := next.Accept()
			if err != nil {
				return
			}
			channel.Close()
		}
	}()
	return listener.Addr().String(), host, &attempts
}

func TestPasswordEvidenceIsFreshForEachConnection(t *testing.T) {
	first, firstHost, _ := passwordEndpoint(t, false)
	second, secondHost, attempts := passwordEndpoint(t, true)
	config := &ssh.ClientConfig{User: "selected", Auth: []ssh.AuthMethod{sshauth.Password([]byte("synthetic-password"))}, HostKeyCallback: ssh.FixedHostKey(firstHost.PublicKey())}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := Check(ctx, first, config); err != nil {
		t.Fatal("selected password control did not authenticate")
	}
	config.HostKeyCallback = ssh.FixedHostKey(secondHost.PublicKey())
	if err := Check(ctx, second, config); err == nil || attempts.Load() != 0 {
		t.Fatal("previous password success authorized a later none-auth connection")
	}
}

func TestSelectedPasswordAuthentication(t *testing.T) {
	for _, mode := range []string{"correct", "wrong", "none", "untyped", "mixed", "wrong-host"} {
		t.Run(mode, func(t *testing.T) {
			address, host, attempts := passwordEndpoint(t, mode == "none")
			value := []byte("synthetic-password")
			if mode == "wrong" {
				value = []byte("wrong-password")
			}
			method := sshauth.Password(value)
			clear(value)
			config := &ssh.ClientConfig{User: "selected", Auth: []ssh.AuthMethod{method}, HostKeyCallback: ssh.FixedHostKey(host.PublicKey())}
			if mode == "untyped" {
				config.Auth = []ssh.AuthMethod{ssh.Password("synthetic-password")}
			}
			if mode == "mixed" {
				config.Auth = append(config.Auth, ssh.Password("fallback"))
			}
			if mode == "wrong-host" {
				_, other := testSigner(t)
				config.HostKeyCallback = ssh.FixedHostKey(other.PublicKey())
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			err := Check(ctx, address, config)
			if mode == "correct" {
				if err != nil || attempts.Load() != 1 {
					t.Fatal("selected owned password did not authenticate")
				}
			} else if err == nil {
				t.Fatal("invalid authentication was accepted as the selected password")
			}
			if (mode == "none" || mode == "untyped" || mode == "mixed" || mode == "wrong-host") && attempts.Load() != 0 {
				t.Fatal("password was offered on a refused or unverified authentication path")
			}
		})
	}
}

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

func TestSSHSetupErrorsPreserveContextCause(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sshStageError(ctx, "server refused the SSH shell"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled setup lost its cause: %v", err)
	}
	expired, stop := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer stop()
	if err := sshStageError(expired, "SSH authentication failed"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired setup lost its cause: %v", err)
	}
	const message = "server refused the interactive SSH terminal"
	if err := sshStageError(context.Background(), message); err == nil || err.Error() != message {
		t.Fatalf("non-cancelled setup changed its diagnostic: %v", err)
	}
}

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

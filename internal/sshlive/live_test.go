package sshlive

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/sshauth"
)

func TestStatusDisplayPreservesKnownZeroAndEscapesProfile(t *testing.T) {
	status := (&Status{
		Profile: `profile"\n`, DesiredKnown: true, DesiredRevision: 0,
		AdoptedKnown: true, AdoptedRevision: 2, Unavailable: true,
	}).Display()
	if status != "\nSSH last observed: profile=\"profile\\\"\\\\n\" desired=0 delivered=unknown adopted=2 unavailable=true" {
		t.Fatalf("unexpected status display: %s", status)
	}
	if (*Status)(nil).Display() != "" {
		t.Fatal("nil status should not display")
	}
}

func testMaterial(address string) Material {
	guard, err := outputguard.New([][]byte{[]byte("synthetic-secret")})
	if err != nil {
		panic(err)
	}
	return Material{
		Profile: "profile-a", Scope: "opaque-scope-a", Revision: 0, Address: address, Guard: guard,
		Config: &ssh.ClientConfig{User: "runner", Auth: []ssh.AuthMethod{sshauth.Password([]byte("synthetic-password"))}, HostKeyCallback: func(string, net.Addr, ssh.PublicKey) error { return nil }},
	}
}

func TestAdmissionFreshensSourceAndKeepsKnownRevision(t *testing.T) {
	material := testMaterial("127.0.0.1:22")
	calls := 0
	runtime, err := New(context.Background(), material.Profile, func(context.Context) (Material, error) {
		calls++
		return material, nil
	})
	if err != nil || calls != 1 {
		t.Fatal("initial source was not validated")
	}
	initial := runtime.Status()
	if !initial.DesiredKnown || initial.DesiredRevision != 0 || initial.DeliveredKnown || initial.AdoptedKnown {
		t.Fatal("revision zero was not represented as known")
	}
	admitted, err := runtime.Admit(context.Background(), material.Profile, "run")
	if err != nil || calls != 2 || admitted.Guard != material.Guard || admitted.Runner == nil {
		t.Fatal("admission did not use fresh guarded material")
	}
	status := runtime.Status()
	if status.DeliveredKnown || status.AdoptedKnown || status.Unavailable {
		t.Fatal("admission alone advanced delivery or adoption")
	}
	admitted.Issued()
	status = runtime.Status()
	if !status.DeliveredKnown || status.DeliveredRevision != 0 || status.AdoptedKnown || status.Unavailable {
		t.Fatal("issuance did not mark delivery or lost revision zero")
	}
}

func TestSourceFailureAndIdentityChangesFailClosed(t *testing.T) {
	initial := testMaterial("127.0.0.1:22")
	bad := initial
	var sourceErr error
	runtime, err := New(context.Background(), initial.Profile, func(context.Context) (Material, error) { return bad, sourceErr })
	if err != nil {
		t.Fatal("valid initial material was refused")
	}
	for _, test := range []string{"private-error", "profile", "scope", "address", "user", "guard"} {
		t.Run(test, func(t *testing.T) {
			bad, sourceErr = initial, nil
			switch test {
			case "private-error":
				sourceErr = errors.New("private source failure")
			case "profile":
				bad.Profile = "other"
			case "scope":
				bad.Scope = "other-scope"
			case "address":
				bad.Address = "other.example:22"
			case "user":
				bad.Config = &ssh.ClientConfig{User: "other", Auth: bad.Config.Auth, HostKeyCallback: bad.Config.HostKeyCallback}
			case "guard":
				bad.Guard = nil
			}
			_, err := runtime.Admit(context.Background(), initial.Profile, "run")
			status := runtime.Status()
			if !errors.Is(err, ErrUnavailable) || err.Error() != ErrUnavailable.Error() || !status.Unavailable || status.DeliveredKnown || status.AdoptedKnown {
				t.Fatal("invalid source material was not hidden and refused")
			}
		})
	}
}

func sshTestServer(t *testing.T, rejectPassword, noAuth bool) (string, ssh.PublicKey) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("synthetic host key generation failed")
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal("synthetic host signer failed")
	}
	config := &ssh.ServerConfig{NoClientAuth: noAuth}
	if !noAuth {
		config.PasswordCallback = func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			if rejectPassword {
				return nil, errors.New("rejected synthetic password")
			}
			return nil, nil
		}
	}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("synthetic SSH listener failed")
	}
	var mu sync.Mutex
	connections := make(map[net.Conn]struct{})
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			connections[conn] = struct{}{}
			workers.Add(1)
			mu.Unlock()
			go func() {
				defer workers.Done()
				defer func() {
					mu.Lock()
					delete(connections, conn)
					mu.Unlock()
				}()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				server, channels, requests, err := ssh.NewServerConn(conn, config)
				if err != nil {
					_ = conn.Close()
					return
				}
				defer server.Close()
				discarded := make(chan struct{})
				go func() {
					ssh.DiscardRequests(requests)
					close(discarded)
				}()
				for channel := range channels {
					channel.Reject(ssh.Prohibited, "synthetic exec disabled")
				}
				_ = server.Close()
				<-discarded
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		for conn := range connections {
			_ = conn.Close()
		}
		mu.Unlock()
		workers.Wait()
	})
	return listener.Addr().String(), signer.PublicKey()
}

func TestAdoptionRequiresSelectedIdentityHandshake(t *testing.T) {
	for _, test := range []struct {
		name           string
		rejectPassword bool
		noAuth         bool
		badHostKey     bool
		adopted        bool
		issue          bool
	}{
		{name: "exec rejected after selected authentication", adopted: true, issue: true},
		{name: "handshake before issuance", adopted: false},
		{name: "password rejected", rejectPassword: true, issue: true},
		{name: "host key rejected", badHostKey: true, issue: true},
		{name: "no authentication selected", noAuth: true, issue: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			address, hostKey := sshTestServer(t, test.rejectPassword, test.noAuth)
			material := testMaterial(address)
			if test.badHostKey {
				material.Config.HostKeyCallback = func(string, net.Addr, ssh.PublicKey) error { return errors.New("wrong synthetic host") }
			} else {
				material.Config.HostKeyCallback = ssh.FixedHostKey(hostKey)
			}
			runtime, err := New(context.Background(), material.Profile, func(context.Context) (Material, error) { return material, nil })
			if err != nil {
				t.Fatal("valid initial material was refused")
			}
			admitted, err := runtime.Admit(context.Background(), material.Profile, "synthetic command")
			if err != nil {
				t.Fatal("fresh material was refused")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if test.issue {
				admitted.Issued()
			}
			_, _ = admitted.Runner(ctx, material.Profile, "synthetic command", io.Discard, io.Discard)
			status := runtime.Status()
			if status.AdoptedKnown != test.adopted || status.DeliveredKnown != test.issue {
				t.Fatal("adoption did not match selected-identity handshake")
			}
		})
	}
}

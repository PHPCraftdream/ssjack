package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

const connectPassword = "synthetic SSH account password"

// ownerConnectionAcceptance drives the picker's real SSH handoff through a
// pseudo-terminal against a loopback synthetic server. The server ID is stable
// across the earlier rename, so the database is addressed by ID.
func ownerConnectionAcceptance(t *testing.T, ctx context.Context, path string, password []byte, server string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Fatal("owner connection acceptance requires the Linux CI fixture")
	}
	before, err := vault.Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer before.Close()
	firstProfile, err := before.AccountProfile(server, "main")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey(before.Targets[firstProfile].PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	var token [8]byte
	if _, err := rand.Read(token[:]); err != nil {
		t.Fatal(err)
	}
	marker := "m" + hex.EncodeToString(token[:])
	loopback := startLoopbackSSH(t, signer.PublicKey(), connectPassword, marker)
	retargetConnections(t, ctx, path, password, server, loopback)
	proxy := ownerProxyTerminalAcceptance(t, ctx, path, password, server, loopback.address())

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	driver, err := filepath.Abs(filepath.Join("..", "..", "scripts", "ci", "owner_connect.py"))
	if err != nil {
		t.Fatal(err)
	}
	runConnectDriver(t, ctx, driver, "multi", executable, path, password, marker)
	// The wrong-pin account must never authenticate: the client refuses first.
	if got, want := loopback.authentications(), []string{"first|publickey", "second|password"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("loopback server authentications %q, want %q", got, want)
	}
	// Singleton run: exactly one human connection point must neither be
	// auto-activated nor connected. The baseline is taken after the multi run.
	restrictToSingleHuman(t, ctx, path, password, server)
	baseline := loopback.acceptedConnections()
	runConnectDriver(t, ctx, driver, "single", executable, path, password, marker)
	if got := loopback.acceptedConnections(); got != baseline {
		t.Fatalf("singleton run accepted %d TCP connections, want none (baseline %d)", got-baseline, baseline)
	}
	if got, want := loopback.authentications(), []string{"first|publickey", "second|password"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("authentications changed after the singleton run: %q", got)
	}
	if accepted, forwarded := proxy.Counts(); accepted != 2 || forwarded != 2 {
		t.Fatal("owner SSH connections bypassed the configured proxy or singleton auto-connected")
	}
	proxy.Close()
	// Join the server explicitly: accept loop and every handler must be gone.
	stopped := make(chan struct{})
	go func() { loopback.stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("loopback SSH server did not join within 10s")
	}
	after, err := vault.Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer after.Close()
	if after.OwnerStore.Pending != nil || len(after.Targets) != len(before.Targets)+2 || after.Servers[server].Name != "pty-renamed" {
		t.Fatal("connections left pending owner state or changed the directory shape")
	}
	for profile, expected := range before.Targets {
		actual, exists := after.Targets[profile]
		if !exists || actual.User != expected.User || !bytes.Equal(actual.PrivateKey, expected.PrivateKey) || !bytes.Equal(actual.Password, expected.Password) {
			t.Fatal("connections changed an SSH account credential")
		}
	}
	secondProfile, err := after.AccountProfile(server, "second")
	if err != nil || string(after.Targets[secondProfile].Password) != connectPassword {
		t.Fatal("connections changed the password account")
	}
}

// retargetConnections points the fixture at the loopback listener with a pin
// for its real host key, adds an agent-only account that the picker must hide,
// and adds a server whose pin is wrong. Only addresses, pins and new accounts
// change; the Edit/Close cycle re-saves under the existing unlock key.
func retargetConnections(t *testing.T, ctx context.Context, path string, password []byte, serverID string, loopback *loopbackSSH) {
	t.Helper()
	wrongPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey, err := ssh.NewPublicKey(wrongPublic)
	if err != nil {
		t.Fatal(err)
	}
	pin, wrong := string(ssh.MarshalAuthorizedKey(loopback.hostKey)), string(ssh.MarshalAuthorizedKey(wrongKey))
	manager, err := ownerdb.Open(ctx, path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Discard()
	err = manager.Edit(func(v *vault.Vault) error {
		server, exists := v.Servers[serverID]
		if !exists {
			return errors.New("fixture server is missing")
		}
		first := v.Targets[server.Accounts["main"]]
		for _, profile := range server.Accounts {
			target := v.Targets[profile]
			target.Address, target.HostKeys = loopback.address(), []string{pin}
			if err := target.Validate(); err != nil {
				return err
			}
			v.Targets[profile] = target
		}
		agent := v.Targets[server.Accounts["main"]]
		agent.User, agent.Usage = "agentonly", "agent"
		if err := v.SetAccount(serverID, "agentonly", agent); err != nil {
			return err
		}
		intruder := first
		intruder.Address, intruder.User, intruder.HostKeys = loopback.address(), "intruder", []string{wrong}
		_, err := v.AddServer("wrong-pin", "intruder", intruder)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if err := manager.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

// runConnectDriver runs the PTY driver in the given mode ("multi" or "single").
// Both stdin lines are synthetic fixtures; the second lets the driver prove the
// SSH password never reaches the terminal transcript.
func runConnectDriver(t *testing.T, ctx context.Context, driver, mode, executable, path string, password []byte, marker string) {
	t.Helper()
	input := append(append(append([]byte(nil), password...), '\n'), []byte(connectPassword+"\n")...)
	defer clear(input)
	command := exec.CommandContext(ctx, "python3", "-I", driver, mode, executable, path, marker)
	command.Stdin = bytes.NewReader(input)
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	command.WaitDelay = 5 * time.Second
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("synthetic owner connection interaction (%s): %v: %s", mode, err, output)
	}
}

// restrictToSingleHuman marks every account except pty-renamed account main (login first) agent-only,
// so the picker lists exactly one connection point. Credentials are untouched.
func restrictToSingleHuman(t *testing.T, ctx context.Context, path string, password []byte, serverID string) {
	t.Helper()
	manager, err := ownerdb.Open(ctx, path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Discard()
	err = manager.Edit(func(v *vault.Vault) error {
		server, exists := v.Servers[serverID]
		if !exists {
			return errors.New("fixture server is missing")
		}
		keep := server.Accounts["main"]
		for profile, target := range v.Targets {
			if profile == keep {
				continue
			}
			target.Usage = "agent"
			if err := target.Validate(); err != nil {
				return err
			}
			v.Targets[profile] = target
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if err := manager.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func liveReadJob(t *testing.T, ctx context.Context, jobs *remote.Manager, id string) remote.ReadOutput {
	t.Helper()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		result, err := jobs.Read(remote.ReadInput{JobID: id})
		if err != nil {
			t.Fatal(err)
		}
		if result.Done {
			return result
		}
		select {
		case <-ctx.Done():
			t.Fatal("synthetic SSH operation did not finish")
		case <-ticker.C:
		}
	}
}

func syntheticLiveReply(server *loopbackSSH, identity string, channel ssh.Channel, request *ssh.Request) bool {
	var command struct{ Command string }
	if server.marker != "owner-control" || ssh.Unmarshal(request.Payload, &command) != nil ||
		(command.Command != "synthetic-live-hold" && command.Command != "synthetic-live-once") {
		return false
	}
	if request.WantReply {
		_ = request.Reply(true, nil)
	}
	if _, err := fmt.Fprintf(channel, "SYNTHETIC-LIVE:%s\n", identity); err != nil {
		return true
	}
	if command.Command == "synthetic-live-hold" {
		server.holdStarted <- identity
		<-server.holdRelease
	}
	_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
	_ = channel.Close()
	return true
}

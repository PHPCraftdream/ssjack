package appstore_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/cli"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/testsupport/sshfixture"
	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/ownercommand"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/sshproxy"
	"github.com/PHPCraftdream/ssjack/internal/vault"
	"github.com/PHPCraftdream/ssjack/tests/fixtures/proxyserver"
)

const ownerProxyPassword = "synthetic owner proxy password"

func ownerProxyTerminalAcceptance(t *testing.T, ctx context.Context, path string, password []byte, serverID, upstream string) *proxyserver.Server {
	t.Helper()
	proxy, err := proxyserver.Start(proxyserver.Options{Protocol: sshproxy.SOCKS5, Target: upstream, Upstream: upstream, Username: "proxy-operator", Password: []byte(ownerProxyPassword)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(proxy.Close)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	driver, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "scripts", "ci", "owner", "owner_proxy.py"))
	if err != nil {
		t.Fatal(err)
	}
	input := append(append(append([]byte(nil), password...), '\n'), []byte(ownerProxyPassword+"\n")...)
	defer clear(input)
	command := exec.CommandContext(ctx, "python3", "-I", driver, executable, path, proxy.Address())
	command.Stdin = bytes.NewReader(input)
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	command.WaitDelay = 5 * time.Second
	output, err := command.CombinedOutput()
	ownerChildExecFail(t, "owner proxy driver", command, output, err)
	if err != nil {
		t.Fatalf("synthetic proxy terminal interaction: %v: %s", err, output)
	}
	loaded, err := vault.Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()
	for _, profile := range loaded.Servers[serverID].Accounts {
		route := loaded.Targets[profile].Proxy
		if route == nil || route.Type != sshproxy.SOCKS5 || route.Address != proxy.Address() || route.Username != "proxy-operator" || string(route.Password) != ownerProxyPassword {
			t.Fatal("terminal proxy form lost encrypted server settings")
		}
	}
	encoded, err := os.ReadFile(path)
	if err != nil || bytes.Contains(encoded, []byte(ownerProxyPassword)) {
		t.Fatal("proxy terminal form persisted plaintext authentication")
	}
	if accepted, forwarded := proxy.Counts(); accepted != 0 || forwarded != 0 {
		t.Fatal("configuring a proxy connected without an explicit connection selection")
	}
	return proxy
}

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
	loopback := sshfixture.StartLoopbackSSH(t, signer.PublicKey(), sshfixture.ConnectPassword, marker)
	retargetConnections(t, ctx, path, password, server, loopback)
	proxy := ownerProxyTerminalAcceptance(t, ctx, path, password, server, loopback.Address())
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	driver, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "scripts", "ci", "owner", "owner_connect.py"))
	if err != nil {
		t.Fatal(err)
	}
	runConnectDriver(t, ctx, driver, "multi", executable, path, password, marker)
	// The wrong-pin account must never authenticate: the client refuses first.
	if got, want := loopback.Authentications(), []string{"first|publickey", "second|password"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("loopback server authentications %q, want %q", got, want)
	}
	// Singleton run: exactly one human connection point must neither be
	// auto-activated nor connected. The baseline is taken after the multi run.
	restrictToSingleHuman(t, ctx, path, password, server)
	baseline := loopback.AcceptedConnections()
	runConnectDriver(t, ctx, driver, "single", executable, path, password, marker)
	if got := loopback.AcceptedConnections(); got != baseline {
		t.Fatalf("singleton run accepted %d TCP connections, want none (baseline %d)", got-baseline, baseline)
	}
	if got, want := loopback.Authentications(), []string{"first|publickey", "second|password"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("authentications changed after the singleton run: %q", got)
	}
	if accepted, forwarded := proxy.Counts(); accepted != 2 || forwarded != 2 {
		t.Fatal("owner SSH connections bypassed the configured proxy or singleton auto-connected")
	}
	proxy.Close()
	// Join the server explicitly: accept loop and every handler must be gone.
	stopped := make(chan struct{})
	go func() { loopback.Stop(); close(stopped) }()
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
	if err != nil || string(after.Targets[secondProfile].Password) != sshfixture.ConnectPassword {
		t.Fatal("connections changed the password account")
	}
}

// retargetConnections points the fixture at the loopback listener with a pin
// for its real host key, adds an agent-only account that the picker must hide,
// and adds a server whose pin is wrong. Only addresses, pins and new accounts
// change; the Edit/Close cycle re-saves under the existing unlock key.
func retargetConnections(t *testing.T, ctx context.Context, path string, password []byte, serverID string, loopback *sshfixture.LoopbackSSH) {
	t.Helper()
	wrongPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey, err := ssh.NewPublicKey(wrongPublic)
	if err != nil {
		t.Fatal(err)
	}
	pin, wrong := string(ssh.MarshalAuthorizedKey(loopback.HostKey)), string(ssh.MarshalAuthorizedKey(wrongKey))
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
			target.Address, target.HostKeys = loopback.Address(), []string{pin}
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
		intruder.Address, intruder.User, intruder.HostKeys = loopback.Address(), "intruder", []string{wrong}
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
	input := append(append(append([]byte(nil), password...), '\n'), []byte(sshfixture.ConnectPassword+"\n")...)
	defer clear(input)
	command := exec.CommandContext(ctx, "python3", "-I", driver, mode, executable, path, marker)
	command.Stdin = bytes.NewReader(input)
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	command.WaitDelay = 5 * time.Second
	output, err := command.CombinedOutput()
	ownerChildExecFail(t, "owner connect driver "+mode, command, output, err)
	if err != nil {
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

// ownerChildExecFail prints failure-only evidence for a finished exec-based
// driver child: command name (never arguments), pid, exit status, output size,
// a digest and a 16 KiB tail of the already-captured combined output.
func ownerChildExecFail(t *testing.T, what string, command *exec.Cmd, output []byte, err error) {
	t.Helper()
	if err == nil {
		return
	}
	name := ""
	if len(command.Args) > 0 {
		name = filepath.Base(command.Args[0])
	}
	pid := 0
	if command.Process != nil {
		pid = command.Process.Pid
	}
	t.Logf("owner child evidence: what=%s name=%s pid=%d exit=%v output-bytes=%d digest=%s\noutput tail:%s",
		what, name, pid, err, len(output), flakediag.Short(output), flakediag.Tail(string(output), 16*1024))
}
func TestOwnerInteractivePTYChild(t *testing.T) {
	if os.Getenv("SSJACK_OWNER_TUI_CHILD") != "1" {
		t.Skip("synthetic terminal child only")
	}
	var args []string
	for i, argument := range os.Args {
		if argument == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	// The import terminal flow pays several production-KDF passes; it asks for a
	// longer bound explicitly, every other caller keeps one minute.
	limit := time.Minute
	if seconds, err := strconv.Atoi(os.Getenv("SSJACK_OWNER_TUI_CHILD_SECONDS")); err == nil && seconds > 0 && seconds <= 600 {
		limit = time.Duration(seconds) * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	code, err := cli.Run(ctx, args)
	if code != 0 || err != nil {
		reason := "other"
		if err != nil {
			switch err.Error() {
			case "owner terminal editor stopped unexpectedly":
				reason = "terminal"
			case "owner editor stopped with unsaved or unresolved changes; reopen the encrypted database and inspect pending recovery":
				reason = "save"
			case "cannot unlock owner database; directory payload schema v2 is required":
				reason = "unlock"
			}
		}
		t.Fatalf("synthetic interactive child failed: code=%d context-ended=%t reason=%s", code, ctx.Err() != nil, reason)
	}
}
func ownerTerminalAcceptance(t *testing.T, ctx context.Context, path string, password []byte, expected *vault.Vault, server string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Fatal("owner terminal acceptance requires the Linux CI fixture")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	driver, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "scripts", "ci", "owner", "owner_tui.py"))
	if err != nil {
		t.Fatal(err)
	}
	input := append(append([]byte(nil), password...), '\n')
	defer clear(input)
	command := exec.CommandContext(ctx, "python3", "-I", driver, executable, path)
	command.Stdin = bytes.NewReader(input)
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	command.WaitDelay = 5 * time.Second
	output, err := command.CombinedOutput()
	ownerChildExecFail(t, "owner terminal driver", command, output, err)
	if err != nil {
		t.Fatalf("synthetic owner terminal interaction: %v: %s", err, output)
	}
	loaded, err := vault.Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()
	if loaded.Servers[server].Name != "pty-renamed" || len(loaded.Targets) != len(expected.Targets) || len(loaded.Servers[server].Accounts) != len(expected.Servers[server].Accounts) || loaded.OwnerStore.Pending != nil {
		t.Fatal("terminal apply/cancel did not preserve the complete directory")
	}
	for profile, target := range expected.Targets {
		actual, exists := loaded.Targets[profile]
		if !exists || actual.Address != target.Address || actual.User != target.User || !bytes.Equal(actual.PrivateKey, target.PrivateKey) || !bytes.Equal(actual.Password, target.Password) {
			t.Fatal("terminal editing changed an unrelated SSH credential")
		}
	}
}

func TestOwnerCommandPTYChild(t *testing.T) {
	if os.Getenv("SSJACK_OWNER_COMMAND_CHILD") != "1" {
		t.Skip("synthetic owner-command terminal child only")
	}
	var args []string
	for i, arg := range os.Args {
		if arg == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 170*time.Second)
	defer cancel()
	code, err := cli.Run(ctx, args)
	if os.Getenv("SSJACK_OWNER_COMMAND_CANCEL") == "1" {
		if code != 1 || !errors.Is(err, ownercommand.ErrCancelled) {
			t.Fatal("cancelled owner command did not refuse")
		}
	} else if code != 0 || err != nil {
		t.Fatal("confirmed owner command failed")
	}
}
func ownerCommandAcceptance(t *testing.T, ctx context.Context, path string, password []byte, server string) {
	t.Helper()
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := vault.Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	name, count := initial.Servers[server].Name, len(initial.Servers[server].Accounts)
	initial.Close()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	driver, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "scripts", "ci", "owner", "owner_command.py"))
	if err != nil {
		t.Fatal(err)
	}
	credential := []byte("synthetic CLI account password")
	defer clear(credential)
	input := append(append(append(append([]byte(nil), password...), '\n'), credential...), '\n')
	defer clear(input)
	for _, mode := range []string{"cancel", "apply"} {
		command := exec.CommandContext(ctx, "python3", "-I", driver, executable, path, name, mode)
		command.Stdin = bytes.NewReader(input)
		command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
		command.WaitDelay = 5 * time.Second
		output, err := command.CombinedOutput()
		ownerChildExecFail(t, "owner command driver "+mode, command, output, err)
		if err != nil {
			t.Fatalf("synthetic owner command: %v: %s", err, output)
		}
		if mode == "cancel" {
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("cancelled command changed database ciphertext")
			}
		}
	}
	loaded, err := vault.Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()
	profile, err := loaded.AccountProfile(server, "cli-added")
	if err != nil {
		t.Fatal(err)
	}
	target := loaded.Targets[profile]
	if target.User != "cli-user" || target.Usage != "agent" || !bytes.Equal(target.Password, credential) || len(loaded.Servers[server].Accounts) != count+1 {
		t.Fatal("parameterized command lost metadata/hidden credentials or changed unrelated accounts")
	}
}

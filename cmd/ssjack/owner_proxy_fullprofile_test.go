package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

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
	driver, err := filepath.Abs(filepath.Join("..", "..", "scripts", "ci", "owner_proxy.py"))
	if err != nil {
		t.Fatal(err)
	}
	input := append(append(append([]byte(nil), password...), '\n'), []byte(ownerProxyPassword+"\n")...)
	defer clear(input)
	command := exec.CommandContext(ctx, "python3", "-I", driver, executable, path, proxy.Address())
	command.Stdin = bytes.NewReader(input)
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	command.WaitDelay = 5 * time.Second
	if output, err := command.CombinedOutput(); err != nil {
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

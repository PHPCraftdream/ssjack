package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/ownercontrol"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
	"github.com/PHPCraftdream/ssjack/internal/ownerterminal"
)

func nativeServerAddress(t *testing.T, ctx context.Context, control *ownercontrol.Control, server, address string) {
	t.Helper()
	backend, ok := control.Backend().(interface {
		ApplyDirectory(ownerpacket.DirectoryChange) error
	})
	if !ok {
		t.Fatal("observer lost typed directory admission")
	}
	if err := backend.ApplyDirectory(ownerpacket.DirectoryChange{Action: "edit-server", ServerID: server, Fields: [][]byte{[]byte(address), nil}}); err != nil {
		t.Fatal(err)
	}
	if err := control.Backend().Flush(ctx); err != nil {
		t.Fatal(err)
	}
}

func nativeHumanSSHAcceptance(t *testing.T, ctx context.Context, path string, password []byte, server string, observer *ownercontrol.Control, loopback *loopbackSSH) {
	t.Helper()
	nativeServerAddress(t, ctx, observer, server, loopback.address())
	metadata, err := observer.Backend().Metadata()
	if err != nil {
		t.Fatal(err)
	}
	name, human := "", 0
	for _, entry := range metadata.Servers {
		if entry.ID == server {
			name = entry.Name
		}
		for _, account := range entry.Accounts {
			if account.Usage == "" || account.Usage == "human" || account.Usage == "both" {
				human++
			}
		}
	}
	if name == "" || human != 1 {
		t.Fatal("human SSH server metadata is missing")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bridge, err := filepath.Abs(filepath.Join("..", "..", "scripts", "ci", "owner_pty_bridge.py"))
	if err != nil {
		t.Fatal(err)
	}
	connections := loopback.acceptedConnections()
	authentications := len(loopback.authentications())
	environment := make([]string, 0)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if !strings.HasPrefix(key, "SSJACK_OWNER_") && key != "SSJACK_VAULT_PASSWORD" && key != "TERM" && key != "NO_COLOR" {
			environment = append(environment, entry)
		}
	}
	environment = append(environment, "TERM=xterm-256color", "NO_COLOR=1", "SSJACK_OWNER_NATIVE_TUI_CHILD=1", "SSJACK_OWNER_TUI_CHILD=1")
	terminal, err := ownerterminal.Start(ctx, ownerterminal.Command{Executable: executable, UnixBridge: bridge, Directory: t.TempDir(), Environment: environment,
		Args: []string{"-test.run=^TestNativeInteractiveProcessChild$", "--", "--vault", path, "--interactive"}})
	if err != nil {
		t.Fatal(err)
	}
	capture := ownerterminal.CaptureOutput(terminal.Output)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = terminal.Close(cleanup)
		if capture.Join(cleanup) != nil || capture.Contains(password) {
			t.Error("human SSH terminal did not join or exposed the vault unlock")
		}
		capture.Clear()
	}()
	expect := func(text string) {
		if capture.Wait(ctx, text) != nil {
			t.Fatal("native human SSH flow did not reach:", text)
		}
	}
	send := func(data []byte) {
		if _, err := terminal.Input.Write(data); err != nil {
			t.Fatal("native human SSH input failed")
		}
	}
	expect("Vault secret:")
	ending := byte('\n')
	if runtime.GOOS == "windows" {
		ending = '\r'
	}
	input := append(append([]byte(nil), password...), ending)
	_, err = terminal.Input.Write(input)
	clear(input)
	if err != nil {
		t.Fatal("native human SSH unlock input failed")
	}
	expect("Connect:")
	// Right must not connect; the following Servers screen is the input barrier.
	send([]byte("\x1b[C\x1b[B\r"))
	expect("[Add server]")
	if loopback.acceptedConnections() != connections {
		t.Fatal("picker connected before an explicit Enter decision")
	}
	send([]byte("\x1b[D\r"))
	expect("SYNTHETIC-SSH-READY user=second")
	if capture.Contains([]byte(connectPassword)) {
		t.Fatal("SSH authentication was disclosed before deliberate human output")
	}
	t.Run("legacy-writer-refusal", func(t *testing.T) {
		nativeWriterRefusal(t, ctx, path, password, name, loopback)
	})
	// Later owner edits must not replace or terminate the captured live shell.
	nativeServerAddress(t, ctx, observer, server, "127.0.0.1:3")
	input = append([]byte(connectPassword), '\r')
	send(input)
	clear(input)
	expect("ECHO:" + connectPassword)
	send([]byte("exit\r"))
	expect("SSH session ended (exit code 0).")
	send([]byte{3})
	if terminal.Wait(ctx) != nil {
		t.Fatal("human shell handoff did not restore and close the picker")
	}
	accepted := loopback.authentications()
	if loopback.acceptedConnections() != connections+1 || len(accepted) != authentications+1 || accepted[len(accepted)-1] != "second|password" {
		t.Fatal("native handoff used the wrong account or opened extra SSH connections")
	}
}

package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/ownerterminal"
)

type nativeArchiveInput struct {
	marker string
	value  []byte
}

func nativeArchiveCommand(t *testing.T, ctx context.Context, database string, cancelled bool, arguments []string, steps ...nativeArchiveInput) {
	t.Helper()
	lifetime, cancel := context.WithTimeout(ctx, 170*time.Second)
	defer cancel()
	executable, err := os.Executable()
	nativeArchiveMust(t, err)
	bridge, err := filepath.Abs(filepath.Join("..", "..", "scripts", "ci", "owner", "owner_pty_bridge.py"))
	nativeArchiveMust(t, err)
	environment := make([]string, 0)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if !strings.HasPrefix(key, "SSJACK_OWNER_") && key != "SSJACK_VAULT_PASSWORD" && key != "TERM" && key != "NO_COLOR" {
			environment = append(environment, entry)
		}
	}
	decision := "0"
	if cancelled {
		decision = "1"
	}
	environment = append(environment, "TERM=xterm-256color", "NO_COLOR=1", "SSJACK_OWNER_NATIVE_CHILD=1", "SSJACK_OWNER_COMMAND_CHILD=1", "SSJACK_OWNER_COMMAND_CANCEL="+decision)
	args := append([]string{"-test.run=^TestOwnerNativeCommandChild$", "--", "--vault", database, "owner"}, arguments...)
	terminal, err := ownerterminal.Start(lifetime, ownerterminal.Command{Executable: executable, UnixBridge: bridge, Environment: environment, Args: args})
	nativeArchiveMust(t, err)
	started := time.Now()
	tail := newOwnerChildTail()
	terminal.Output = teeOwnerChildOutput(terminal.Output, tail)
	ownerChildTerminal(t, "native archive terminal", executable, terminal, tail, started)
	capture := ownerterminal.CaptureOutput(terminal.Output)
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Minute)
		defer stop()
		_ = terminal.Close(cleanup)
		if capture.Join(cleanup) != nil {
			t.Error("native archive terminal output did not join")
		}
		for _, private := range []string{nativeArchivePassword, nativeArchiveMaster, nativeArchiveValue, nativeArchiveExcluded, nativeArchiveCredential, nativeArchiveMCPBasic, nativeArchiveMCPBearer, nativeArchiveMCPHeader, nativeArchiveMCPBearerHeader, nativeArchiveMCPExcluded, nativeArchiveMCPExcludedHeader} {
			if capture.Contains([]byte(private)) {
				t.Error("native archive terminal disclosed private data")
			}
		}
		capture.Clear()
	}()
	ending := byte('\n')
	if runtime.GOOS == "windows" {
		ending = '\r'
	}
	unlock := append([]byte(nativeArchivePassword), ending)
	defer clear(unlock)
	steps = append([]nativeArchiveInput{{"Vault secret:", unlock}}, steps...)
	for _, step := range steps {
		captureWaitDiag(t, lifetime, capture, step.marker, "native archive command missed terminal barrier \""+step.marker+"\"")
		if len(step.value) != 0 {
			_, err := terminal.Input.Write(step.value)
			nativeArchiveMust(t, err)
		}
	}
	if err := terminal.Wait(lifetime); err != nil {
		// Tell a timeout from a child that exited with an error; both used to read the same.
		class := "child ended with error: " + flakediag.Tail(err.Error(), 200)
		if lifetime.Err() != nil {
			class = "lifetime expired: " + lifetime.Err().Error()
		}
		t.Fatal("native archive command did not complete its explicit decision (" + class + ")")
	}
	if !cancelled {
		captureWaitDiag(t, lifetime, capture, "Owner command completed; encrypted persistence confirmed.", "native archive command omitted its persistence receipt")
	}
}

func nativeArchiveApply(value string) []byte {
	return append([]byte(value), '\t', '\r')
}

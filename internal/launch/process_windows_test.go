package launch

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsBatchHarness(t *testing.T) {
	path := filepath.Join(t.TempDir(), "harness with spaces.cmd")
	if err := os.WriteFile(path, []byte("@echo off\r\necho %~1\r\nexit /b 7\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd, err := harnessCommand(context.Background(), []string{path, "-c"})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	err = cmd.Run()
	if err == nil || cmd.ProcessState.ExitCode() != 7 || !bytes.Contains(output.Bytes(), []byte("-c")) {
		t.Fatalf("incorrect batch launch: %q %v", output.String(), err)
	}
	for _, arg := range []string{"%PATH%", "!PATH!", "x&echo injected", "\"broken"} {
		if _, err := harnessCommand(context.Background(), []string{path, arg}); err == nil {
			t.Fatal("ambiguous batch argument was accepted")
		}
	}
}

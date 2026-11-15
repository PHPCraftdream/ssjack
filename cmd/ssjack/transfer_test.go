package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

func TestPrepareTransferAcceptsRoots(t *testing.T) {
	dir := realTempDir(t)
	vault := filepath.Join(realTempDir(t), "v.ktav")
	subA, subB := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	for _, sub := range []string{subA, subB} {
		if err := os.MkdirAll(sub, 0700); err != nil {
			t.Fatal(err)
		}
	}
	defaults := transfercore.DefaultLimits()
	options, err := prepareTransfer(vault, []string{subA, "named=" + subB}, defaults.MaxBytes, defaults.MaxEntries)
	if err != nil {
		t.Fatalf("prepareTransfer: %v", err)
	}
	if len(options.roots) != 2 || options.roots[0].Name() != "" || options.roots[1].Name() != "named" {
		t.Fatalf("unexpected roots: %q %q", options.roots[0].Name(), options.roots[1].Name())
	}
	if options.limits.MaxBytes != defaults.MaxBytes {
		t.Fatalf("limits.MaxBytes = %d, want %d", options.limits.MaxBytes, defaults.MaxBytes)
	}
	empty, err := prepareTransfer(vault, nil, defaults.MaxBytes, defaults.MaxEntries)
	if err != nil || len(empty.roots) != 0 || empty.limits.Validate() != nil {
		t.Fatalf("no-spec prepareTransfer: roots=%d limits=%v err=%v", len(empty.roots), empty.limits, err)
	}
}

func TestPrepareTransferRejectsDuplicateNames(t *testing.T) {
	dir := realTempDir(t)
	vault := filepath.Join(realTempDir(t), "v.ktav")
	subA, subB := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	for _, sub := range []string{subA, subB} {
		if err := os.MkdirAll(sub, 0700); err != nil {
			t.Fatal(err)
		}
	}
	defaults := transfercore.DefaultLimits()
	for _, specs := range [][]string{
		{"dup=" + subA, "dup=" + subB},
		{subA, subB},
	} {
		if _, err := prepareTransfer(vault, specs, defaults.MaxBytes, defaults.MaxEntries); err == nil || !strings.Contains(err.Error(), "duplicate transfer root name") {
			t.Fatalf("duplicate names accepted: %q => %v", specs, err)
		}
	}
}

func TestPrepareTransferRejectsVaultInsideRoot(t *testing.T) {
	subA := filepath.Join(realTempDir(t), "a")
	if err := os.MkdirAll(subA, 0700); err != nil {
		t.Fatal(err)
	}
	vault := filepath.Join(subA, "v.ktav")
	defaults := transfercore.DefaultLimits()
	if _, err := prepareTransfer(vault, []string{subA}, defaults.MaxBytes, defaults.MaxEntries); err == nil || !strings.Contains(err.Error(), "must not contain the vault") {
		t.Fatalf("vault inside root accepted: %v", err)
	}
}

func TestPrepareTransferValidatesLimits(t *testing.T) {
	subA := filepath.Join(realTempDir(t), "a")
	if err := os.MkdirAll(subA, 0700); err != nil {
		t.Fatal(err)
	}
	vault := filepath.Join(realTempDir(t), "v.ktav")
	defaults := transfercore.DefaultLimits()
	for _, tc := range []struct {
		name       string
		maxBytes   int64
		maxEntries int
	}{
		{"zero bytes", 0, defaults.MaxEntries},
		{"zero entries", defaults.MaxBytes, 0},
		{"negative entries", defaults.MaxBytes, -5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := prepareTransfer(vault, []string{subA}, tc.maxBytes, tc.maxEntries); err == nil || !strings.Contains(err.Error(), "transfer limits are invalid") {
				t.Fatalf("invalid limits accepted: %d %d => %v", tc.maxBytes, tc.maxEntries, err)
			}
		})
	}
}

func TestTransferFlagsRefusedOutsideFullMode(t *testing.T) {
	subA := filepath.Join(realTempDir(t), "a")
	if err := os.MkdirAll(subA, 0700); err != nil {
		t.Fatal(err)
	}
	vault := filepath.Join(realTempDir(t), "v.ktav")
	for _, args := range [][]string{
		{"--mode", "declarative", "--transfer-root", subA, "--vault", vault, "run", "driver"},
		{"--mode", "declarative", "--transfer-max-bytes", "100", "--vault", vault, "run", "driver"},
	} {
		code, err := run(context.Background(), args)
		if code == 0 || err == nil || !strings.Contains(err.Error(), "only available in full mode") {
			t.Fatalf("transfer flags accepted outside full mode: %q => %d %v", args, code, err)
		}
		if strings.Contains(err.Error(), subA) {
			t.Fatalf("refusal leaked the root path: %v", err)
		}
	}
}

func TestTransferRootParsedBeforeCredentials(t *testing.T) {
	subA := filepath.Join(realTempDir(t), "a")
	if err := os.MkdirAll(subA, 0700); err != nil {
		t.Fatal(err)
	}
	vault := filepath.Join(realTempDir(t), "v.ktav")
	markerErr := errors.New("credentials reached")
	credentialsCalled := false
	oldCredentials := cliLoadAgentCredentials
	cliLoadAgentCredentials = func(context.Context, string, string) (*agentCredentials, error) {
		credentialsCalled = true
		return nil, markerErr
	}
	defer func() { cliLoadAgentCredentials = oldCredentials }()
	code, err := run(context.Background(), []string{"--transfer-root", subA, "--vault", vault, "run", "harness"})
	if code != 1 || !errors.Is(err, markerErr) || !credentialsCalled {
		t.Fatalf("valid root did not reach credentials: %d %v (credentials=%v)", code, err, credentialsCalled)
	}
	credentialsCalled = false
	code, err = run(context.Background(), []string{"--transfer-root", "relative/dir", "--vault", vault, "run", "harness"})
	if code != 1 || err == nil || credentialsCalled {
		t.Fatalf("invalid root reached credentials: %d %v (credentials=%v)", code, err, credentialsCalled)
	}
	if !strings.Contains(err.Error(), "absolute") || strings.Contains(err.Error(), "relative/dir") {
		t.Fatalf("unexpected refusal message: %v", err)
	}
}

// realTempDir returns a temp directory with symlinks resolved; transfer roots
// refuse symlinked ancestors such as macOS /var.
func realTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

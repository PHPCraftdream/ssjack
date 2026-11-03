package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstoreentry"
)

func withInput(t *testing.T, fn func(string, bool) ([]byte, error)) {
	t.Helper()
	prior := appstoreReadInput
	appstoreReadInput = fn
	t.Cleanup(func() { appstoreReadInput = prior })
}

func TestSetupMismatch(t *testing.T) {
	if !appstoreentry.Supported() {
		t.Skip("appstore setup unsupported on this platform")
	}
	pub1 := base64.StdEncoding.EncodeToString(make([]byte, 32))
	pub2bytes := make([]byte, 32)
	pub2bytes[0] = 1
	pub2 := base64.StdEncoding.EncodeToString(pub2bytes)
	root := base64.StdEncoding.EncodeToString([]byte("arbitrary root DER"))
	chain := base64.StdEncoding.EncodeToString([]byte("arbitrary client DER"))
	cases := []struct {
		name  string
		input []string
		count int
	}{
		{"endpoint", []string{"https://anchor.invalid/anchor", "https://other.invalid/anchor"}, 2},
		{"store", []string{"https://anchor.invalid/anchor", "https://anchor.invalid/anchor", "00000000000000000000000000000001", "00000000000000000000000000000002"}, 4},
		{"signing key", []string{"https://anchor.invalid/anchor", "https://anchor.invalid/anchor", "00000000000000000000000000000001", "00000000000000000000000000000001", pub1, pub2}, 6},
		{"CA fingerprint", []string{"https://anchor.invalid/anchor", "https://anchor.invalid/anchor", "00000000000000000000000000000001", "00000000000000000000000000000001", pub1, pub1, root, chain, hex.EncodeToString(make([]byte, 32))}, 9},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "store")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			calls := 0
			withInput(t, func(string, bool) ([]byte, error) {
				calls++
				if calls > len(tc.input) {
					t.Fatal("unexpected secret/private/master prompt")
				}
				return []byte(tc.input[calls-1]), nil
			})
			code, _ := run(context.Background(), []string{"appstore", "setup", dir})
			if code != 1 || calls != tc.count {
				t.Fatalf("setup code=%d prompts=%d, want 1 and %d", code, calls, tc.count)
			}
			if _, err := os.Stat(filepath.Join(dir, "binding.bin")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("binding.bin exists or cannot be checked: %v", err)
			}
		})
	}
}

func TestSetupUnsupported(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux supports appstore")
	}
	if appstoreentry.Supported() {
		t.Fatal("expected unsupported platform")
	}
	calls := 0
	withInput(t, func(string, bool) ([]byte, error) { calls++; return []byte("fixture"), nil })
	code, err := run(context.Background(), []string{"appstore", "setup", t.TempDir()})
	if code == 0 || !errors.Is(err, appstoreentry.ErrUnsupported) || calls != 0 {
		t.Fatalf("setup=%d, %v; prompts=%d", code, err, calls)
	}
}

func TestSetupPromptErrorClearsInput(t *testing.T) {
	if !appstoreentry.Supported() {
		t.Skip("appstore setup unsupported on this platform")
	}
	buf := []byte("marker")
	withInput(t, func(string, bool) ([]byte, error) { return buf, errors.New("synthetic input error") })
	_, err := promptStoreField("fixture: ")
	if err == nil {
		t.Fatal("expected input error")
	}
	if string(buf) != "\x00\x00\x00\x00\x00\x00" {
		t.Fatalf("input buffer not cleared: %q", buf)
	}
}

func TestReadTerminalInputRejectsPipe(t *testing.T) {
	old := os.Stdin
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = reader
	t.Cleanup(func() { os.Stdin = old; reader.Close(); writer.Close() })
	got, err := readTerminalInput("", false)
	if err == nil || len(got) != 0 {
		t.Fatalf("pipe input=%q, err=%v", got, err)
	}
	if strings.Contains(err.Error(), "marker") {
		t.Fatal("unexpected sensitive output")
	}
	_, _ = io.WriteString(writer, "synthetic fixture")
}

func TestSetupCancelledBeforePrompt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	withInput(t, func(string, bool) ([]byte, error) { t.Fatal("cancelled setup prompted"); return nil, nil })
	code, err := run(ctx, []string{"appstore", "setup", t.TempDir()})
	if code == 0 || err == nil {
		t.Fatalf("cancelled setup accepted: %d %v", code, err)
	}
}

func TestWriterFailureIsReconcileOnly(t *testing.T) {
	cases := []struct {
		name  string
		cause error
		want  string
	}{
		{"pending", appstorecrypto.ErrWriterPending, "outcome pending"},
		{"pending wrapped", fmt.Errorf("synthetic sensitive marker: %w", appstorecrypto.ErrWriterPending), "outcome pending"},
		{"burned", appstorecrypto.ErrWriterBurned, "reservation burned"},
		{"burned wrapped", fmt.Errorf("synthetic sensitive marker: %w", appstorecrypto.ErrWriterBurned), "reservation burned"},
		{"rejected", appstorecrypto.ErrWriterRejected, "mutation rejected"},
		{"rejected wrapped", fmt.Errorf("synthetic sensitive marker: %w", appstorecrypto.ErrWriterRejected), "mutation rejected"},
		{"pointer lag", appstorecrypto.ErrWriterPointerLag, "pointer lag"},
		{"pointer lag wrapped", fmt.Errorf("synthetic sensitive marker: %w", appstorecrypto.ErrWriterPointerLag), "pointer lag"},
		{"unknown", errors.New("unknown failure"), "outcome uncertain"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := writerFailure(tc.cause).Error()
			if !strings.Contains(got, "reconcile") || !strings.Contains(got, tc.want) {
				t.Fatalf("writer failure %q lacks reconcile classification %q", got, tc.want)
			}
			for _, forbidden := range []string{"synthetic sensitive marker", "secret", "Ref"} {
				if strings.Contains(got, forbidden) {
					t.Fatalf("unsafe writer failure output contains %q: %q", forbidden, got)
				}
			}
			if strings.Contains(tc.name, "wrapped") && !errors.Is(tc.cause, wrappedSentinel(tc.name)) {
				t.Fatal("wrapped cause no longer matches its sentinel")
			}
		})
	}
}

func wrappedSentinel(name string) error {
	switch {
	case strings.HasPrefix(name, "pending"):
		return appstorecrypto.ErrWriterPending
	case strings.HasPrefix(name, "burned"):
		return appstorecrypto.ErrWriterBurned
	case strings.HasPrefix(name, "rejected"):
		return appstorecrypto.ErrWriterRejected
	default:
		return appstorecrypto.ErrWriterPointerLag
	}
}

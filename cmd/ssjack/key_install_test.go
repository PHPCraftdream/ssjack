package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func installFixture(t *testing.T) ([]byte, string) {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	encoded := ssh.MarshalAuthorizedKey(key)
	var output bytes.Buffer
	if err := writeKeyInstallInstructions(&output, encoded); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	start := strings.Index(text, "sh -eu <<'SSJACK_INSTALL_KEY'\n")
	if start < 0 {
		t.Fatal("missing installation command")
	}
	return encoded, text[start:]
}

func runInstallFixture(t *testing.T, home, command string, success bool) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX installation command executes in Linux/macOS CI")
	}
	cmd := exec.Command("sh", "-s")
	cmd.Env = append(os.Environ(), "HOME="+home)
	cmd.Stdin = strings.NewReader(command)
	output, err := cmd.CombinedOutput()
	if (err == nil) != success {
		t.Fatalf("installation success=%t: %v %s", success, err, output)
	}
}

func TestGeneratedInstallCommandPreservesKeysAndIsIdempotent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX installation command executes in Linux/macOS CI")
	}
	public, command := installFixture(t)
	old, _ := installFixture(t)
	home := t.TempDir()
	dir := filepath.Join(home, ".ssh")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "authorized_keys")
	previous := bytes.TrimSpace(old)
	if err := os.WriteFile(path, previous, 0600); err != nil {
		t.Fatal(err)
	}
	runInstallFixture(t, home, command, true)
	first, err := os.ReadFile(path)
	if err != nil || !bytes.HasPrefix(first, append(append([]byte(nil), previous...), '\n')) {
		t.Fatal("old key without final newline was changed or joined to the new key")
	}
	line := "restrict,pty " + strings.TrimSpace(string(public))
	if strings.Count(string(first), line) != 1 {
		t.Fatal("generated key not installed exactly once with PTY")
	}
	_, _, options, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil || strings.Join(options, ",") != "restrict,pty" {
		t.Fatal("SSH options do not allow PTY while retaining restrict")
	}
	runInstallFixture(t, home, command, true)
	second, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("repeated installation duplicated or changed keys")
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("authorized_keys is not private")
	}
	if _, err := os.Stat(filepath.Join(dir, ".ssjack-key-install.lock")); !os.IsNotExist(err) {
		t.Fatal("installation lock leaked")
	}
}

func TestGeneratedInstallCommandCreatesMissingSSHDirectory(t *testing.T) {
	public, command := installFixture(t)
	home := t.TempDir()
	runInstallFixture(t, home, command, true)
	data, err := os.ReadFile(filepath.Join(home, ".ssh", "authorized_keys"))
	if err != nil || !bytes.Contains(data, []byte("restrict,pty "+strings.TrimSpace(string(public)))) {
		t.Fatal("new authorized_keys missing")
	}
}

func TestGeneratedInstallCommandRejectsExistingRestrictions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX installation command executes in Linux/macOS CI")
	}
	public, command := installFixture(t)
	for _, options := range []string{"restrict", `restrict,command="echo fixed"`, `restrict,from="192.0.2.1"`} {
		home := t.TempDir()
		dir := filepath.Join(home, ".ssh")
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "authorized_keys")
		previous := []byte(options + " " + strings.TrimSpace(string(public)) + "\n")
		if err := os.WriteFile(path, previous, 0600); err != nil {
			t.Fatal(err)
		}
		runInstallFixture(t, home, command, false)
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, previous) {
			t.Fatal("existing restrictions were changed")
		}
	}
}

func TestGeneratedInstallCommandRejectsSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX symlink fixture")
	}
	_, command := installFixture(t)
	for _, linkedDirectory := range []bool{false, true} {
		home := t.TempDir()
		outside := t.TempDir()
		path := filepath.Join(outside, "authorized_keys")
		previous := []byte("untouched fixture\n")
		if err := os.WriteFile(path, previous, 0600); err != nil {
			t.Fatal(err)
		}
		if linkedDirectory {
			if err := os.Symlink(outside, filepath.Join(home, ".ssh")); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := os.Mkdir(filepath.Join(home, ".ssh"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(path, filepath.Join(home, ".ssh", "authorized_keys")); err != nil {
				t.Fatal(err)
			}
		}
		runInstallFixture(t, home, command, false)
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, previous) {
			t.Fatal("symlink target changed")
		}
	}
}

func TestGeneratedInstructionsRequireSuccessfulSave(t *testing.T) {
	public, _ := installFixture(t)
	failure := errors.New("injected encrypted-save failure")
	var output bytes.Buffer
	if err := saveProfileWithInstructions(context.Background(), func() error { return failure }, &output, public); !errors.Is(err, failure) || output.Len() != 0 {
		t.Fatal("instructions printed before encrypted save succeeded")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	if err := saveProfileWithInstructions(ctx, func() error { called = true; return nil }, &output, public); !errors.Is(err, context.Canceled) || called || output.Len() != 0 {
		t.Fatal("cancelled operation saved or printed a key")
	}
	saved := false
	if err := saveProfileWithInstructions(context.Background(), func() error { saved = true; return nil }, &output, public); err != nil || !saved {
		t.Fatal("successful save failed")
	}
	if !bytes.Contains(output.Bytes(), bytes.TrimSpace(public)) || bytes.Contains(output.Bytes(), []byte("PRIVATE KEY")) {
		t.Fatal("instructions omitted public key or exposed a private payload")
	}
}

func TestGeneratedProfileSyntaxAndCancellation(t *testing.T) {
	for _, args := range [][]string{{"add", "work", "--generate-key"}, {"add", "work"}} {
		if err := validateVaultArgs(args); err != nil {
			t.Fatalf("valid generation syntax: %v", err)
		}
	}
	for _, args := range [][]string{{"edit", "work", "--generate-key"}, {"add", "work", "--unknown"}, {"add", "work", "--generate-key", "extra"}} {
		if err := validateVaultArgs(args); err == nil {
			t.Fatal("invalid generation syntax accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, args := range [][]string{{"-p", "work", "add", "--generate-key"}, {"-p", "work", "vault", "init", "--generate-key"}} {
		code, err := run(ctx, args)
		if code == 0 || !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled generation prompted or saved: %v", err)
		}
	}
}

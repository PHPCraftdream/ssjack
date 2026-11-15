package remote

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestPOSIXKeyAdditionPreservesOldAccessAndRejectsOptions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX account script is exercised on Linux and macOS CI")
	}
	_, old := testSigner(t)
	_, next := testSigner(t)
	oldLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(old.PublicKey())))
	newLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(next.PublicKey())))
	for _, test := range []struct {
		name    string
		content string
		allowed bool
	}{
		{"bare-no-newline", oldLine, true},
		{"restricted", "restrict " + oldLine + "\n", false},
		{"forced-command", "command=\"echo restricted\" " + oldLine + "\n", false},
		{"restricted-new", oldLine + "\nfrom=\"127.0.0.1\" " + newLine + "\n", false},
		{"missing-old", "# no matching key\n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			directory := filepath.Join(home, ".ssh")
			if err := os.Mkdir(directory, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "authorized_keys")
			if err := os.WriteFile(path, []byte(test.content), 0600); err != nil {
				t.Fatal(err)
			}
			run := func() error {
				command := exec.Command("/bin/sh", "-c", authorizedKeyScript)
				command.Env = append(os.Environ(), "HOME="+home)
				command.Stdin = strings.NewReader(oldLine + "\n" + newLine + "\n")
				return command.Run()
			}
			err := run()
			if (err == nil) != test.allowed {
				t.Fatalf("key installation: allowed=%t error=%v", test.allowed, err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !test.allowed {
				if string(data) != test.content {
					t.Fatal("rejected rotation changed authorized_keys")
				}
				return
			}
			if !bytes.HasPrefix(data, []byte(test.content)) || !strings.Contains(string(data), "\n"+newLine+"\n") {
				t.Fatal("old key was removed or new key joined its final line")
			}
			if err := run(); err != nil {
				t.Fatal(err)
			}
			again, _ := os.ReadFile(path)
			if !bytes.Equal(data, again) {
				t.Fatal("retry duplicated the new key")
			}
		})
	}
}

func TestPOSIXKeyRetirementRemovesOnlyTheOldBareKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX account script is exercised on Linux and macOS CI")
	}
	_, old := testSigner(t)
	_, next := testSigner(t)
	_, other := testSigner(t)
	line := func(key ssh.PublicKey) string { return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))) }
	oldLine, newLine, otherLine := line(old.PublicKey()), line(next.PublicKey()), line(other.PublicKey())
	for _, test := range []struct {
		name    string
		content string
		want    string
		allowed bool
		backup  bool
	}{
		{"removes-old-keeps-others", "# managed\n" + otherLine + " other@host\n" + oldLine + " old@host\n" + newLine + "\n", "# managed\n" + otherLine + " other@host\n" + newLine + "\n", true, true},
		{"old-already-absent", otherLine + "\n" + newLine + "\n", otherLine + "\n" + newLine + "\n", true, false},
		{"new-missing", otherLine + "\n" + oldLine + "\n", otherLine + "\n" + oldLine + "\n", false, false},
		{"old-restricted", "restrict " + oldLine + "\n" + newLine + "\n", "restrict " + oldLine + "\n" + newLine + "\n", false, false},
		{"new-restricted", oldLine + "\nfrom=\"127.0.0.1\" " + newLine + "\n", oldLine + "\nfrom=\"127.0.0.1\" " + newLine + "\n", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			directory := filepath.Join(home, ".ssh")
			if err := os.Mkdir(directory, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "authorized_keys")
			if err := os.WriteFile(path, []byte(test.content), 0600); err != nil {
				t.Fatal(err)
			}
			run := func() error {
				command := exec.Command("/bin/sh", "-c", retireKeyScript)
				command.Env = append(os.Environ(), "HOME="+home)
				command.Stdin = strings.NewReader(oldLine + "\n" + newLine + "\n")
				return command.Run()
			}
			for attempt := 0; attempt < 2; attempt++ {
				if err := run(); (err == nil) != test.allowed {
					t.Fatalf("attempt %d: allowed=%t error=%v", attempt, test.allowed, err)
				}
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if string(data) != test.want {
					t.Fatalf("attempt %d: authorized_keys = %q, want %q", attempt, data, test.want)
				}
			}
			backup, err := os.ReadFile(path + ".ssjack-retired")
			if test.backup {
				if err != nil || string(backup) != test.content {
					t.Fatalf("pre-retirement copy = %q, %v", backup, err)
				}
			}
			entries, err := os.ReadDir(directory)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if entry.Name() == ".ssjack-rotate.lock" || strings.HasPrefix(entry.Name(), ".ssjack-retire.") {
					t.Fatalf("script left %q behind", entry.Name())
				}
			}
		})
	}
}

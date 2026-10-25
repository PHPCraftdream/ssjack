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

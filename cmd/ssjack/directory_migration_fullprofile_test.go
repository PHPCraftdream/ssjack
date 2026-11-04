//go:build linux && amd64

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func TestDirectoryMigrationPTYChild(t *testing.T) {
	if os.Getenv("SSJACK_MIGRATION_CLI_CHILD") != "1" {
		t.Skip("synthetic migration terminal child only")
	}
	var args []string
	for i, argument := range os.Args {
		if argument == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	code, err := run(ctx, args)
	if os.Getenv("SSJACK_MIGRATION_REFUSAL") == "1" {
		if code == 0 || err == nil {
			t.Fatal("cancelled migration did not refuse")
		}
	} else if code != 0 || err != nil {
		t.Fatal("confirmed migration CLI failed")
	}
}

func TestDirectoryMigrationCLIFullProfile(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("production KDF runs only in dedicated GitHub CI")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate synthetic migration identity")
	}
	defer clear(private)
	block, err := ssh.MarshalPrivateKey(private, "synthetic CLI migration identity")
	if err != nil {
		t.Fatal("encode synthetic migration identity")
	}
	defer clear(block.Bytes)
	host, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal("encode synthetic migration host pin")
	}
	v := vault.New()
	defer v.Close()
	if v.Version != 1 {
		t.Fatal("migration CLI fixture must start in the legacy schema")
	}
	v.Targets["key-account"] = vault.Target{Address: "example.invalid:22", User: "first", Usage: "human", PrivateKey: pem.EncodeToMemory(block), HostKeys: []string{string(ssh.MarshalAuthorizedKey(host))}}
	v.Targets["password-account"] = vault.Target{Address: "example.invalid:22", User: "second", Usage: "human", Password: []byte("synthetic migration SSH password"), HostKeys: []string{string(ssh.MarshalAuthorizedKey(host))}}
	password := []byte("synthetic migration database password")
	defer clear(password)
	parent := t.TempDir()
	source, destination := filepath.Join(parent, "original.ktav"), filepath.Join(parent, "directory.ktav")
	if err := vault.CreateWithRecords(ctx, source, v, password); err != nil {
		t.Fatal("create production-profile legacy fixture")
	}
	original, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	migrationTerminal(t, ctx, source, destination, password, true, v.Targets["password-account"].Password)
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatal("cancelled migration published a replacement")
	}
	unchanged, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(original, unchanged) {
		t.Fatal("cancelled migration changed its rollback source")
	}
	migrationTerminal(t, ctx, source, destination, password, false, v.Targets["password-account"].Password)
	migrated, err := vault.Load(destination, password)
	if err != nil {
		t.Fatal("reload migrated CLI fixture with the original password")
	}
	defer migrated.Close()
	if migrated.Version != 2 || len(migrated.Servers) != 2 || !reflect.DeepEqual(v.Targets, migrated.Targets) {
		t.Fatal("migration CLI lost credentials, settings or individual legacy profiles")
	}
	for name := range v.Targets {
		server, err := migrated.ServerID(name)
		if err != nil {
			t.Fatal("migration CLI lost a legacy server name")
		}
		profile, err := migrated.AccountProfile(server, "main")
		if err != nil || profile != name {
			t.Fatal("migration CLI changed stable credential identity")
		}
	}
	unchanged, err = os.ReadFile(source)
	if err != nil || !bytes.Equal(original, unchanged) {
		t.Fatal("confirmed migration changed its rollback source")
	}
	encoded, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range v.Targets {
		if len(target.PrivateKey) != 0 && bytes.Contains(encoded, target.PrivateKey) || len(target.Password) != 0 && bytes.Contains(encoded, target.Password) {
			t.Fatal("migration CLI persisted plaintext credentials")
		}
	}
}

func migrationTerminal(t *testing.T, parent context.Context, source, destination string, password []byte, refuse bool, values ...[]byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	defer cancel()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	prefix := []string{"-L", "ssjack-migrate-" + hex.EncodeToString(nonce[:]), "-f", "/dev/null"}
	environment := append(os.Environ(), "TERM=xterm-256color", "SSJACK_MIGRATION_CLI_CHILD=1", "SSJACK_MIGRATION_REFUSAL="+map[bool]string{false: "0", true: "1"}[refuse])
	tmux := func(args ...string) []byte {
		t.Helper()
		command := exec.CommandContext(ctx, "tmux", append(append([]string(nil), prefix...), args...)...)
		command.Env = environment
		output, err := command.Output()
		if err != nil {
			t.Fatal("synthetic migration terminal command failed")
		}
		return output
	}
	tmux("new-session", "-d", "-s", "migration", "-x", "120", "-y", "30", "sh", "-c", `stty -echo; exec "$@"`, "migration-cli", executable, "-test.run=^TestDirectoryMigrationPTYChild$", "--", "--vault", source, "vault", "migrate-directory", destination)
	pid, err := strconv.Atoi(strings.TrimSpace(string(tmux("display-message", "-p", "-t", "migration", "#{pid}"))))
	if err != nil || pid <= 1 {
		t.Fatal("invalid owned migration terminal identity")
	}
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		query := exec.CommandContext(cleanup, "tmux", append(append([]string(nil), prefix...), "display-message", "-p", "-t", "migration", "#{pid}")...)
		if output, err := query.Output(); err == nil && strings.TrimSpace(string(output)) == strconv.Itoa(pid) {
			process, err := os.FindProcess(pid)
			if err == nil {
				process.Kill()
			}
		}
	}()
	tmux("set-option", "-w", "-t", "migration", "remain-on-exit", "on")
	tmux("set-hook", "-g", "pane-died", "wait-for -S migrated")
	control := exec.CommandContext(ctx, "tmux", append(append([]string(nil), prefix...), "-C", "attach-session", "-t", "migration")...)
	control.Env = environment
	stdin, err := control.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := control.StdoutPipe()
	if err != nil {
		stdin.Close()
		t.Fatal(err)
	}
	if err := control.Start(); err != nil {
		stdin.Close()
		stdout.Close()
		t.Fatal(err)
	}
	events, ended := make(chan struct{}, 1), make(chan struct{})
	var transcript bytes.Buffer
	overflow := false
	go func() {
		defer close(ended)
		buffer := make([]byte, 32768)
		for {
			n, err := stdout.Read(buffer)
			if n != 0 {
				if transcript.Len()+n > 1<<20 {
					overflow = true
					return
				}
				transcript.Write(buffer[:n])
				select {
				case events <- struct{}{}:
				default:
				}
			}
			if err != nil {
				return
			}
		}
	}()
	var stopped sync.Once
	stop := func() { stopped.Do(func() { stdin.Close(); control.Process.Kill(); control.Wait(); <-ended }) }
	defer stop()
	protected := append([][]byte{password, []byte("OPENSSH PRIVATE KEY")}, values...)
	leaked := func(data []byte) bool {
		for _, value := range protected {
			if len(value) != 0 && bytes.Contains(data, value) {
				return true
			}
		}
		return false
	}
	screen := func() []byte {
		content := tmux("capture-pane", "-p", "-t", "migration")
		if leaked(content) {
			t.Fatal("migration terminal exposed private input")
		}
		return content
	}
	expect := func(text string) {
		t.Helper()
		for !bytes.Contains(screen(), []byte(text)) {
			select {
			case <-events:
			case <-ended:
				t.Fatal("migration terminal ended before phase:", text)
			case <-ctx.Done():
				t.Fatal("migration terminal timed out before phase:", text)
			}
		}
	}
	paste := func(value []byte) {
		command := exec.CommandContext(ctx, "tmux", append(append([]string(nil), prefix...), "load-buffer", "-")...)
		command.Stdin = bytes.NewReader(value)
		if err := command.Run(); err != nil {
			t.Fatal("write synthetic migration terminal input")
		}
		tmux("paste-buffer", "-d", "-t", "migration")
	}
	expect("Vault secret:")
	input := append(append([]byte(nil), password...), '\n')
	paste(input)
	clear(input)
	expect("Type MIGRATE DIRECTORY")
	phrase := []byte("MIGRATE DIRECTORY\n")
	if refuse {
		phrase = []byte("CANCEL\n")
	}
	paste(phrase)
	tmux("wait-for", "migrated")
	if status := strings.TrimSpace(string(tmux("display-message", "-p", "-t", "migration", "#{pane_dead_status}"))); status != "0" {
		t.Fatal("synthetic migration command did not finish as expected")
	}
	screen()
	stop()
	if overflow || leaked(transcript.Bytes()) {
		t.Fatal("migration transcript exceeded its bound or exposed private input")
	}
}

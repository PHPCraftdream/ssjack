//go:build linux

package transferremote

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

// linuxShRunner runs fixed command templates through a local `sh -c` inside a
// temp directory, byte-exact like the SSH StreamRunner it replaces.
func linuxShRunner() remote.StreamRunner {
	return func(ctx context.Context, target string, command string, stdin io.Reader, stdout io.Writer, stderr io.Writer) (int, error) {
		cmd := exec.CommandContext(ctx, "sh", "-c", command)
		if stdin != nil {
			cmd.Stdin = stdin
		}
		cmd.Stdout = stdout
		cmd.Stderr = stderr
		if err := cmd.Run(); err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				return exitErr.ExitCode(), nil
			}
			return -1, err
		}
		return 0, nil
	}
}

// linuxCountingRunner counts every command executed through the runner.
func linuxCountingRunner(count *int) remote.StreamRunner {
	inner := linuxShRunner()
	return func(ctx context.Context, target string, command string, stdin io.Reader, stdout io.Writer, stderr io.Writer) (int, error) {
		*count++
		return inner(ctx, target, command, stdin, stdout, stderr)
	}
}

// linuxTestError asserts err is a *transfercore.Error with the wanted class.
func linuxTestError(t *testing.T, err error, class transfercore.Class) *transfercore.Error {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error class %q, got nil", class)
	}
	var e *transfercore.Error
	if !errors.As(err, &e) {
		t.Fatalf("expected *transfercore.Error, got %T: %v", err, err)
	}
	if e.Class != class {
		t.Fatalf("expected error class %q, got %q (%v)", class, e.Class, err)
	}
	return e
}

func TestProbeLinux(t *testing.T) {
	// Other packages probe concurrently in the shared temp directory; the scan
	// below must only see this test's own scratch directory.
	t.Setenv("TMPDIR", t.TempDir())
	ctx := context.Background()
	r := New(linuxShRunner(), "t", transfercore.DefaultLimits())
	if err := r.Probe(ctx); err != nil {
		t.Fatalf("Probe against local sh failed: %v", err)
	}
	entries, err := os.ReadDir(os.TempDir())
	if err != nil {
		t.Fatalf("list temp dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), probePrefix) {
			t.Fatalf("probe left a scratch directory %q behind", e.Name())
		}
	}
}

func TestWriteFileRefusalsLinux(t *testing.T) {
	ctx := context.Background()
	count := 0
	r := New(linuxCountingRunner(&count), "t", transfercore.DefaultLimits())
	dir := t.TempDir()
	existing := dir + "/exists.bin"
	if err := os.WriteFile(existing, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed existing file: %v", err)
	}

	_, err := r.WriteFile(ctx, existing, strings.NewReader("y"), false)
	linuxTestError(t, err, transfercore.ClassExists)

	_, err = r.WriteFile(ctx, dir+"/missing-parent/child.bin", strings.NewReader("y"), false)
	linuxTestError(t, err, transfercore.ClassRemoteFailed)

	count = 0
	_, err = r.WriteFile(ctx, dir+"/a\tb", strings.NewReader("y"), false)
	linuxTestError(t, err, transfercore.ClassRefusedPath)

	if count != 0 {
		t.Fatalf("control-character path ran %d commands, want 0", count)
	}
}

func TestStagingLifecycleLinux(t *testing.T) {
	ctx := context.Background()
	run := linuxShRunner()
	r := New(run, "t", transfercore.DefaultLimits())
	parent := t.TempDir()

	staging, err := r.CreateStaging(ctx, parent)
	if err != nil {
		t.Fatalf("CreateStaging: %v", err)
	}
	name := strings.TrimPrefix(staging, parent+"/")
	if !validStagingName(name) {
		t.Fatalf("CreateStaging returned %q which is not a valid staging name", name)
	}
	info, err := os.Stat(staging)
	if err != nil {
		t.Fatalf("staging directory %s does not exist on disk: %v", staging, err)
	}
	if !info.IsDir() {
		t.Fatalf("staging path %s is not a directory", staging)
	}
	if mode := linuxModeOf(t, run, staging); mode != "700" {
		t.Fatalf("staging directory mode = %s, want 700", mode)
	}

	second, err := r.CreateStaging(ctx, parent)
	if err != nil {
		t.Fatalf("second CreateStaging: %v", err)
	}
	if second == staging {
		t.Fatalf("second CreateStaging returned the same name %q", staging)
	}
	if err := r.CleanupStaging(ctx, parent, strings.TrimPrefix(second, parent+"/")); err != nil {
		t.Fatalf("CleanupStaging(second): %v", err)
	}

	if err := r.CleanupStaging(ctx, parent, name); err != nil {
		t.Fatalf("CleanupStaging: %v", err)
	}
	if _, err := os.Stat(staging); !os.IsNotExist(err) {
		t.Fatalf("staging directory %s still exists after CleanupStaging: %v", staging, err)
	}
	if err := r.CleanupStaging(ctx, parent, name); err != nil {
		t.Fatalf("second CleanupStaging on absent staging failed: %v", err)
	}

	count := 0
	strict := New(linuxCountingRunner(&count), "t", transfercore.DefaultLimits())
	err = strict.CleanupStaging(ctx, parent, "not-a-staging-name")
	if err == nil {
		t.Fatal("CleanupStaging with a non-staging name succeeded, want ClassRefusedPath")
	}
	linuxTestError(t, err, transfercore.ClassRefusedPath)
	err = strict.CleanupStaging(ctx, parent, stagingPrefix+"0123456789abcdef")
	if err == nil {
		t.Fatal("CleanupStaging with a pattern-valid but never created name succeeded, want ClassRefusedPath")
	}
	linuxTestError(t, err, transfercore.ClassRefusedPath)
	if count != 0 {
		t.Fatalf("refused CleanupStaging calls ran %d commands, want 0", count)
	}

	missing := parent + "/does-not-exist"
	_, err = strict.CreateStaging(ctx, missing)
	linuxTestError(t, err, transfercore.ClassRefusedPath)

	// A regular file at a pattern-valid, job-created staging path is refused
	// on cleanup: the remote refuses non-directories.
	faked, err := r.CreateStaging(ctx, parent)
	if err != nil {
		t.Fatalf("CreateStaging for file-swap case: %v", err)
	}
	fakeName := strings.TrimPrefix(faked, parent+"/")
	if err := os.Remove(faked); err != nil {
		t.Fatalf("remove staging dir for file-swap case: %v", err)
	}
	if err := os.WriteFile(faked, []byte("not a dir"), 0o600); err != nil {
		t.Fatalf("write regular file at staging path: %v", err)
	}
	err = r.CleanupStaging(ctx, parent, fakeName)
	linuxTestError(t, err, transfercore.ClassRefusedPath)
	if code := linuxTestError(t, err, transfercore.ClassRefusedPath).ExitCode; code != exitRefusedPath {
		t.Fatalf("cleanup of a non-directory exited %d, want %d", code, exitRefusedPath)
	}
}

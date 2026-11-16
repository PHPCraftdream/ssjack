package transferremote

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

func TestProbe(t *testing.T) {
	f := &fakeRunner{respond: func(command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		_, err := io.WriteString(stdout, "SSJACK-CAPS sha256sum t gnu names\n")
		return 0, err
	}}
	if err := New(f.run, "t", sampleLimits()).Probe(context.Background()); err != nil {
		t.Fatalf("Probe = %v, want nil", err)
	}
	cmds := f.recorded()
	if len(cmds) != 1 {
		t.Fatalf("Probe ran %d commands, want 1", len(cmds))
	}
	for _, want := range []string{"set -eu", "command -v", "xargs -0", "mv -T", "SSJACK-CAPS"} {
		if !strings.Contains(cmds[0], want) {
			t.Errorf("probe command missing %q:\n%s", want, cmds[0])
		}
	}
	for _, c := range []testExitCase{
		{20, transfercore.ClassUnsupportedRemote},
		{127, transfercore.ClassUnsupportedRemote},
		{1, transfercore.ClassRemoteFailed},
	} {
		testExpectExit(t, c.code, func(f *fakeRunner) {
			err := New(f.run, "t", sampleLimits()).Probe(context.Background())
			expectClass(t, err, c.want)
			expectCode(t, err, c.code)
		})
	}
}

func TestCreateStaging(t *testing.T) {
	const parent = "/dest"
	f := &fakeRunner{}
	r := New(f.run, "t", sampleLimits())
	got, err := r.CreateStaging(context.Background(), parent)
	if err != nil {
		t.Fatalf("CreateStaging = %v, want nil", err)
	}
	name := strings.TrimPrefix(got, parent+"/")
	if !validStagingName(name) {
		t.Errorf("staging path %q has invalid name %q", got, name)
	}
	cmds := f.recorded()
	if len(cmds) != 1 {
		t.Fatalf("CreateStaging ran %d commands, want 1", len(cmds))
	}
	quotedIn(t, cmds[0], parent)
	for _, want := range []string{shellQuote(parent), "mkdir -m 700"} {
		if !strings.Contains(cmds[0], want) {
			t.Errorf("create command missing %q:\n%s", want, cmds[0])
		}
	}
	// Job ownership: CleanupStaging of the created name must run a command.
	if err := r.CleanupStaging(context.Background(), parent, name); err != nil {
		t.Fatalf("CleanupStaging after create = %v, want nil", err)
	}
	if got := len(f.recorded()); got != 2 {
		t.Errorf("%d commands after create+cleanup, want 2", got)
	}
	for _, c := range []testExitCase{
		{21, transfercore.ClassRefusedPath},
		{22, transfercore.ClassExists},
		{24, transfercore.ClassRemoteFailed},
	} {
		testExpectExit(t, c.code, func(f *fakeRunner) {
			_, err := New(f.run, "t", sampleLimits()).CreateStaging(context.Background(), parent)
			expectClass(t, err, c.want)
			expectCode(t, err, c.code)
		})
	}
}

func TestCleanupStaging(t *testing.T) {
	const parent = "/dest"
	name := stagingPrefix + "0123456789abcdef"

	for _, c := range []struct {
		name string
		msg  string
	}{
		{"evil", msgRefused},
		{name, msgNotJobOwned},
	} {
		f := &fakeRunner{}
		err := New(f.run, "t", sampleLimits()).CleanupStaging(context.Background(), parent, c.name)
		testWantErr(t, err, transfercore.ClassRefusedPath, c.msg, -1)
		if got := len(f.recorded()); got != 0 {
			t.Errorf("%s: %d commands run, want 0", c.name, got)
		}
	}

	f3 := &fakeRunner{}
	r3 := New(f3.run, "t", sampleLimits())
	path3, err := r3.CreateStaging(context.Background(), parent)
	if err != nil {
		t.Fatalf("CreateStaging: %v", err)
	}
	createdName := strings.TrimPrefix(path3, parent+"/")
	if err := r3.CleanupStaging(context.Background(), parent, createdName); err != nil {
		t.Fatalf("CleanupStaging = %v, want nil", err)
	}
	cmd := f3.recorded()[1]
	for _, want := range []string{"rm -rf", shellQuote(createdName), ".ssjack-transfer-*"} {
		if !strings.Contains(cmd, want) {
			t.Errorf("cleanup command missing %q:\n%s", want, cmd)
		}
	}
	for _, c := range []testExitCase{
		{21, transfercore.ClassRefusedPath},
		{24, transfercore.ClassRemoteFailed},
	} {
		testExpectExit(t, c.code, func(f *fakeRunner) {
			f.respond = nil
			r := New(f.run, "t", sampleLimits())
			path4, cerr := r.CreateStaging(context.Background(), parent)
			if cerr != nil {
				t.Fatalf("CreateStaging: %v", cerr)
			}
			f.respond = func(command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
				return c.code, nil
			}
			err := r.CleanupStaging(context.Background(), parent, strings.TrimPrefix(path4, parent+"/"))
			expectClass(t, err, c.want)
			expectCode(t, err, c.code)
		})
	}
}

func TestWriteFile(t *testing.T) {
	const dest = "/dest/a b'c$(d)"
	var drained []byte
	f := &fakeRunner{respond: func(command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		if stdin == nil {
			t.Errorf("WriteFile passed nil stdin")
			return 0, nil
		}
		drained = drainReader(t, stdin)
		return 0, nil
	}}
	n, err := New(f.run, "t", sampleLimits()).WriteFile(context.Background(), dest, strings.NewReader(string(testPayload)), false)
	if err != nil {
		t.Fatalf("WriteFile = %v, want nil", err)
	}
	if n != int64(len(testPayload)) || string(drained) != string(testPayload) {
		t.Errorf("WriteFile count %d / drained stdin differ from payload (want %d)", n, len(testPayload))
	}
	cmd := f.recorded()[0]
	quotedIn(t, cmd, dest)
	if !strings.Contains(cmd, "cat >") {
		t.Errorf("write command missing \"cat >\":\n%s", cmd)
	}
	for _, bad := range []string{"umask", "chmod"} {
		if strings.Contains(cmd, bad) {
			t.Errorf("non-executable write contains %q:\n%s", bad, cmd)
		}
	}
	f2 := &fakeRunner{}
	if _, err := New(f2.run, "t", sampleLimits()).WriteFile(context.Background(), dest, strings.NewReader("x"), true); err != nil {
		t.Fatalf("executable WriteFile = %v", err)
	}
	if !strings.Contains(f2.recorded()[0], "chmod +x") {
		t.Errorf("executable write missing `chmod +x`:\n%s", f2.recorded()[0])
	}
	for _, c := range []testExitCase{
		{22, transfercore.ClassExists},
		{24, transfercore.ClassRemoteFailed},
		{21, transfercore.ClassRefusedPath},
	} {
		testExpectExit(t, c.code, func(f *fakeRunner) {
			_, err := New(f.run, "t", sampleLimits()).WriteFile(context.Background(), dest, strings.NewReader("x"), false)
			expectClass(t, err, c.want)
			expectCode(t, err, c.code)
		})
	}
}

func TestStatFile(t *testing.T) {
	const dest = "/dest/f"
	sum := sha256.Sum256(testPayload)
	good := fmt.Sprintf("4096\n%s  %s\n", hex.EncodeToString(sum[:]), dest)

	f := &fakeRunner{respond: func(command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		fmt.Fprint(stdout, good)
		return 0, nil
	}}
	size, hash, err := New(f.run, "t", sampleLimits()).StatFile(context.Background(), dest)
	if err != nil {
		t.Fatalf("StatFile = %v, want nil", err)
	}
	if size != 4096 {
		t.Errorf("size = %d, want 4096", size)
	}
	if hash != sum {
		t.Errorf("hash = %x, want %x", hash, sum)
	}

	cases := []struct {
		name string
		out  string
	}{
		{"name mismatch", fmt.Sprintf("4096\n%s  /dest/other\n", hex.EncodeToString(sum[:]))},
		{"extra line", good + "extra\n"},
		{"missing newline", strings.TrimSuffix(good, "\n")},
	}
	for _, c := range cases {
		fc := &fakeRunner{respond: func(command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
			fmt.Fprint(stdout, c.out)
			return 0, nil
		}}
		_, _, err := New(fc.run, "t", sampleLimits()).StatFile(context.Background(), dest)
		testWantErr(t, err, transfercore.ClassIntegrity, "unexpected remote file listing", -1)
	}

	testExpectExit(t, 21, func(f *fakeRunner) {
		_, _, err := New(f.run, "t", sampleLimits()).StatFile(context.Background(), dest)
		testWantErr(t, err, transfercore.ClassRefusedPath, msgRefused, 21)
	})
}

func TestReadFile(t *testing.T) {
	const dest = "/dest/f"
	f := &fakeRunner{respond: func(command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		_, err := stdout.Write(testPayload)
		return 0, err
	}}
	var buf strings.Builder
	n, err := New(f.run, "t", sampleLimits()).ReadFile(context.Background(), dest, &buf)
	if err != nil {
		t.Fatalf("ReadFile = %v, want nil", err)
	}
	if n != int64(len(testPayload)) || buf.String() != string(testPayload) {
		t.Errorf("ReadFile count %d / output differ from payload (want %d)", n, len(testPayload))
	}
	for _, c := range []testExitCase{
		{21, transfercore.ClassRefusedPath},
		{24, transfercore.ClassRemoteFailed},
	} {
		testExpectExit(t, c.code, func(f *fakeRunner) {
			_, err := New(f.run, "t", sampleLimits()).ReadFile(context.Background(), dest, &strings.Builder{})
			expectClass(t, err, c.want)
			expectCode(t, err, c.code)
		})
	}
}

func TestTarInOut(t *testing.T) {
	const root = "/dest/tree"
	tarBytes := []byte("fake-tar-stream\x00bytes")
	f := &fakeRunner{respond: func(command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		_, err := stdout.Write(tarBytes)
		return 0, err
	}}
	var dst strings.Builder
	if err := New(f.run, "t", sampleLimits()).TarOut(context.Background(), root, &dst); err != nil {
		t.Fatalf("TarOut = %v, want nil", err)
	}
	cmd := f.recorded()[0]
	for _, want := range []string{"tar -c -f - .", shellQuote(root)} {
		if !strings.Contains(cmd, want) {
			t.Errorf("TarOut command missing %q:\n%s", want, cmd)
		}
	}
	if dst.String() != string(tarBytes) {
		t.Errorf("TarOut output differs from fake stream")
	}

	var drained []byte
	f2 := &fakeRunner{respond: func(command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		drained = drainReader(t, stdin)
		return 0, nil
	}}
	if err := New(f2.run, "t", sampleLimits()).TarIn(context.Background(), root, strings.NewReader(string(testPayload))); err != nil {
		t.Fatalf("TarIn = %v, want nil", err)
	}
	if string(drained) != string(testPayload) {
		t.Errorf("TarIn stdin differs from payload")
	}
	cmd2 := f2.recorded()[0]
	if !strings.Contains(cmd2, "tar -x --no-same-owner --no-same-permissions -f -") {
		t.Errorf("TarIn command missing flags:\n%s", cmd2)
	}
	for _, c := range []testExitCase{
		{21, transfercore.ClassRefusedPath},
		{24, transfercore.ClassRemoteFailed},
	} {
		testExpectExit(t, c.code, func(f *fakeRunner) {
			err := New(f.run, "t", sampleLimits()).TarIn(context.Background(), root, strings.NewReader("x"))
			expectClass(t, err, c.want)
			expectCode(t, err, c.code)
		})
	}
}

package transferremote

import (
	"context"
	"io"
	"path"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

const (
	testStaging = "/dest/.ssjack-transfer-0123456789abcdef"
	testDest    = "/dest/f"
)

func TestPublishFileNoOverwrite(t *testing.T) {
	f := &fakeRunner{respond: func(command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		if stdin != nil {
			t.Errorf("publish op got non-nil stdin")
		}
		return 0, nil
	}}
	if err := New(f.run, "t", sampleLimits()).PublishFile(context.Background(), testStaging, testDest, false); err != nil {
		t.Fatalf("PublishFile = %v, want nil", err)
	}
	cmd := f.recorded()[0]
	for _, want := range []string{`ln "$src" "$dst"`, `rm -f "$src"`, "mv -T"} {
		if !strings.Contains(cmd, want) {
			t.Errorf("publish command missing %q:\n%s", want, cmd)
		}
	}
	quotedIn(t, cmd, testStaging)
	quotedIn(t, cmd, testDest)

	for _, c := range []testExitCase{
		{22, transfercore.ClassExists},
		{24, transfercore.ClassRemoteFailed},
	} {
		fc := &fakeRunner{respond: func(command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
			return c.code, nil
		}}
		err := New(fc.run, "t", sampleLimits()).PublishFile(context.Background(), testStaging, testDest, false)
		expectClass(t, err, c.want)
		expectCode(t, err, c.code)
	}
}

func TestPublishFileOverwrite(t *testing.T) {
	f := &fakeRunner{}
	if err := New(f.run, "t", sampleLimits()).PublishFile(context.Background(), testStaging, testDest, true); err != nil {
		t.Fatalf("PublishFile overwrite = %v, want nil", err)
	}
	if !strings.Contains(f.recorded()[0], "mv -T -f") {
		t.Errorf("overwrite publish missing `mv -T -f`:\n%s", f.recorded()[0])
	}
	for _, c := range []testExitCase{
		{21, transfercore.ClassRefusedPath},
		{24, transfercore.ClassRemoteFailed},
	} {
		fc := &fakeRunner{respond: func(command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
			return c.code, nil
		}}
		err := New(fc.run, "t", sampleLimits()).PublishFile(context.Background(), testStaging, testDest, true)
		expectClass(t, err, c.want)
		expectCode(t, err, c.code)
	}
}

func TestPublishDirNoOverwrite(t *testing.T) {
	f := &fakeRunner{}
	if err := New(f.run, "t", sampleLimits()).PublishDir(context.Background(), testStaging, testDest, false); err != nil {
		t.Fatalf("PublishDir = %v, want nil", err)
	}
	cmd := f.recorded()[0]
	if !strings.Contains(cmd, "mv -T") {
		t.Errorf("dir publish missing `mv -T`:\n%s", cmd)
	}
	if strings.Contains(cmd, "ln") {
		t.Errorf("dir publish without overwrite must not use `ln`:\n%s", cmd)
	}
	for _, c := range []testExitCase{
		{22, transfercore.ClassExists},
		{24, transfercore.ClassRemoteFailed},
	} {
		fc := &fakeRunner{respond: func(command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
			return c.code, nil
		}}
		err := New(fc.run, "t", sampleLimits()).PublishDir(context.Background(), testStaging, testDest, false)
		expectClass(t, err, c.want)
		expectCode(t, err, c.code)
	}
}

// testAsideName extracts the quoted `old=` value from a dir-overwrite command
// and returns its final path component.
func testAsideName(t *testing.T, cmd string) string {
	t.Helper()
	i := strings.Index(cmd, "old='")
	if i < 0 {
		t.Fatalf("command has no old= quoted assignment:\n%s", cmd)
	}
	rest := cmd[i+len("old='"):]
	end := strings.Index(rest, "'")
	if end < 0 {
		t.Fatalf("unterminated old= quote:\n%s", cmd)
	}
	val := rest[:end]
	return val[strings.LastIndex(val, "/")+1:]
}

func TestPublishDirOverwrite(t *testing.T) {
	f := &fakeRunner{}
	if err := New(f.run, "t", sampleLimits()).PublishDir(context.Background(), testStaging, testDest, true); err != nil {
		t.Fatalf("PublishDir overwrite = %v, want nil", err)
	}
	cmd := f.recorded()[0]
	if got := strings.Count(cmd, "mv -T"); got != 4 {
		t.Errorf("dir overwrite has %d `mv -T` occurrences, want 4:\n%s", got, cmd)
	}
	if !strings.Contains(cmd, `rm -rf "$old"`) {
		t.Errorf("dir overwrite missing `rm -rf \"$old\"`:\n%s", cmd)
	}
	quotedIn(t, cmd, testStaging)
	quotedIn(t, cmd, testDest)
	aside := testAsideName(t, cmd)
	if !validStagingName(aside) {
		t.Errorf("aside name %q is not a valid staging name", aside)
	}

	// Registration: after a failed run the aside name must be cleanable.
	fFail := &fakeRunner{respond: func(command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		if strings.Contains(command, "mv -T") {
			return 24, nil
		}
		return 0, nil
	}}
	r := New(fFail.run, "t", sampleLimits())
	err := r.PublishDir(context.Background(), testStaging, testDest, true)
	testWantErr(t, err, transfercore.ClassRemoteFailed, msgRemoteFailed, 24)
	name := testAsideName(t, fFail.recorded()[0])
	if err := r.CleanupStaging(context.Background(), path.Dir(testDest), name); err != nil {
		t.Fatalf("CleanupStaging of registered aside name = %v, want nil", err)
	}
	if got := len(fFail.recorded()); got != 2 {
		t.Fatalf("%d commands after failed publish+cleanup, want 2", got)
	}
	if !strings.Contains(fFail.recorded()[1], shellQuote(name)) {
		t.Errorf("cleanup command missing quoted aside name %q:\n%s", name, fFail.recorded()[1])
	}

	for _, c := range []testExitCase{
		{21, transfercore.ClassRefusedPath},
		{22, transfercore.ClassExists},
		{24, transfercore.ClassRemoteFailed},
		{25, transfercore.ClassRemoteFailed},
	} {
		fc := &fakeRunner{respond: func(command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
			return c.code, nil
		}}
		err := New(fc.run, "t", sampleLimits()).PublishDir(context.Background(), testStaging, testDest, true)
		expectClass(t, err, c.want)
		expectCode(t, err, c.code)
	}
}

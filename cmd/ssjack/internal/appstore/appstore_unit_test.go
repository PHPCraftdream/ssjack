package appstore

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/testsupport/appanchor"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstoreentry"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/ownerfs"
)

func TestParseTextUnlockOptions(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		want    []string
		fd      int
		reverse bool
		enabled bool
		bad     bool
	}{
		{"hydrate", []string{"--text-mode", "hydrate", "--text-fd", "3", "harness", "-c"}, []string{"harness", "-c"}, 3, false, true, false},
		{"reverse", []string{"--text-mode", "reverse", "--text-fd", "1024", "harness"}, []string{"harness"}, 1024, true, true, false},
		{"ordinary", []string{"harness", "-c"}, []string{"harness", "-c"}, -1, false, false, false},
		{"no harness", []string{"--text-mode", "hydrate", "--text-fd", "3"}, nil, -1, false, true, true},
		{"bad mode", []string{"--text-mode", "other", "--text-fd", "3", "harness"}, nil, -1, false, true, true},
		{"bad descriptor", []string{"--text-mode", "hydrate", "--text-fd", "2", "harness"}, nil, -1, false, true, true},
		{"descriptor overflow", []string{"--text-mode", "reverse", "--text-fd", "1025", "harness"}, nil, -1, false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, fd, reverse, enabled, err := parseTextUnlock(tc.args)
			if (err != nil) != tc.bad || fd != tc.fd || reverse != tc.reverse || enabled != tc.enabled || len(got) != len(tc.want) {
				t.Fatalf("parseTextUnlock = %v,%d,%t,%t,%v", got, fd, reverse, enabled, err)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("arg[%d]=%q want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestAppstoreSetupRejectsMissingOrUnsafeDirectoryBeforePrompt(t *testing.T) {
	if !appstoreentry.Supported() {
		calls := 0
		old := appstoreReadInput
		appstoreReadInput = func(string, bool) ([]byte, error) { calls++; return []byte("secret"), nil }
		defer func() { appstoreReadInput = old }()
		if code, err := runAppstore(context.Background(), []string{"setup", t.TempDir()}); code == 0 || !errors.Is(err, appstoreentry.ErrUnsupported) || calls != 0 {
			t.Fatalf("unsupported setup = %d, %v; prompts=%d", code, err, calls)
		}
		return
	}
	calls := 0
	old := appstoreReadInput
	appstoreReadInput = func(string, bool) ([]byte, error) { calls++; return []byte("secret"), nil }
	defer func() { appstoreReadInput = old }()
	parent := t.TempDir()
	missing := filepath.Join(parent, "missing")
	if code, err := runAppstore(context.Background(), []string{"setup", missing}); code == 0 || err == nil {
		t.Fatalf("missing directory accepted: %d %v", code, err)
	}
	missingEntries, readErr := os.ReadDir(parent)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(missingEntries) != 0 || calls != 0 {
		t.Fatalf("missing directory prompted/created files: entries=%v prompts=%d", missingEntries, calls)
	}
	// A writable-by-group directory must be rejected before any secret prompt.
	unsafe := filepath.Join(parent, "unsafe")
	if err := os.Mkdir(unsafe, 0770); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0770); err != nil {
		t.Fatal(err)
	}
	if code, err := runAppstore(context.Background(), []string{"setup", unsafe}); code == 0 || err == nil {
		t.Fatalf("unsafe directory accepted: %d %v", code, err)
	}
	entries, readErr := os.ReadDir(unsafe)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 || calls != 0 {
		t.Fatalf("unsafe directory prompted/created files: entries=%v prompts=%d", entries, calls)
	}
}

func TestAppstoreSetupCancellationStopsBeforeInstallation(t *testing.T) {
	if !appstoreentry.Supported() {
		t.Skip("protected store unavailable on this platform")
	}
	dir := protectedStoreTestDirectory(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	code, err := runAppstoreSetup(ctx, dir)
	if code == 0 || err == nil {
		t.Fatalf("cancelled setup accepted: %d %v", code, err)
	}
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("cancelled setup created files: %v", entries)
	}
}

func TestAppstorePutMissingInstallationFailsWithoutSecret(t *testing.T) {
	if !appstoreentry.Supported() {
		calls := 0
		old := appstoreReadInput
		appstoreReadInput = func(string, bool) ([]byte, error) { calls++; return []byte("secret"), nil }
		defer func() { appstoreReadInput = old }()
		code, err := runAppstore(context.Background(), []string{"put", filepath.Join(t.TempDir(), "missing")})
		if code == 0 || !errors.Is(err, appstoreentry.ErrUnsupported) || calls != 0 {
			t.Fatalf("put = %d, %v; prompts=%d", code, err, calls)
		}
		return
	}
	dir := protectedStoreTestDirectory(t)
	code, err := runAppstore(context.Background(), []string{"put", dir})
	if code == 0 || !errors.Is(err, errAppstore) {
		t.Fatalf("missing installation: %d %v", code, err)
	}
}

func protectedStoreTestDirectory(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "store")
	root, err := ownerfs.MakeRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func CheckCanceledSecretDoesNotMutate(t *testing.T, run func(context.Context, []string) (int, error)) {
	if os.Getenv("SSJACK_TEST_SCOPED_KDF") != "1" {
		t.Skip("private scoped acceptance only")
	}
	f := newAppstoreReplayFixture(t)
	before := f.Accepted.Load()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var prompts atomic.Int64
	old := appstoreReadInput
	appstoreReadInput = func(_ string, _ bool) ([]byte, error) {
		switch prompts.Add(1) {
		case 1:
			return []byte(f.Master), nil
		case 2:
			cancel()
			return []byte(f.Secret), nil
		default:
			t.Fatal("unexpected additional input prompt")
			return nil, os.ErrClosed
		}
	}
	defer func() { appstoreReadInput = old }()
	out, stderr, code, err := captureAppstoreOutput(t, func() (int, error) {
		return run(ctx, []string{"appstore", "put", f.Dir})
	})
	if code == 0 || err == nil {
		t.Fatalf("canceled secret collection accepted: %d %v", code, err)
	}
	if got := prompts.Load(); got != 2 {
		t.Fatalf("input prompts=%d, want 2", got)
	}
	noSecretOutput(t, out+stderr, f.Master, f.Secret)
	state := f.AnchorState(t)
	if state.Sequence() != 0 || state.JournalCount() != 0 {
		t.Fatalf("canceled secret collection changed anchor: sequence=%d journal=%d", state.Sequence(), state.JournalCount())
	}
	if got := f.Accepted.Load() - before; got != 1 {
		t.Fatalf("accepted requests=%d, want initial CLI read only (1)", got)
	}
}

func CheckLostCommitAckNoBlindReplay(t *testing.T, run func(context.Context, []string) (int, error)) {
	if os.Getenv("SSJACK_TEST_SCOPED_KDF") != "1" {
		t.Skip("private scoped acceptance only")
	}
	f := newAppstoreReplayFixture(t)
	before := f.Accepted.Load()
	f.Drop.Store(true)
	f.DenyRead.Store(true)
	restore := replayInput([]byte(f.Master), []byte(f.Secret))
	out, stderr, code, err := captureAppstoreOutput(t, func() (int, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return run(ctx, []string{"appstore", "put", f.Dir})
	})
	restore()
	if code == 0 || err == nil {
		t.Fatalf("unreconciled lost acknowledgement succeeded: %d %v", code, err)
	}
	if !f.Dropped.Load() {
		t.Fatal("service did not drop the committed response")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "inspect") && !strings.Contains(strings.ToLower(err.Error()), "reconcile") {
		t.Fatalf("error does not describe inspection/reconciliation: %v", err)
	}
	noSecretOutput(t, out+stderr, f.Master, f.Secret)
	if strings.TrimSpace(out) != "" || strings.Contains(out, "$ssjack") {
		t.Fatalf("uncertain mutation emitted stdout: %q", out)
	}
	state := f.AnchorState(t)
	if state.Sequence() != 1 || state.JournalCount() != 1 {
		t.Fatalf("lost acknowledgement state: sequence=%d journal=%d", state.Sequence(), state.JournalCount())
	}
	if got := f.Accepted.Load() - before; got != 7 {
		t.Fatalf("connections=%d, want CLI read, writer read, reservation reconciliation read, reserve plus confirmation read, commit plus reconciliation read (7)", got)
	}

	f.DenyRead.Store(false)
	before = f.Accepted.Load()
	oldSecond := appstoreReadInput
	var secondPrompts atomic.Int64
	appstoreReadInput = func(_ string, _ bool) ([]byte, error) {
		if secondPrompts.Add(1) == 1 {
			return []byte(f.Master), nil
		}
		t.Fatal("unexpected additional input prompt")
		return nil, os.ErrClosed
	}
	defer func() { appstoreReadInput = oldSecond }()
	out, stderr, code, err = captureAppstoreOutput(t, func() (int, error) {
		return run(context.Background(), []string{"appstore", "put", f.Dir})
	})
	if code == 0 || err == nil {
		t.Fatalf("second first-entry put unexpectedly succeeded: %d %v", code, err)
	}
	noSecretOutput(t, out+stderr, f.Master, f.Secret)
	if got := f.Accepted.Load() - before; got != 1 {
		t.Fatalf("second invocation accepted requests=%d, want read-only preflight (1)", got)
	}
	state = f.AnchorState(t)
	if state.Sequence() != 1 || state.JournalCount() != 1 {
		t.Fatalf("second invocation changed committed state: sequence=%d journal=%d", state.Sequence(), state.JournalCount())
	}
}

func CheckLostCommitAckReconcilesWithoutReplay(t *testing.T, run func(context.Context, []string) (int, error)) {
	if os.Getenv("SSJACK_TEST_SCOPED_KDF") != "1" {
		t.Skip("private scoped acceptance only")
	}
	f := newAppstoreReplayFixture(t)
	before := f.Accepted.Load()
	f.Drop.Store(true)
	f.DenyRead.Store(false)
	var calls int
	old := appstoreReadInput
	appstoreReadInput = func(_ string, _ bool) ([]byte, error) {
		calls++
		switch calls {
		case 1:
			return []byte(f.Master), nil
		case 2:
			return []byte(f.Secret), nil
		default:
			t.Fatal("unexpected additional input prompt")
			return nil, os.ErrClosed
		}
	}
	defer func() { appstoreReadInput = old }()
	out, stderr, code, err := captureAppstoreOutput(t, func() (int, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return run(ctx, []string{"appstore", "put", f.Dir})
	})
	if code != 0 || err != nil {
		t.Fatalf("reconciled lost acknowledgement failed: code=%d err=%v", code, err)
	}
	if !f.Dropped.Load() {
		t.Fatal("service did not drop the committed response")
	}
	if calls != 2 {
		t.Fatalf("input prompts=%d, want exactly 2", calls)
	}
	noSecretOutput(t, out+stderr, f.Master, f.Secret)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 || lines[1] != "sequence=1 revision=1" {
		t.Fatalf("unexpected safe CLI result: %q", out)
	}
	ref, err := appstoreplaceholder.Parse([]byte(lines[0]))
	if err != nil {
		t.Fatalf("invalid exact placeholder: %v", err)
	}
	state := f.AnchorState(t)
	if state.Sequence() != 1 || state.JournalCount() != 1 {
		t.Fatalf("reconciled lost acknowledgement state: sequence=%d journal=%d", state.Sequence(), state.JournalCount())
	}
	if !ref.Valid() || ref.StoreID() != f.Store || ref.SnapshotID() != state.CommittedSnapshotID() || ref.SnapshotID() == ([16]byte{}) {
		t.Fatalf("placeholder reference mismatch: store=%v snapshot=%v committed=%v", ref.StoreID(), ref.SnapshotID(), state.CommittedSnapshotID())
	}
	if got := f.Accepted.Load() - before; got != 7 {
		t.Fatalf("connections=%d, want CLI read, writer read, reservation reconciliation read, reserve plus confirmation read, commit plus reconciliation read (7)", got)
	}
}

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
			dir := protectedStoreTestDirectory(t)
			calls := 0
			withInput(t, func(string, bool) ([]byte, error) {
				calls++
				if calls > len(tc.input) {
					t.Fatal("unexpected secret/private/master prompt")
				}
				return []byte(tc.input[calls-1]), nil
			})
			code, _ := runAppstore(context.Background(), []string{"setup", dir})
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
	if appstoreentry.Supported() {
		t.Skip("protected store is supported on this platform")
	}
	calls := 0
	withInput(t, func(string, bool) ([]byte, error) { calls++; return []byte("fixture"), nil })
	code, err := runAppstore(context.Background(), []string{"setup", t.TempDir()})
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
	code, err := runAppstore(ctx, []string{"setup", t.TempDir()})
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

func captureAppstoreOutput(t *testing.T, runFn func() (int, error)) (stdout, stderr string, code int, err error) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	outR, outW, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	errR, errW, e := os.Pipe()
	if e != nil {
		_ = outR.Close()
		_ = outW.Close()
		t.Fatal(e)
	}
	restored := false
	restore := func() {
		if !restored {
			os.Stdout, os.Stderr = oldOut, oldErr
			restored = true
		}
	}
	t.Cleanup(restore)
	os.Stdout = outW
	os.Stderr = errW
	code, err = runFn()
	_ = outW.Close()
	_ = errW.Close()
	restore()
	var outBuffer, errBuffer bytes.Buffer
	_, _ = outBuffer.ReadFrom(outR)
	_, _ = errBuffer.ReadFrom(errR)
	_ = outR.Close()
	_ = errR.Close()
	return outBuffer.String(), errBuffer.String(), code, err
}

type appstoreReplayFixture = appanchor.Fixture

func newAppstoreReplayFixture(t *testing.T) *appstoreReplayFixture {
	t.Helper()
	f := appanchor.New(t)
	private, e := x509.MarshalPKCS8PrivateKey(f.Client.PrivateKey)
	if e != nil {
		t.Fatal(e)
	}
	store, e := appstoreentry.Open(f.Dir)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	dev, ino, e := store.Identity()
	if e != nil {
		t.Fatal(e)
	}
	h, e := makeInstallationHeader(f.Store)
	if e != nil {
		t.Fatal(e)
	}
	installctx, installcancel := context.WithTimeout(context.Background(), 60*time.Second)
	encoded, e := appstorecrypto.NewInstallation(installctx, h, []byte(f.Master), appstorecrypto.Binding{Endpoint: f.Endpoint, RootsDER: [][]byte{f.CADER}, CertificateDER: f.Client.Certificate, PrivateDER: private, ServiceKey: f.ServiceKey, Header: h, DirectoryDev: dev, DirectoryIno: ino})
	installcancel()
	clear(private)
	if e != nil {
		t.Fatal(e)
	}
	if e = store.Install(encoded); e != nil {
		t.Fatal(e)
	}
	clear(encoded)
	return f
}

func noSecretOutput(t *testing.T, s string, secrets ...string) {
	t.Helper()
	for _, v := range secrets {
		if v != "" && strings.Contains(s, v) {
			t.Fatal("CLI disclosed secret")
		}
	}
}

func replayInput(values ...[]byte) func() {
	prior := appstoreReadInput
	i := 0
	appstoreReadInput = func(string, bool) ([]byte, error) {
		if i >= len(values) {
			return nil, os.ErrClosed
		}
		v := append([]byte(nil), values[i]...)
		i++
		return v, nil
	}
	return func() { appstoreReadInput = prior }
}

func SetPromptInputForTest(fn func(prompt string, allowEmpty bool) ([]byte, error)) (restore func()) {
	prior := appstoreReadInput
	appstoreReadInput = fn
	return func() { appstoreReadInput = prior }
}

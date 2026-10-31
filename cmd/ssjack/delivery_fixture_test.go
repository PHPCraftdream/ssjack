package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstoreentry"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
)

type deliveryFixture struct {
	anchor     *appstoreReplayFixture
	store, cli string
}

func newDeliveryFixture(t *testing.T) *deliveryFixture {
	t.Helper()
	if os.Getenv("SSJACK_PUBLIC_CI") != "1" {
		t.Skip("public-CI fixture")
	}
	if !appstoreentry.Supported() {
		t.Skip("Linux appstore acceptance")
	}
	cli := os.Getenv("SSJACK_DELIVERY_CLI")
	if cli == "" {
		t.Fatal("SSJACK_DELIVERY_CLI is required")
	}
	f := newAppstoreReplayFixtureMode(t, false)
	parent, e := os.MkdirTemp("/tmp", "ssjack-delivery-")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(parent, 0755); e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(parent, "store")
	if e = os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.Chown(dir, 65534, 65534); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = os.RemoveAll(parent) })
	f.dir = dir
	return &deliveryFixture{anchor: f, store: dir, cli: cli}
}

type deliveryAnswer struct {
	Prompt string `json:"prompt"`
	Answer []byte `json:"answer"`
}

type deliveryCLIResult struct {
	ExitCode        int    `json:"exit_code"`
	PromptsAnswered int    `json:"prompts_answered"`
	Refusal         string `json:"refusal"`
	Stdout          string `json:"stdout"`
}
type deliveryCLIRefusal struct{ Class, Code string }

func (e *deliveryCLIRefusal) Error() string { return "delivery CLI authority refusal" }

func (f *deliveryFixture) tryDeliveryCLIAs(t *testing.T, uid int, answers []deliveryAnswer, args ...string) (string, error) {
	t.Helper()
	payloadAnswers := make([]struct {
		Prompt string `json:"prompt"`
		Answer string `json:"answer"`
	}, len(answers))
	for i, a := range answers {
		payloadAnswers[i].Prompt = a.Prompt
		payloadAnswers[i].Answer = base64.StdEncoding.EncodeToString(append([]byte(nil), a.Answer...))
	}
	payload, err := json.Marshal(payloadAnswers)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(payload)
	helper, err := filepath.Abs(filepath.Join("..", "..", "scripts", "ci", "delivery_pty.py"))
	if err != nil {
		return "", errors.New("delivery helper path unavailable")
	}
	workspace, err := os.MkdirTemp("/tmp", "ssjack-delivery-project-")
	if err != nil {
		return "", errors.New("delivery workspace creation failed")
	}
	defer os.RemoveAll(workspace)
	if err := os.Chown(workspace, uid, uid); err != nil {
		return "", errors.New("delivery workspace ownership failed")
	}
	cmd := exec.Command("python3", append([]string{helper, f.cli}, args...)...)
	cmd.Dir = workspace
	cmd.Env = append(os.Environ(), "SSJACK_DELIVERY_UID="+strconv.Itoa(uid))
	cmd.Stdin = bytes.NewReader(payload)
	out, err := cmd.Output()
	if err != nil {
		clear(out)
		var exit *exec.ExitError
		if len(args) >= 2 && errors.As(err, &exit) {
			return "", fmt.Errorf("delivery helper command=%s/%s exit=%d", args[0], args[1], exit.ExitCode())
		}
		return "", errors.New("delivery PTY infrastructure failure")
	}
	defer clear(out)
	var result deliveryCLIResult
	dec := json.NewDecoder(bytes.NewReader(out))
	dec.DisallowUnknownFields()
	if dec.Decode(&result) != nil || result.ExitCode < 0 || result.PromptsAnswered < 0 || result.PromptsAnswered > len(answers) || len(result.Stdout) > 65536 {
		return "", errors.New("invalid delivery PTY result")
	}
	if dec.Decode(new(any)) != io.EOF {
		return "", errors.New("invalid delivery PTY result")
	}
	for _, secret := range []string{f.anchor.master, f.anchor.secret} {
		if secret != "" && (strings.Contains(result.Stdout, secret) || strings.Contains(string(out), secret)) {
			clear([]byte(result.Stdout))
			return "", errors.New("CLI disclosed secret")
		}
	}
	if encoded := base64.StdEncoding.EncodeToString(f.anchor.privateDER); encoded != "" && strings.Contains(result.Stdout, encoded) {
		return "", errors.New("CLI disclosed private key")
	}
	allowed := map[string]string{"no active delivery grant": "no-active-grant", "no unique active delivery grant": "no-unique-active-grant", "application-store setup failed": "application-store-setup", "invalid declarative slice request": "invalid-slice-request", "declarative authority unavailable or invalid": "authority-unavailable"}
	if result.Refusal != "" {
		if _, ok := allowed[result.Refusal]; !ok || result.ExitCode == 0 || result.PromptsAnswered < 1 {
			return "", errors.New("unclassified delivery CLI result")
		}
		return result.Stdout, &deliveryCLIRefusal{Class: "authority", Code: allowed[result.Refusal]}
	}
	if result.ExitCode != 0 {
		return "", errors.New("delivery CLI child failed")
	}
	if result.PromptsAnswered != len(answers) {
		return "", errors.New("delivery CLI did not answer all prompts")
	}
	return result.Stdout, nil
}
func (f *deliveryFixture) requireDeliveryRefusal(t *testing.T, err error, code string) {
	t.Helper()
	var refusal *deliveryCLIRefusal
	if !errors.As(err, &refusal) || refusal.Class != "authority" || refusal.Code != code {
		t.Fatalf("expected typed authority refusal %q", code)
	}
}

func (f *deliveryFixture) runDeliveryCLIAs(t *testing.T, uid int, answers []deliveryAnswer, args ...string) string {
	t.Helper()
	out, err := f.tryDeliveryCLIAs(t, uid, answers, args...)
	if err != nil {
		t.Fatalf("delivery CLI helper failed: %v", err)
	}
	return out
}
func (f *deliveryFixture) runDeliveryCLI(t *testing.T, answers []deliveryAnswer, args ...string) string {
	return f.runDeliveryCLIAs(t, 65534, answers, args...)
}
func (f *deliveryFixture) setupAndPut(t *testing.T) string {
	t.Helper()
	a := f.anchor
	hexStore := hex.EncodeToString(a.store[:])
	b64 := func(b []byte) []byte { return []byte(base64.StdEncoding.EncodeToString(b)) }
	sum := func(b []byte) []byte { x := sha256.Sum256(b); return []byte(hex.EncodeToString(x[:])) }
	chain := make([]string, len(a.clientChain))
	for i, der := range a.clientChain {
		chain[i] = base64.StdEncoding.EncodeToString(der)
	}
	ans := []deliveryAnswer{{"Exact HTTPS anchor endpoint: ", []byte(a.endpoint)}, {"Repeat exact endpoint from independent source: ", []byte(a.endpoint)}, {"Existing storeID (32 hex characters): ", []byte(hexStore)}, {"Repeat exact storeID from independent source: ", []byte(hexStore)}, {"Anchor signing public key raw 32-byte base64: ", b64(a.serviceKey)}, {"Repeat signing public key from independent source: ", b64(a.serviceKey)}, {"CA certificate DER base64 (one root only): ", b64(a.caDER)}, {"Client certificate chain DER base64 (leaf first, max 8): ", []byte(strings.Join(chain, ","))}, {"CA SHA256 fingerprint from independent source: ", sum(a.caDER)}, {"Client leaf SHA256 fingerprint from independent source: ", sum(a.clientChain[0])}, {"Client PKCS#8 private key DER base64: ", b64(a.privateDER)}, {"New application-store master secret: ", []byte(a.master)}, {"Confirm application-store master secret: ", []byte(a.master)}}
	out := f.runDeliveryCLI(t, ans, "appstore", "setup", f.store)
	answers := []deliveryAnswer{{"Application-store master secret: ", []byte(a.master)}, {"Secret (max 16 KiB): ", []byte("scoped secret")}}
	out = f.runDeliveryCLI(t, answers, "appstore", "put", f.store)
	line := strings.SplitN(out, "\n", 2)[0]
	ref, err := appstoreplaceholder.Parse([]byte(line))
	if err != nil || !ref.Valid() {
		t.Fatalf("invalid emitted reference: %v", err)
	}
	return string(line)
}

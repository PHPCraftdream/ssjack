//go:build linux && amd64

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
)

const (
	cliPath        = "/lab/ssjack"
	driverSource   = "/lab/driver"
	consumerSource = "/lab/consumer"
	harnessPath    = "/lab/harness"
	ptyPath        = "/lab/delivery_pty.py"
	labUID         = 65534
)

type labAnswer struct {
	Prompt string `json:"prompt"`
	Answer []byte `json:"answer"`
}
type labResult struct {
	ExitCode        int    `json:"exit_code"`
	PromptsAnswered int    `json:"prompts_answered"`
	Refusal         string `json:"refusal"`
	Stdout          string `json:"stdout"`
}
type labRefusal struct{ Code string }

func (e *labRefusal) Error() string { return "typed synthetic CLI refusal" }

type deliveryLab struct {
	anchor                                              *syntheticAnchor
	master, payload                                     []byte
	ref, root, workspace, installationHash, encodedHash string
}

func runStandaloneLab() (err error) {
	if os.Geteuid() != 0 {
		return errors.New("synthetic lab unavailable")
	}
	marker, e := os.Lstat("/lab/isolation-ok")
	if e != nil || !marker.Mode().IsRegular() {
		return errors.New("synthetic lab unavailable")
	}
	for _, p := range []string{cliPath, driverSource, consumerSource, harnessPath, ptyPath, "/lab/conductor"} {
		if _, e = os.Stat(p); e != nil {
			return errors.New("synthetic lab unavailable")
		}
	}
	l := &deliveryLab{}
	defer func() {
		if l.anchor != nil {
			_ = l.anchor.Close()
		}
		clear(l.master)
		clear(l.payload)
		if l.workspace != "" {
			_ = os.RemoveAll(l.workspace)
		}
	}()
	l.anchor, err = newSyntheticAnchor()
	if err != nil {
		return errors.New("synthetic lab setup failed")
	}
	random := make([]byte, 32)
	if _, err = rand.Read(random); err != nil {
		clear(random)
		return errors.New("synthetic lab setup failed")
	}
	l.master = []byte(hex.EncodeToString(random))
	clear(random)
	l.payload = []byte("scoped secret")
	if err = l.provision(); err != nil {
		return errors.New("synthetic lab setup failed")
	}
	if err = l.storeSetup(); err != nil {
		return errors.New("synthetic lab setup failed")
	}
	if err = l.scanCiphertext(); err != nil {
		return errors.New("synthetic lab ciphertext check failed")
	}
	fields, err := l.inspect()
	if err != nil {
		return errors.New("synthetic lab inspect failed")
	}
	if err = l.register(fields); err != nil {
		return errors.New("synthetic lab registration failed")
	}
	state := filepath.Join(declarativeauthority.StatePath, "state.json")
	if err = declarativeauthority.PrepareState(labUID); err != nil {
		return errors.New("synthetic state provisioning failed")
	}
	if err = l.resetGenesis(state); err != nil {
		return errors.New("synthetic genesis setup failed")
	}
	receiptPath := filepath.Join(declarativeauthority.StatePath, "consumer-receipt")
	if _, e = os.Lstat(receiptPath); !errors.Is(e, os.ErrNotExist) {
		return errors.New("receipt was not fresh")
	}
	answers := []labAnswer{{"Exact canonical delivery reference: ", []byte(l.ref)}, {"Application-store master secret: ", l.master}}
	out, err := l.cli(labUID, answers, "appstore", "unlock", harnessPath, l.ref, "golden")
	if err != nil || !strings.Contains(out, "DELIVERY_ACCEPTANCE_OK") {
		return errors.New("positive delivery failed")
	}
	receipt, e := os.ReadFile(receiptPath)
	if e != nil || !validReceipt(receipt) {
		return errors.New("positive receipt invalid")
	}
	if e = ensureOwnerMode(receiptPath, uint32(labUID), 0600); e != nil {
		return errors.New("receipt metadata invalid")
	}
	if err = l.verifyPositiveState(state); err != nil {
		return errors.New("positive state invalid")
	}
	if err = l.revoke(); err != nil {
		return errors.New("revocation failed")
	}
	beforeState, e := os.ReadFile(state)
	if e != nil {
		return errors.New("state read failed")
	}
	beforeReceipt, e := os.ReadFile(receiptPath)
	if e != nil {
		return errors.New("receipt read failed")
	}
	_, denied := l.cli(labUID, answers, "appstore", "unlock", harnessPath, l.ref, "golden")
	var refusal *labRefusal
	if !errors.As(denied, &refusal) || refusal.Code != "no-unique-active-grant" {
		return errors.New("typed revocation denial missing")
	}
	afterState, e := os.ReadFile(state)
	if e != nil {
		return errors.New("state read failed")
	}
	afterReceipt, e := os.ReadFile(receiptPath)
	if e != nil || !bytes.Equal(beforeState, afterState) || !bytes.Equal(beforeReceipt, afterReceipt) {
		return errors.New("denial changed state")
	}
	return l.metadata()
}
func (l *deliveryLab) provision() error {
	var err error
	for _, d := range []string{"/usr/libexec", "/etc/ssjack/declarative", "/var/lib/ssjack"} {
		if err = os.MkdirAll(d, 0755); err != nil {
			return err
		}
		if err = os.Chmod(d, 0755); err != nil {
			return err
		}
	}
	setup := filepath.Join(declarativeauthority.RegistryPath, declarativeauthority.SetupName)
	if _, err = os.Stat(setup); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if _, err = l.cli(0, []labAnswer{{"Type SETUP DECLARATIVE SYNTHETIC METADATA ONLY: ", []byte("SETUP DECLARATIVE SYNTHETIC METADATA ONLY")}}, "declarative", "setup"); err != nil {
			return err
		}
	}
	for _, x := range []struct{ src, dst string }{{driverSource, declarativeauthority.DriverPath}, {consumerSource, declarativeauthority.ConsumerPath}} {
		b, e := os.ReadFile(x.src)
		if e != nil {
			return e
		}
		if len(b) < 64 || string(b[:4]) != "\x7fELF" {
			clear(b)
			return errors.New("invalid ELF artifact")
		}
		e = os.WriteFile(x.dst, b, 0755)
		clear(b)
		if e != nil {
			return e
		}
		if e = os.Chown(x.dst, 0, 0); e != nil {
			return e
		}
		if e = os.Chmod(x.dst, 0755); e != nil {
			return e
		}
	}
	l.workspace, err = os.MkdirTemp("/lab", "delivery-work-")
	if err != nil {
		return err
	}
	if err = os.Chmod(l.workspace, 0755); err != nil {
		return err
	}
	l.root = filepath.Join(l.workspace, "store")
	if err = os.Mkdir(l.root, 0700); err != nil {
		return err
	}
	if err = os.Chown(l.root, labUID, labUID); err != nil {
		return err
	}
	return os.Chmod(l.root, 0700)
}
func (l *deliveryLab) metadata() error {
	hashes := map[string]string{}
	for name, path := range map[string]string{"ssjack": cliPath, "harness": harnessPath, "driver": declarativeauthority.DriverPath, "consumer": declarativeauthority.ConsumerPath, "conductor": "/lab/conductor"} {
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		sum := sha256.Sum256(b)
		clear(b)
		hashes[name] = hex.EncodeToString(sum[:])
	}
	revision, run := os.Getenv("GITHUB_SHA"), os.Getenv("GITHUB_RUN_ID")
	if len(revision) != 40 || run == "" {
		return errors.New("metadata unavailable")
	}
	for _, c := range revision {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return errors.New("metadata unavailable")
		}
	}
	for _, c := range run {
		if c < '0' || c > '9' {
			return errors.New("metadata unavailable")
		}
	}
	data, e := json.Marshal(map[string]any{"result": "synthetic-delivery-complete", "product_base": "2997e692cdc24f5b9a5aa23cadc3b22ab1b32f02", "source_revision": revision, "run_id": run, "binary_sha256": hashes})
	if e != nil {
		return e
	}
	_, e = os.Stdout.Write(append(data, '\n'))
	return e
}

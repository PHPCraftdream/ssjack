//go:build linux && amd64

package appstorecrypto_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
)

func TestClawwrightTextPairConnected(t *testing.T) {
	if os.Getenv(pairGate) != "1" {
		t.Skip("explicit paired CI gate disabled")
	}
	if os.Getenv(pairChild) == "1" {
		pairConnectedChild(t)
		return
	}
	if os.Geteuid() != 0 || !filepath.IsAbs(os.Getenv(pairRoot)) {
		t.Fatal("pair acceptance requires root and a pinned Clawwright checkout")
	}
	grantR, grantW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer grantR.Close()
	ackR, ackW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer ackW.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	deadline, _ := ctx.Deadline()
	if err = grantR.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, os.Args[0], "-test.v", "-test.run", "^TestClawwrightTextPairConnected$")
	command.Dir = "/tmp"
	command.ExtraFiles = []*os.File{grantW, ackR}
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "TMPDIR=/tmp", pairGate + "=1", pairChild + "=1", pairRoot + "=" + os.Getenv(pairRoot)}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
	log := &boundedChildLog{}
	command.Stdout, command.Stderr = log, log
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	stop := func() {
		if !waited {
			_ = command.Process.Kill()
			_ = command.Wait()
			waited = true
		}
	}
	defer stop()
	defer func() {
		if t.Failed() {
			stop()
			if strings.Contains(log.String(), pairShortSecret) {
				t.Log("private child diagnostics withheld")
			} else {
				t.Logf("pair child diagnostics:\n%s", log.String())
			}
		}
	}()
	_ = grantW.Close()
	_ = ackR.Close()
	var grants []declarativeauthority.TextAdapterGrant
	if err = json.NewDecoder(grantR).Decode(&grants); err != nil {
		t.Fatalf("read pair grants: %v", err)
	}
	if len(grants) != 6 {
		t.Fatalf("expected six finite pair grants, got %d", len(grants))
	}
	if err = declarativeauthority.LoadSetup(); err != nil {
		if err = declarativeauthority.Setup(); err != nil {
			t.Fatal(err)
		}
	}
	for _, grant := range grants {
		if grant.RecipientUID != 65534 || grant.Profile != "pair-target" {
			t.Fatal("unexpected pair grant subject")
		}
		if err = declarativeauthority.RegisterTextAdapter(grant); err != nil {
			t.Fatalf("register finite pair grant: %v", err)
		}
		id := grant.ID
		t.Cleanup(func() { _ = declarativeauthority.RevokeTextAdapter(id) })
	}
	duplicate := grants[0]
	duplicate.ID = connectedVariantID(duplicate.ID, "duplicate")
	duplicate.References = append(append([]string(nil), duplicate.References...), duplicate.References[0])
	if err = declarativeauthority.RegisterTextAdapter(duplicate); err == nil {
		_ = declarativeauthority.RevokeTextAdapter(duplicate.ID)
		t.Fatal("duplicate approved references were accepted")
	}
	if _, err = ackW.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if err = command.Wait(); err != nil {
		waited = true
		t.Fatalf("paired child failed: %v", err)
	}
	waited = true
	if log.truncated || strings.Contains(log.String(), pairShortSecret) {
		t.Fatal("pair diagnostics exceeded bounds or disclosed private data")
	}
}

func pairGrant(grant declarativeauthority.TextAdapterGrant, label string) declarativeauthority.TextAdapterGrant {
	grant.ID = connectedVariantID(grant.ID, label)
	grant.References = append([]string(nil), grant.References...)
	return grant
}

func pairMissingRef(t *testing.T, placeholder string, missingObject bool) string {
	t.Helper()
	ref, err := appstoreplaceholder.Parse([]byte(placeholder))
	if err != nil {
		t.Fatal(err)
	}
	object, version := ref.ObjectID(), ref.VersionID()
	if missingObject {
		object = [16]byte{99}
	} else {
		version[0] ^= 0x80
		version[1] = 1
	}
	missing, err := appstoreref.New(ref.StoreID(), object, version, ref.SnapshotID())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := appstoreplaceholder.Encode(missing)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func pairConnectedChild(t *testing.T) {
	grantPipe, ackPipe := os.NewFile(3, "pair-grants"), os.NewFile(4, "pair-approval")
	if grantPipe == nil || ackPipe == nil {
		t.Fatal("missing pair approval pipes")
	}
	defer grantPipe.Close()
	defer ackPipe.Close()
	installation, base, refs := appstorecrypto.TextAdapterFixtureValues(t, [][]byte{[]byte(pairLongSecret), []byte(pairShortSecret)})
	target, runner, credential := newPairTarget(t, "pair-target")
	base.Profile, base.Command, base.File, base.CredentialSHA256 = "pair-target", "pair-write", target.path, credential
	deploy := pairGrant(base, "deploy")
	backup := pairGrant(base, "backup")
	backup.Mode, backup.Command = "reverse-copy-v1", "pair-read"
	restore := pairGrant(base, "restore")
	missingVersion := pairGrant(base, "missing-version")
	missingVersion.References[0] = pairMissingRef(t, refs[0], false)
	missingObject := pairGrant(base, "missing-object")
	missingObject.References[0] = pairMissingRef(t, refs[0], true)
	equalInstallation, equal, equalRefs := appstorecrypto.TextAdapterFixtureValues(t, [][]byte{[]byte(pairShortSecret), []byte(pairShortSecret)})
	equal.Profile, equal.Command, equal.File, equal.CredentialSHA256 = base.Profile, base.Command, base.File, credential
	grants := []declarativeauthority.TextAdapterGrant{deploy, backup, restore, missingVersion, missingObject, equal}
	if err := json.NewEncoder(grantPipe).Encode(grants); err != nil {
		t.Fatal(err)
	}
	var ack [1]byte
	if _, err := io.ReadFull(ackPipe, ack[:]); err != nil || ack[0] != 1 {
		t.Fatal("pair grants were not acknowledged")
	}
	template := "first=" + refs[0] + "\nsecond=" + refs[1] + "\n"
	expected := "first=" + pairLongSecret + "\nsecond=" + pairShortSecret + "\n"
	cli := newPairCLI(t, template)
	if !t.Run("deploy-and-pre-dispatch-refusals", func(t *testing.T) {
		bootstrap := pairServer(t, installation, deploy, runner)
		cli.run(t, nil, "", false, "deploy-text", "--file", target.path, "--template", cli.template, "--profile", base.Profile)
		cli.run(t, &bootstrap, "", false, "deploy-text", "--file", target.path, "--template", cli.template, "--profile", "wrong-profile")
		cli.run(t, &bootstrap, "withheld", false, "deploy-text", "--file", target.path+".wrong", "--template", cli.template, "--profile", base.Profile)
		oversize := filepath.Join(cli.root, "oversize.txt")
		if err := os.WriteFile(oversize, bytes.Repeat([]byte{'x'}, (32<<10)+1), 0o600); err != nil {
			t.Fatal(err)
		}
		cli.run(t, &bootstrap, "", false, "deploy-text", "--file", target.path, "--template", oversize, "--profile", base.Profile)
		if target.writes.Load() != 0 || target.reads.Load() != 0 {
			t.Fatal("a refused call contacted the SSH target")
		}
		cli.run(t, &bootstrap, "received", true, "deploy-text", "--file", target.path, "--template", cli.template, "--profile", base.Profile)
		pairAssertFile(t, target.path, expected)
		if target.writes.Load() != 1 {
			t.Fatal("deploy did not perform exactly one SSH write")
		}
	}) {
		return
	}
	if !t.Run("private-backup", func(t *testing.T) {
		bootstrap := pairServer(t, installation, backup, runner)
		cli.run(t, &bootstrap, "received", true, "backup-text", "--file", target.path, "--output", cli.backup, "--profile", base.Profile)
		pairAssertFile(t, cli.backup, template)
		pairAssertFile(t, target.path, expected)
		if target.reads.Load() != 1 || target.writes.Load() != 1 {
			t.Fatal("backup changed the source or repeated its SSH read")
		}
	}) {
		return
	}
	if !t.Run("exact-version-restore", func(t *testing.T) {
		if err := os.WriteFile(target.path, []byte("changed consumer state\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		bootstrap := pairServer(t, installation, restore, runner)
		cli.run(t, &bootstrap, "received", true, "deploy-text", "--file", target.path, "--template", cli.backup, "--profile", base.Profile)
		pairAssertFile(t, target.path, expected)
		pairAssertFile(t, cli.backup, template)
		if target.writes.Load() != 2 {
			t.Fatal("restore did not perform exactly one SSH write")
		}
	}) {
		return
	}
	for _, grant := range []declarativeauthority.TextAdapterGrant{missingVersion, missingObject, equal} {
		t.Run("refusal-"+grant.ID, func(t *testing.T) {
			currentInstallation, selected := installation, cli.template
			if grant.ID == equal.ID {
				currentInstallation = equalInstallation
				selected = filepath.Join(cli.root, "equal.txt")
				if err := os.WriteFile(selected, []byte(equalRefs[0]+"\n"+equalRefs[1]), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			before := target.writes.Load()
			bootstrap := pairServer(t, currentInstallation, grant, runner)
			cli.run(t, &bootstrap, "withheld", false, "deploy-text", "--file", target.path, "--template", selected, "--profile", base.Profile)
			pairAssertFile(t, target.path, expected)
			if target.writes.Load() != before {
				t.Fatal("invalid exact mapping reached the SSH target")
			}
		})
	}
	pairAssertOperatorFiles(t, cli.root)
}

//go:build linux && amd64

package conformance

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

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/connectedkit"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/testkit"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
)

// TestConsumerConformance runs the v1 bounded-text scenarios against the
// consumer named by SSJACK_CONSUMER_COMMAND. The root parent registers finite
// grants for the unprivileged child, which runs the consumer.
func TestConsumerConformance(t *testing.T) {
	if os.Getenv(consumerGate) != "1" {
		t.Skip("explicit consumer conformance gate disabled")
	}
	if os.Getenv(consumerTextChild) == "1" {
		consumerTextChildRun(t)
		return
	}
	if os.Geteuid() != 0 {
		t.Fatal("consumer conformance requires root")
	}
	loadConsumerConfig(t)
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
	command := exec.CommandContext(ctx, os.Args[0], "-test.v", "-test.run", "^TestConsumerConformance$")
	command.Dir = "/tmp"
	command.ExtraFiles = []*os.File{grantW, ackR}
	command.Env = consumerChildEnv(consumerTextChild)
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
	log := &connectedkit.BoundedChildLog{}
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
			if strings.Contains(log.String(), connectedkit.PairShortSecret) {
				t.Log("private child diagnostics withheld")
			} else {
				t.Logf("conformance child diagnostics:\n%s", log.String())
			}
		}
	}()
	_ = grantW.Close()
	_ = ackR.Close()
	var grants []declarativeauthority.TextAdapterGrant
	if err = json.NewDecoder(grantR).Decode(&grants); err != nil {
		t.Fatalf("read conformance grants: %v", err)
	}
	if len(grants) != 6 {
		t.Fatalf("expected six finite conformance grants, got %d", len(grants))
	}
	if err = declarativeauthority.LoadSetup(); err != nil {
		if err = declarativeauthority.Setup(); err != nil {
			t.Fatal(err)
		}
	}
	for _, grant := range grants {
		if grant.RecipientUID != 65534 || grant.Profile != consumerProfile {
			t.Fatal("unexpected conformance grant subject")
		}
		if err = declarativeauthority.RegisterTextAdapter(grant); err != nil {
			t.Fatalf("register finite conformance grant: %v", err)
		}
		id := grant.ID
		t.Cleanup(func() { _ = declarativeauthority.RevokeTextAdapter(id) })
	}
	duplicate := grants[0]
	duplicate.ID = connectedkit.ConnectedVariantID(duplicate.ID, "duplicate")
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
		t.Fatalf("conformance child failed: %v", err)
	}
	waited = true
	if log.Truncated() || strings.Contains(log.String(), connectedkit.PairShortSecret) {
		t.Fatal("conformance diagnostics exceeded bounds or disclosed private data")
	}
}

func consumerGrant(grant declarativeauthority.TextAdapterGrant, label string) declarativeauthority.TextAdapterGrant {
	grant.ID = connectedkit.ConnectedVariantID(grant.ID, label)
	grant.References = append([]string(nil), grant.References...)
	return grant
}

func consumerMissingRef(t *testing.T, placeholder string, missingObject bool) string {
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

func consumerTextChildRun(t *testing.T) {
	grantPipe, ackPipe := os.NewFile(3, "conformance-grants"), os.NewFile(4, "conformance-approval")
	if grantPipe == nil || ackPipe == nil {
		t.Fatal("missing conformance approval pipes")
	}
	defer grantPipe.Close()
	defer ackPipe.Close()
	installation, base, refs := testkit.TextAdapterFixtureValues(t, [][]byte{[]byte(connectedkit.PairLongSecret), []byte(connectedkit.PairShortSecret)})
	target, runner, credential := connectedkit.NewPairTarget(t, consumerProfile)
	base.Profile, base.Command, base.File, base.CredentialSHA256 = consumerProfile, "pair-write", target.Path, credential
	deploy := consumerGrant(base, "deploy")
	backup := consumerGrant(base, "backup")
	backup.Mode, backup.Command = "reverse-copy-v1", "pair-read"
	restore := consumerGrant(base, "restore")
	missingVersion := consumerGrant(base, "missing-version")
	missingVersion.References[0] = consumerMissingRef(t, refs[0], false)
	missingObject := consumerGrant(base, "missing-object")
	missingObject.References[0] = consumerMissingRef(t, refs[0], true)
	equalInstallation, equal, equalRefs := testkit.TextAdapterFixtureValues(t, [][]byte{[]byte(connectedkit.PairShortSecret), []byte(connectedkit.PairShortSecret)})
	equal.Profile, equal.Command, equal.File, equal.CredentialSHA256 = base.Profile, base.Command, base.File, credential
	grants := []declarativeauthority.TextAdapterGrant{deploy, backup, restore, missingVersion, missingObject, equal}
	if err := json.NewEncoder(grantPipe).Encode(grants); err != nil {
		t.Fatal(err)
	}
	var ack [1]byte
	if _, err := io.ReadFull(ackPipe, ack[:]); err != nil || ack[0] != 1 {
		t.Fatal("conformance grants were not acknowledged")
	}
	template := "first=" + refs[0] + "\nsecond=" + refs[1] + "\n"
	expected := "first=" + connectedkit.PairLongSecret + "\nsecond=" + connectedkit.PairShortSecret + "\n"
	cli := newConsumerCLI(t, template)
	if !t.Run("deploy-and-pre-dispatch-refusals", func(t *testing.T) {
		bootstrap := consumerServer(t, installation, deploy, runner)
		cli.deploy(t, nil, "", false, "--file", target.Path, "--template", cli.templatePath, "--profile", base.Profile)
		cli.deploy(t, &bootstrap, "", false, "--file", target.Path, "--template", cli.templatePath, "--profile", "wrong-profile")
		cli.deploy(t, &bootstrap, "withheld", false, "--file", target.Path+".wrong", "--template", cli.templatePath, "--profile", base.Profile)
		oversize := filepath.Join(cli.root, "oversize.txt")
		oversizeText := append([]byte(template), bytes.Repeat([]byte{'x'}, (32<<10)+1-len(template))...)
		if err := os.WriteFile(oversize, oversizeText, 0o600); err != nil {
			t.Fatal(err)
		}
		cli.deploy(t, &bootstrap, "", false, "--file", target.Path, "--template", oversize, "--profile", base.Profile)
		if target.Accepted.Load() != 0 || target.Writes.Load() != 0 || target.Reads.Load() != 0 {
			t.Fatal("a refused call contacted the SSH target")
		}
		cli.deploy(t, &bootstrap, "received", true, "--file", target.Path, "--template", cli.templatePath, "--profile", base.Profile)
		consumerAssertFile(t, target.Path, expected)
		if target.Writes.Load() != 1 {
			t.Fatal("deploy did not perform exactly one SSH write")
		}
	}) {
		return
	}
	if !t.Run("private-backup", func(t *testing.T) {
		bootstrap := consumerServer(t, installation, backup, runner)
		cli.backup(t, &bootstrap, "received", true, "--file", target.Path, "--output", cli.backupPath, "--profile", base.Profile)
		consumerAssertFile(t, cli.backupPath, template)
		consumerAssertFile(t, target.Path, expected)
		if target.Reads.Load() != 1 || target.Writes.Load() != 1 {
			t.Fatal("backup changed the source or repeated its SSH read")
		}
	}) {
		return
	}
	if !t.Run("exact-version-restore", func(t *testing.T) {
		if err := os.WriteFile(target.Path, []byte("changed consumer state\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		bootstrap := consumerServer(t, installation, restore, runner)
		cli.deploy(t, &bootstrap, "received", true, "--file", target.Path, "--template", cli.backupPath, "--profile", base.Profile)
		consumerAssertFile(t, target.Path, expected)
		consumerAssertFile(t, cli.backupPath, template)
		if target.Writes.Load() != 2 {
			t.Fatal("restore did not perform exactly one SSH write")
		}
	}) {
		return
	}
	for _, grant := range []declarativeauthority.TextAdapterGrant{missingVersion, missingObject, equal} {
		t.Run("refusal-"+grant.ID, func(t *testing.T) {
			currentInstallation, selected := installation, cli.templatePath
			if grant.ID == equal.ID {
				currentInstallation = equalInstallation
				selected = filepath.Join(cli.root, "equal.txt")
				if err := os.WriteFile(selected, []byte(equalRefs[0]+"\n"+equalRefs[1]), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			before, beforeConnections := target.Writes.Load(), target.Accepted.Load()
			bootstrap := consumerServer(t, currentInstallation, grant, runner)
			cli.deploy(t, &bootstrap, "withheld", false, "--file", target.Path, "--template", selected, "--profile", base.Profile)
			consumerAssertFile(t, target.Path, expected)
			if target.Writes.Load() != before || target.Accepted.Load() != beforeConnections {
				t.Fatal("invalid exact mapping reached the SSH target")
			}
		})
	}
	consumerAssertOperatorFiles(t, cli.root)
}

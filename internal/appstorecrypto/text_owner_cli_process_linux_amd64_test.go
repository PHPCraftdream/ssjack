//go:build linux && amd64

package appstorecrypto_test

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreentry"
	"github.com/PHPCraftdream/ssjack/internal/ownercontrol"
	"github.com/PHPCraftdream/ssjack/internal/ownerlocal"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
	"github.com/PHPCraftdream/ssjack/internal/ownerterminal"
	"github.com/PHPCraftdream/ssjack/internal/ownertui"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

const textOwnerLaterValue = "synthetic later text owner value"

func verifyTextOwnerCLIProcess(t *testing.T, fixture textOwnerCLICase) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	harness, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	status := "received"
	if fixture.mode == "linked-stale" {
		status = "withheld"
	}
	environment := make([]string, 0)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if key != "SSJACK_VAULT_PASSWORD" && key != "SSJACK_TEXT_OWNER_HARNESS_CHILD" {
			environment = append(environment, entry)
		}
	}
	environment = append(environment, "SSJACK_TEXT_OWNER_HARNESS_CHILD=1")
	terminal, err := ownerterminal.Start(ctx, ownerterminal.Command{Executable: os.Getenv(textOwnerCLIPath), UnixBridge: os.Getenv(textOwnerBridge), Directory: t.TempDir(), Environment: environment,
		Args: []string{"--vault", fixture.database, "--server", "text-owner", "--account", "main", "text-adapter", "serve", fixture.grant.ID, harness, "-test.run=^TestTextOwnerHarnessChild$", "--", status, fixture.grant.File, fixture.grant.References[0]}})
	if err != nil {
		t.Fatal(err)
	}
	capture := ownerterminal.CaptureOutput(terminal.Output)
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Minute)
		defer stop()
		_ = terminal.Close(cleanup)
		if capture.Join(cleanup) != nil || capture.Contains(fixture.password) || capture.Contains([]byte(textOwnerMaster)) || capture.Contains([]byte(textOwnerSSHPassword)) || capture.Contains([]byte(connectedSecret)) || capture.Contains([]byte(textOwnerLaterValue)) || capture.Contains([]byte(pairShortSecret)) {
			t.Error("actual text CLI did not join or disclosed private output")
		}
		capture.Clear()
	}()
	expect := func(text string) {
		if capture.Wait(ctx, text) != nil {
			t.Fatal("actual text CLI did not reach:", text)
		}
	}
	expect("Vault secret:")
	input := append(append([]byte(nil), fixture.password...), '\n')
	_, err = terminal.Input.Write(input)
	clear(input)
	if err != nil {
		t.Fatal(err)
	}
	if fixture.mode == "unlinked-positive" {
		expect("Application-store master secret:")
		probeTextOwner(t, ctx, fixture.database)
		input = append([]byte(textOwnerMaster), '\n')
		_, err = terminal.Input.Write(input)
		clear(input)
		if err != nil {
			t.Fatal(err)
		}
	}
	expect("TEXT-OWNER-HARNESS-READY")
	if fixture.mode != "unlinked-positive" && capture.Contains([]byte("Application-store master secret:")) {
		t.Fatal("linked actual text CLI requested a second installation unlock")
	}
	probeTextOwner(t, ctx, fixture.database)
	observer, err := ownercontrol.Open(ctx, fixture.database, fixture.password)
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Detach()
	editTextOwnerCLI(t, ctx, observer, fixture)
	if _, err := terminal.Input.Write([]byte("h\n")); err != nil {
		t.Fatal(err)
	}
	expect("TEXT-OWNER-HYDRATE-" + status)
	if status == "received" {
		value, err := os.ReadFile(fixture.target.path)
		if err != nil || !bytes.Equal(value, []byte("before "+connectedSecret+" after")) || fixture.target.writes.Load() != 1 {
			t.Fatal("actual text CLI did not deliver exact pinned private bytes")
		}
		clear(value)
	} else if fixture.target.writes.Load() != 0 || fixture.target.accepted.Load() != 0 {
		t.Fatal("stale actual text grant reached the SSH target")
	}
	if err := observer.Close(ctx); err != nil {
		t.Fatal(err)
	}
	probeTextOwner(t, ctx, fixture.database)
	if _, err := terminal.Input.Write([]byte("q\n")); err != nil || terminal.Wait(ctx) != nil {
		t.Fatal("actual text CLI failed joined consumer/service shutdown")
	}
	listener, err := ownerlocal.Listen(fixture.database)
	if err != nil {
		t.Fatal("actual text CLI shutdown retained the database role")
	}
	_ = listener.Close()
	store, err := appstoreentry.Open(fixture.grant.StorePath)
	if err != nil {
		t.Fatal("actual text CLI shutdown retained the installation lease")
	}
	_ = store.Close()
	reopened, err := vault.Load(fixture.database, fixture.password)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if (reopened.OwnerStore == nil) != (fixture.mode == "unlinked-positive") || (fixture.mode == "linked-stale" && len(reopened.Secrets) != 1) {
		t.Fatal("actual text CLI lost owner persistence or implicitly changed its link")
	}
}

func probeTextOwner(t *testing.T, ctx context.Context, path string) {
	t.Helper()
	connection, err := ownerlocal.Dial(ctx, path)
	if err != nil {
		t.Fatal("actual text CLI did not retain its native coordinator")
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
}

func editTextOwnerCLI(t *testing.T, ctx context.Context, observer *ownercontrol.Control, fixture textOwnerCLICase) {
	t.Helper()
	status := observer.Backend().Status()
	if status.Err != nil || status.Database.Err != nil {
		t.Fatal("text CLI observer could not read its explicit revision")
	}
	scoper, ok := observer.Backend().(interface{ AtRevision(uint64) ownertui.Backend })
	if !ok {
		t.Fatal("text CLI observer lost revision admission")
	}
	backend := scoper.AtRevision(status.Database.Revision)
	if fixture.mode == "linked-stale" {
		if err := backend.Submit(vault.OwnerChange{Action: "add", Name: "later-value", MediaType: "text/plain", Value: []byte(textOwnerLaterValue)}); err != nil {
			t.Fatal(err)
		}
	} else {
		directory, ok := backend.(interface {
			ApplyDirectory(ownerpacket.DirectoryChange) error
		})
		if !ok {
			t.Fatal("text CLI observer lost typed directory dispatch")
		}
		if err := directory.ApplyDirectory(ownerpacket.DirectoryChange{Action: "edit-server", ServerID: fixture.server, Fields: [][]byte{[]byte("127.0.0.1:1"), nil}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := observer.Backend().Flush(ctx); err != nil {
		t.Fatal("live actual text owner edit failed or competed for installation lease:", err)
	}
	after := observer.Backend().Status()
	if after.Err != nil || after.Database.Err != nil || after.Database.Revision <= status.Database.Revision || after.Database.SavedRevision != after.Database.Revision {
		t.Fatal("actual text CLI did not persist its explicit owner decision")
	}
}

//go:build linux && amd64

package appstorecrypto_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

const textOwnerCLIChild = "SSJACK_TEXT_OWNER_CLI_CHILD"
const textOwnerCLIPath = "SSJACK_TEXT_OWNER_CLI"
const textOwnerBridge = "SSJACK_TEXT_OWNER_BRIDGE"
const textOwnerMaster = "synthetic installation writer fixture"
const textOwnerSSHPassword = "synthetic text owner SSH password"
const textOwnerVaultPassword = "synthetic text owner CLI vault password"

type textOwnerCLICase struct {
	mode, database, server string
	password               []byte
	grant                  declarativeauthority.TextAdapterGrant
	target                 *pairTarget
}

func TestTextOwnerCLIConnected(t *testing.T) {
	if os.Getenv(connectedGate) != "1" {
		t.Skip("root-owned text CLI acceptance gate is disabled")
	}
	if os.Getenv(textOwnerCLIChild) == "1" {
		textOwnerCLIChildCases(t)
		return
	}
	if os.Geteuid() != 0 || !filepath.IsAbs(os.Getenv(textOwnerCLIPath)) || !filepath.IsAbs(os.Getenv(textOwnerBridge)) {
		t.Fatal("text CLI parent requires root and explicit CI binaries")
	}
	grantR, grantW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	ackR, ackW, err := os.Pipe()
	if err != nil {
		_ = grantR.Close()
		_ = grantW.Close()
		t.Fatal(err)
	}
	defer grantR.Close()
	defer grantW.Close()
	defer ackR.Close()
	defer ackW.Close()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestTextOwnerCLIConnected$", "-test.v")
	command.Dir = "/tmp"
	command.ExtraFiles = []*os.File{grantW, ackR}
	command.Env = append(os.Environ(), textOwnerCLIChild+"=1", "TMPDIR=/tmp")
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
	log := &boundedChildLog{}
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	_ = grantW.Close()
	_ = ackR.Close()
	waited := false
	defer func() {
		if !waited {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	failChild := func(reason string) {
		if !waited {
			_ = command.Process.Kill()
			_ = command.Wait()
			waited = true
		}
		output := log.String()
		for _, private := range []string{connectedSecret, textOwnerMaster, textOwnerSSHPassword, textOwnerVaultPassword, textOwnerLaterValue, pairShortSecret} {
			if bytes.Contains([]byte(output), []byte(private)) {
				t.Fatal("text CLI child diagnostics contained private data")
			}
		}
		t.Fatalf("%s; bounded child diagnostics: %s", reason, output)
	}
	decoder := json.NewDecoder(grantR)
	for index := 0; index < 3; index++ {
		var grant declarativeauthority.TextAdapterGrant
		if err := decoder.Decode(&grant); err != nil {
			failChild("unprivileged text CLI did not publish its grant metadata")
		}
		if grant.RecipientUID != 65534 {
			t.Fatal("text CLI grant recipient changed")
		}
		if err := declarativeauthority.RegisterTextAdapter(grant); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = declarativeauthority.RevokeTextAdapter(grant.ID) })
		if _, err := ackW.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
	}
	err = command.Wait()
	waited = true
	if err != nil || log.truncated || bytes.Contains(log.data, []byte(connectedSecret)) || bytes.Contains(log.data, []byte(textOwnerMaster)) || bytes.Contains(log.data, []byte(textOwnerSSHPassword)) {
		failChild("actual text CLI acceptance failed or emitted private diagnostics")
	}
}

func textOwnerCLIChildCases(t *testing.T) {
	grantFD, ackFD := os.NewFile(3, "grant"), os.NewFile(4, "ack")
	if os.Geteuid() <= 0 || grantFD == nil || ackFD == nil {
		t.Fatal("text CLI child requires owned grant pipes and non-root identity")
	}
	defer grantFD.Close()
	defer ackFD.Close()
	installation, grant, _ := appstorecrypto.TextAdapterProductionFixture(t)
	for _, mode := range []string{"unlinked-positive", "linked-positive", "linked-stale"} {
		if !t.Run(mode, func(t *testing.T) {
			fixture := newTextOwnerCLICase(t, installation, grant, mode)
			if err := json.NewEncoder(grantFD).Encode(fixture.grant); err != nil {
				t.Fatal(err)
			}
			var acknowledgement [1]byte
			if _, err := ackFD.Read(acknowledgement[:]); err != nil || acknowledgement[0] != 1 {
				t.Fatal("root text CLI grant registration did not complete")
			}
			verifyTextOwnerCLIProcess(t, fixture)
		}) {
			return
		}
	}
}

func newTextOwnerCLICase(t *testing.T, installation *appstorecrypto.Installation, grant declarativeauthority.TextAdapterGrant, mode string) textOwnerCLICase {
	t.Helper()
	host := pairSigner(t)
	config := &ssh.ServerConfig{PasswordCallback: func(metadata ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if metadata.User() != "pair-consumer" || !bytes.Equal(password, []byte(textOwnerSSHPassword)) {
			return nil, os.ErrPermission
		}
		return nil, nil
	}}
	config.AddHostKey(host)
	target := startPairTarget(t, 1<<20, config)
	password := []byte(textOwnerVaultPassword)
	t.Cleanup(func() { clear(password) })
	v := vault.NewDirectory()
	defer v.Close()
	sshTarget := vault.Target{Address: target.listener.Addr().String(), User: "pair-consumer", Password: []byte(textOwnerSSHPassword), HostKeys: []string{string(ssh.MarshalAuthorizedKey(host.PublicKey()))}, Usage: "agent"}
	defer clear(sshTarget.Password)
	server, err := v.AddServer("text-owner", "main", sshTarget)
	if err != nil {
		t.Fatal(err)
	}
	if mode != "unlinked-positive" {
		store := installation.Header().StoreID()
		master := []byte(textOwnerMaster)
		defer clear(master)
		if err := v.LinkOwnerStore(vault.OwnerStore{Directory: grant.StorePath, StoreID: hex.EncodeToString(store[:]), Master: master}); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	path := filepath.Join(t.TempDir(), "text-owner.ktav")
	if err := vault.CreateWithRecords(ctx, path, v, password); err != nil {
		t.Fatal(err)
	}
	loaded, err := vault.Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()
	profile, err := loaded.AccountProfile(server, "main")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := loaded.PasswordCredentialIdentity(profile)
	if err != nil {
		t.Fatal(err)
	}
	grant.ID = connectedVariantID(grant.ID, mode)
	grant.Profile, grant.CredentialSHA256, grant.Command = profile, digest, "pair-write"
	return textOwnerCLICase{mode: mode, database: path, server: server, password: password, grant: grant, target: target}
}

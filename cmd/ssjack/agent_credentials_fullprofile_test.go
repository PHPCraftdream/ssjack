package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/ownerlocal"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
	"github.com/PHPCraftdream/ssjack/internal/ownerrpc"
	"github.com/PHPCraftdream/ssjack/internal/startupsecret"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func TestVaultKeeperLifetimeFullProfile(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("production keeper ownership acceptance is CI-only")
	}
	for _, directory := range []bool{true, false} {
		name := "legacy"
		if directory {
			name = "directory"
		}
		t.Run(name, func(t *testing.T) { keeperLifetimeAcceptance(t, directory) })
	}
}

func keeperLifetimeAcceptance(t *testing.T, directory bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	defer clear(private)
	public, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	server := startLoopbackSSH(t, public, connectPassword, "keeper-lifetime")
	v := vault.New()
	if directory {
		v = vault.NewDirectory()
	}
	defer v.Close()
	target := vault.Target{Address: server.address(), User: "second", Password: []byte(connectPassword), HostKeys: []string{string(ssh.MarshalAuthorizedKey(server.hostKey))}, Usage: "agent"}
	defer clear(target.Password)
	expectedAuthentication := "second|password"
	if !directory {
		block, err := ssh.MarshalPrivateKey(private, "synthetic keeper lifetime fixture")
		if err != nil {
			t.Fatal(err)
		}
		defer clear(block.Bytes)
		target.User, target.Password, target.PrivateKey = "first", nil, pem.EncodeToMemory(block)
		defer clear(target.PrivateKey)
		expectedAuthentication = "first|publickey"
	}
	selection, serverID := "main", ""
	if directory {
		serverID, err = v.AddServer("production", "main", target)
		if err != nil {
			t.Fatal(err)
		}
		selection = "@production/main"
	} else {
		v.Targets["main"] = target
	}
	password := []byte("synthetic keeper lifetime database password")
	defer clear(password)
	path := filepath.Join(t.TempDir(), "keeper.ktav")
	if err := vault.CreateWithRecords(ctx, path, v, password); err != nil {
		t.Fatal(err)
	}
	source := startupsecret.New(string(password), true)
	defer source.Close()
	ctx = context.WithValue(ctx, startupPasswordKey{}, source)
	credentials, err := loadAgentCredentials(ctx, path, selection)
	if err != nil || credentials == nil || len(credentials.targets) != 1 {
		t.Fatal("keeper failed to capture its selected credentials")
	}
	if _, err := source.Read(func() ([]byte, error) { t.Fatal("keeper requested another password"); return nil, nil }); !errors.Is(err, startupsecret.ErrConsumed) {
		t.Fatal("keeper startup did not consume exactly one password source")
	}
	var manager *ownerdb.Manager
	defer func() {
		cleanupCode := 0
		var cleanupError error
		finishAgentCredentials(credentials, &cleanupCode, &cleanupError)
		if credentials.service != nil {
			select {
			case <-credentials.service.Done():
			default:
				t.Error("keeper fixture still has unfinished peers")
				return
			}
		}
		if manager != nil {
			manager.Discard()
		}
	}()
	if directory {
		var ok bool
		manager, ok = credentials.owner.(*ownerdb.Manager)
		if !ok || manager == nil || credentials.service == nil {
			t.Fatal("directory keeper discarded its authenticated owner session or service")
		}
		binding, err := manager.OwnerBinding()
		if err != nil {
			t.Fatal(err)
		}
		connection, err := ownerlocal.Dial(ctx, path)
		if err != nil {
			t.Fatal("keeper did not start its owned service")
		}
		packet, err := manager.LocalOwnerPeer(binding)
		if err != nil {
			connection.Close()
			t.Fatal(err)
		}
		client, err := ownerrpc.Attach(ctx, connection, packet)
		if err != nil {
			t.Fatal("keeper service did not authenticate its retained context")
		}
		reply, err := client.Execute(ctx, ownerpacket.Command{Operation: "snapshot"})
		client.Close()
		if err != nil || reply.CipherDigest == ([32]byte{}) {
			t.Fatal("keeper startup service omitted saved metadata")
		}
		snapshot, err := manager.Snapshot()
		if err != nil || snapshot.CipherDigest == ([32]byte{}) {
			t.Fatal("retained owner has no authenticated saved snapshot")
		}
		err = manager.EditAt(snapshot.Status.Database.Revision, func(candidate *vault.Vault) error {
			profile, err := candidate.AccountProfile(serverID, "main")
			if err != nil {
				return err
			}
			changed := candidate.Targets[profile]
			changed.Address, changed.User, changed.Usage = "127.0.0.1:1", "edited", "human"
			candidate.Targets[profile] = changed
			return nil
		})
		if err != nil || manager.Flush(ctx) != nil {
			t.Fatal("retained owner could not edit and save without another unlock")
		}
	} else if credentials.owner != nil || credentials.service != nil {
		t.Fatal("legacy startup silently created an unsupported directory coordinator")
	}
	// The shell-only fixture refuses exec after authenticating the frozen config.
	if _, err := credentials.runner(ctx, credentials.targets[0], "true", io.Discard, io.Discard); err == nil {
		t.Fatal("shell-only fixture unexpectedly accepted exec")
	}
	if !reflect.DeepEqual(server.authentications(), []string{expectedAuthentication}) {
		t.Fatal("keeper runner adopted later database edits or borrowed cleared credentials")
	}
	code := 0
	var outcome error
	finishAgentCredentials(credentials, &code, &outcome)
	if code != 0 || outcome != nil {
		t.Fatal("keeper did not close its saved owner session")
	}
	if manager != nil {
		if _, err := manager.Metadata(); err == nil {
			t.Fatal("keeper shutdown left its owner session available")
		}
	}
	encoded, err := os.ReadFile(path)
	if err != nil || bytes.Contains(encoded, password) || bytes.Contains(encoded, []byte(connectPassword)) {
		t.Fatal("keeper persisted plaintext credential material")
	}
	loaded, err := vault.Load(path, password)
	if err != nil {
		t.Fatal("keeper database did not authenticate after shutdown")
	}
	defer loaded.Close()
	if directory {
		profile, err := loaded.AccountProfile(serverID, "main")
		if err != nil || loaded.Targets[profile].User != "edited" || loaded.Targets[profile].Usage != "human" {
			t.Fatal("retained owner changes did not survive keeper shutdown")
		}
	} else if loaded.Targets["main"].User != "first" {
		t.Fatal("legacy read-only startup changed its record")
	}
}

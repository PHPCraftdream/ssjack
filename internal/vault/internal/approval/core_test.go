// Package approval_test exercises the application-approval behavior through
// the exported core API only. It lives out here because core imports approval,
// so only an external test package can import core from this folder without a
// cycle; vaulttest does not import approval, so importing it here is safe.
package approval_test

import (
	"bytes"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/approval"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/core"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/vaulttest"
	"github.com/ktav-lang/golang/pure"
)

func record(t *testing.T, name string) approval.Record {
	t.Helper()
	return approval.Record{Name: name, Path: filepath.Join(t.TempDir(), name), Hash: strings.Repeat("ab", 32)}
}

func onlyKey(m map[string]any) string {
	for name := range m {
		return name
	}
	return ""
}

// addMCP attaches six 8KiB bearer secrets: bulk material that alone stays
// under the plaintext limit but crosses it once an approvals section lands.
func addMCP(t *testing.T, v *core.Vault) {
	t.Helper()
	v.RemoteMCP = mcpdirectory.New()
	server, err := v.RemoteMCP.AddServer("docs", "https://docs.invalid/mcp")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"one", "two", "three", "four", "five", "six"} {
		secret := bytes.Repeat([]byte("s"), 8192)
		_, err = v.RemoteMCP.AddAccount(mcpdirectory.Account{ServerID: server, Name: name, Enabled: true, Auth: mcpdirectory.Authentication{Kind: "bearer", Secret: secret}})
		clear(secret)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestVaultApplicationApprovals(t *testing.T) {
	t.Run("round trip backfills record names", func(t *testing.T) {
		v, _ := vaulttest.DirectoryFixture(t)
		rec := record(t, "tool")
		if err := v.ApproveApplication(rec, ""); err != nil {
			t.Fatal(err)
		}
		encoded, err := core.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(encoded)
		decoded, err := core.Unmarshal(encoded)
		if err != nil {
			t.Fatalf("loaded vault with approvals was rejected: %v", err)
		}
		defer decoded.Close()
		if decoded.Approvals["tool"] != rec || decoded.Approvals["tool"].Name != "tool" {
			t.Fatal("loaded approvals lost their names or values")
		}
	})
	t.Run("old key counts", func(t *testing.T) {
		legacy := core.New()
		defer legacy.Close()
		legacy.Targets["solo"] = vaulttest.Target(t)
		encoded, err := core.Marshal(legacy)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(encoded)
		if decoded, err := core.Unmarshal(encoded); err != nil {
			t.Fatal(err)
		} else {
			decoded.Close()
		}
		directory, _ := vaulttest.DirectoryFixture(t)
		encoded, err = core.Marshal(directory)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(encoded)
		if decoded, err := core.Unmarshal(encoded); err != nil {
			t.Fatal(err)
		} else {
			decoded.Close()
		}
		value, err := pure.LoadsStrict(string(encoded))
		if err != nil {
			t.Fatal(err)
		}
		root := value.(map[string]any)
		delete(root, "servers")
		delete(root, "secrets")
		root["applications"] = map[string]any{"tool": map[string]any{
			"path": record(t, "tool").Path, "hash": strings.Repeat("ab", 32),
		}}
		text, err := pure.EmitCanonical(root)
		if err != nil {
			t.Fatal(err)
		}
		if decoded, err := core.Unmarshal([]byte(text)); err == nil {
			decoded.Close()
			t.Fatal("applications without servers and secrets was accepted")
		}
	})
	t.Run("eight section round trip", func(t *testing.T) {
		v, sshID, _ := vaulttest.RemoteFixture(t)
		link := core.OwnerStore{Directory: t.TempDir(), StoreID: vaulttest.OwnerID(1), Master: []byte("synthetic round-trip master")}
		if err := v.LinkOwnerStore(link); err != nil {
			t.Fatal(err)
		}
		rec := record(t, "tool")
		if err := v.ApproveApplication(rec, ""); err != nil {
			t.Fatal(err)
		}
		encoded, err := core.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(encoded)
		decoded, err := core.Unmarshal(encoded)
		if err != nil {
			t.Fatal(err)
		}
		defer decoded.Close()
		rotation := &core.RotationJournal{
			ID: "0102030405060708090a0b0c0d0e0f10", PlanID: 1, BaseRevision: 1,
			Phase: core.RotationArchived, ServerID: sshID, Account: "main", Profile: "production",
			CommitDigest: strings.Repeat("ab", 32), RecoveryPath: "recovery", RecoveryDigest: strings.Repeat("cd", 32),
		}
		v.Rotation = rotation
		second, err := core.Marshal(v)
		if err != nil {
			t.Fatalf("eight-section vault was refused: %v", err)
		}
		defer clear(second)
		decoded.Close()
		decoded, err = core.Unmarshal(second)
		if err != nil {
			t.Fatalf("eight-section vault did not reload: %v", err)
		}
		defer decoded.Close()
		if decoded.Servers == nil || decoded.Secrets == nil || decoded.OwnerStore == nil ||
			decoded.OwnerStore.StoreID != link.StoreID || decoded.RemoteMCP == nil ||
			decoded.Rotation == nil || decoded.Rotation.Phase != core.RotationArchived ||
			decoded.Approvals["tool"] != rec {
			t.Fatal("eight-section round trip lost a section")
		}
	})
	t.Run("v1 rejects approvals", func(t *testing.T) {
		v := core.New()
		defer v.Close()
		v.Targets["solo"] = vaulttest.Target(t)
		v.Approvals = map[string]approval.Record{"tool": record(t, "tool")}
		if err := core.Validate(v); err == nil {
			t.Fatal("version 1 accepted directory approval metadata")
		}
	})
}

func TestVaultApplicationApprovalRollback(t *testing.T) {
	t.Run("empty section plaintext rollback", func(t *testing.T) {
		// A and B are independent directoryFixture-shaped vaults: both use
		// profile "production", server name "production" and account "main",
		// while server IDs, private keys and host-key pins are random. B is
		// normalized onto A's random identity before the byte-exact canonical
		// comparison, so the rollback check compares against a genuinely
		// independent vault rather than A's own pre-approval baseline.
		a, _ := vaulttest.DirectoryFixture(t)
		b, _ := vaulttest.DirectoryFixture(t)
		baseline, err := core.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(baseline)
		baseValue, err := pure.LoadsStrict(string(baseline))
		if err != nil {
			t.Fatal(err)
		}
		base := baseValue.(map[string]any)
		if len(base) != 4 {
			t.Fatalf("baseline vault unexpectedly carried %d root sections", len(base))
		}
		aServer := onlyKey(base["servers"].(map[string]any))
		aTarget := base["targets"].(map[string]any)["production"].(map[string]any)
		bRaw, err := core.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(bRaw)
		bValue, err := pure.LoadsStrict(string(bRaw))
		if err != nil {
			t.Fatal(err)
		}
		bRoot := bValue.(map[string]any)
		servers := bRoot["servers"].(map[string]any)
		bServer := onlyKey(servers)
		bTarget := bRoot["targets"].(map[string]any)["production"].(map[string]any)
		bTarget["private_key"] = aTarget["private_key"]
		bTarget["host_keys"] = aTarget["host_keys"]
		servers[aServer] = servers[bServer]
		delete(servers, bServer)
		normalized, err := pure.EmitCanonical(bRoot)
		if err != nil {
			t.Fatal(err)
		}
		want, err := pure.EmitCanonical(base)
		if err != nil {
			t.Fatal(err)
		}
		if normalized != want {
			t.Fatal("independent fixture normalized to a different baseline plaintext")
		}
		rec := record(t, "tool")
		if err := a.ApproveApplication(rec, ""); err != nil {
			t.Fatal(err)
		}
		if err := a.RevokeApplication("tool"); err != nil {
			t.Fatal(err)
		}
		after, err := core.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(after)
		afterValue, err := pure.LoadsStrict(string(after))
		if err != nil {
			t.Fatal(err)
		}
		afterRoot := afterValue.(map[string]any)
		rolled, err := pure.EmitCanonical(afterRoot)
		if err != nil {
			t.Fatal(err)
		}
		if rolled != normalized {
			t.Fatal("revoking every approval did not restore the canonical plaintext of an independent vault")
		}
		if _, exists := afterRoot["applications"]; exists {
			t.Fatal("rolled-back payload still carries an applications section")
		}
	})
}

func TestInitializeDirectoryRefusesApprovalsOnlyVault(t *testing.T) {
	v := core.NewDirectory()
	t.Cleanup(v.Close)
	if err := v.ApproveApplication(record(t, "solo"), ""); err != nil {
		t.Fatal(err)
	}
	if len(v.Servers) != 0 || len(v.Targets) != 0 || len(v.Secrets) != 0 || v.OwnerStore != nil || v.RemoteMCP != nil {
		t.Fatal("fixture vault is not approvals-only")
	}
	target := vaulttest.Target(t)
	defer clear(target.PrivateKey)
	if err := v.InitializeDirectory("production", target); err == nil {
		t.Fatal("initialization was accepted on a vault that already carries approvals")
	}
}

func TestVaultApplicationApprovalLifecycle(t *testing.T) {
	t.Run("approval limits", func(t *testing.T) {
		v, _ := vaulttest.DirectoryFixture(t)
		for i := 0; i < approval.MaxApprovals; i++ {
			if err := v.ApproveApplication(record(t, fmt.Sprintf("app-%02d", i)), ""); err != nil {
				t.Fatal(err)
			}
		}
		if err := v.ApproveApplication(record(t, "app-extra"), ""); err == nil {
			t.Fatal("33rd approval was accepted")
		}
		encoded, err := core.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(encoded)
		loaded, err := core.Unmarshal(encoded)
		if err != nil {
			t.Fatal(err)
		}
		loaded.Close()
	})
	t.Run("duplicate and replacement approvals", func(t *testing.T) {
		v, _ := vaulttest.DirectoryFixture(t)
		rec := record(t, "tool")
		if err := v.ApproveApplication(rec, ""); err != nil {
			t.Fatal(err)
		}
		// Add-on-existing must be refused by the add guard itself, not by the
		// unchanged guard: the resubmitted record differs in both hash and
		// route, and the stored record must survive the refusal untouched.
		changed := rec
		changed.Hash = strings.Repeat("cd", 32)
		changed.Route = "incus:other-container:alice"
		if err := v.ApproveApplication(changed, ""); err == nil {
			t.Fatal("add-new with changed content on an existing name was accepted")
		}
		if list, err := v.ListApplicationApprovals(); err != nil || len(list) != 1 || list[0] != rec {
			t.Fatal("refused add-new changed the stored approval")
		}
		if err := v.ApproveApplication(rec, rec.Hash); err == nil {
			t.Fatal("identical re-approval was accepted")
		}
		other := rec
		other.Name = "clash"
		if err := v.ApproveApplication(other, ""); err == nil {
			t.Fatal("second name for the same path was accepted")
		}
		replacement := rec
		replacement.Hash = strings.Repeat("ef", 32)
		replacement.Route = "incus:web-container:alice"
		if err := v.ApproveApplication(replacement, rec.Hash); err != nil {
			t.Fatal(err)
		}
		stale := rec
		stale.Route = "incus:web-container:alice"
		if err := v.ApproveApplication(stale, strings.Repeat("01", 32)); err == nil {
			t.Fatal("replacement with an unreviewed hash was accepted")
		}
		list, err := v.ListApplicationApprovals()
		if err != nil || len(list) != 1 || list[0] != replacement {
			t.Fatal("approval replacement was not reflected in the list")
		}
	})
	t.Run("explicit add and replace", func(t *testing.T) {
		v, _ := vaulttest.DirectoryFixture(t)
		rec := record(t, "tool")
		if err := v.ApproveApplication(rec, rec.Hash); err == nil {
			t.Fatal("replace on a missing name was accepted")
		}
		if err := v.ApproveApplication(rec, ""); err != nil {
			t.Fatal(err)
		}
		wrongHash := rec
		wrongHash.Hash = strings.Repeat("cd", 32)
		if err := v.ApproveApplication(wrongHash, strings.Repeat("ef", 32)); err == nil {
			t.Fatal("replacement with a wrong reviewed hash was accepted")
		}
		if list, err := v.ListApplicationApprovals(); err != nil || len(list) != 1 || list[0] != rec {
			t.Fatal("refused replacement changed the stored approval")
		}
		if err := v.ApproveApplication(wrongHash, rec.Hash); err != nil {
			t.Fatal(err)
		}
		if list, err := v.ListApplicationApprovals(); err != nil || len(list) != 1 || list[0] != wrongHash {
			t.Fatal("approval list did not reflect the explicit replacement")
		}
	})
	t.Run("revoke and sorted list", func(t *testing.T) {
		v, _ := vaulttest.DirectoryFixture(t)
		for _, name := range []string{"beta", "alpha"} {
			if err := v.ApproveApplication(record(t, name), ""); err != nil {
				t.Fatal(err)
			}
		}
		list, err := v.ListApplicationApprovals()
		if err != nil || len(list) != 2 || list[0].Name != "alpha" || list[1].Name != "beta" {
			t.Fatal("approval list was not sorted by name")
		}
		if err := v.RevokeApplication("missing"); err == nil {
			t.Fatal("revoking an unknown approval was accepted")
		}
		if err := v.RevokeApplication("beta"); err != nil {
			t.Fatal(err)
		}
		if list, err = v.ListApplicationApprovals(); err != nil || len(list) != 1 || list[0].Name != "alpha" {
			t.Fatal("revocation did not remove the record")
		}
	})
	t.Run("oversized plaintext refused with approvals intact", func(t *testing.T) {
		// Paths are exactly 512 bytes on every OS: the absolute prefix is
		// "C:\" (3 bytes) on Windows and "/" (1 byte) elsewhere, so the filler
		// shrinks accordingly; the varying 4-digit suffix keeps paths distinct
		// without changing the length. Only CI exercises the Windows prefix.
		prefix := "/"
		if runtime.GOOS == "windows" {
			prefix = `C:\`
		}
		path := func(i int) string {
			return prefix + strings.Repeat("a", 512-len(prefix)-4) + fmt.Sprintf("%04d", i)
		}
		// Without approvals the same bulk MCP material still marshals: only
		// the approval set pushes the payload past the plaintext limit.
		clean, _ := vaulttest.DirectoryFixture(t)
		addMCP(t, clean)
		if encoded, err := core.Marshal(clean); err != nil {
			t.Fatalf("vault without approvals was refused: %v", err)
		} else {
			clear(encoded)
		}
		v, _ := vaulttest.DirectoryFixture(t)
		first := approval.Record{
			Name: "app-00", Path: path(0), Hash: strings.Repeat("ab", 32),
			Route: "incus:" + strings.Repeat("c", 63) + ":" + strings.Repeat("u", 32),
		}
		if err := v.ApproveApplication(first, ""); err != nil {
			t.Fatal(err)
		}
		for i := 1; i < approval.MaxApprovals; i++ {
			rec := first
			rec.Name = fmt.Sprintf("app-%02d", i)
			rec.Path = path(i)
			if err := v.ApproveApplication(rec, ""); err != nil {
				t.Fatal(err)
			}
		}
		addMCP(t, v)
		if _, err := core.Marshal(v); err == nil || !strings.Contains(err.Error(), "64 KiB") {
			t.Fatalf("oversized vault marshal error = %v, want the plaintext limit", err)
		}
		list, err := v.ListApplicationApprovals()
		if err != nil || len(list) != approval.MaxApprovals {
			t.Fatalf("failed marshal disturbed the approval set: %d records, err %v", len(list), err)
		}
		for i, got := range list {
			want := first
			want.Name = fmt.Sprintf("app-%02d", i)
			want.Path = path(i)
			if got != want {
				t.Fatalf("approval record %d changed after the failed marshal", i)
			}
		}
	})
}

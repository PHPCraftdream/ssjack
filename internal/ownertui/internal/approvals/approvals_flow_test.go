package approvals

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/application"
	"github.com/PHPCraftdream/ssjack/internal/application/discovery"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

var sharedVault struct {
	sync.Once
	path     string
	v        *vault.Vault
	password []byte
	err      error
}

func openTestVault(t *testing.T) (string, *vault.Vault, []byte) {
	t.Helper()
	sharedVault.Do(func() {
		sharedVault.path = filepath.Join(os.TempDir(), "ssjack-approvals-shared-test-vault")
		sharedVault.password = []byte("test-password")
		sharedVault.v = vault.NewDirectory()
		sharedVault.err = vault.CreateWithRecords(context.Background(), sharedVault.path, sharedVault.v, sharedVault.password)
		if sharedVault.err == nil {
			sharedVault.v, sharedVault.err = vault.Load(sharedVault.path, sharedVault.password)
		}
	})
	if sharedVault.err != nil {
		t.Fatal(sharedVault.err)
	}
	records, err := vault.ListApplicationApprovals(sharedVault.v)
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		if err := sharedVault.v.RevokeApplication(record.Name); err != nil {
			t.Fatal(err)
		}
	}
	return sharedVault.path, sharedVault.v, sharedVault.password
}

func controllerFor(t *testing.T, v *vault.Vault) *Controller {
	t.Helper()
	root := t.TempDir()
	putDescriptor(t, root, "svc-a", "service-a")
	c := New(v, root)
	c.Refresh()
	for i, e := range c.Entries() {
		if e.candidate != nil {
			c.Select(i)
			break
		}
	}
	return c
}

type fakeVaultOps struct {
	listCalls, approveCalls, revokeCalls int
	rec                                  vault.Approval
	records                              []vault.Approval
	replacesHash                         string
	approveErr, revokeErr                error
}

func (f *fakeVaultOps) ListApplicationApprovals() ([]vault.Approval, error) {
	f.listCalls++
	return append([]vault.Approval(nil), f.records...), nil
}
func (f *fakeVaultOps) ApproveApplication(rec vault.Approval, replacesHash string) error {
	f.approveCalls++
	f.rec, f.replacesHash = rec, replacesHash
	return f.approveErr
}
func (f *fakeVaultOps) RevokeApplication(name string) error {
	f.revokeCalls++
	for i, record := range f.records {
		if record.Name == name {
			f.records = append(f.records[:i], f.records[i+1:]...)
			break
		}
	}
	return f.revokeErr
}

func TestVerifiedRevoke(t *testing.T) {
	t.Run("matching live record revokes", func(t *testing.T) {
		record := vault.Approval{Name: "service-a", Path: "/work/svc", Hash: strings.Repeat("a", 64)}
		ops := &fakeVaultOps{records: []vault.Approval{record}}
		m := Mutation{Kind: "revoke", Name: record.Name, Path: record.Path, Replaces: record.Hash}
		if err := VerifyRevoke(ops, m); err != nil {
			t.Fatal(err)
		}
		if err := ApplyVerified(ops, m); err != nil || ops.revokeCalls != 1 {
			t.Fatalf("err=%v calls=%d", err, ops.revokeCalls)
		}
	})
	t.Run("changed live hash refuses without revoke", func(t *testing.T) {
		record := vault.Approval{Name: "service-a", Path: "/work/svc", Hash: strings.Repeat("a", 64)}
		ops := &fakeVaultOps{records: []vault.Approval{{Name: record.Name, Path: record.Path, Hash: strings.Repeat("b", 64)}}}
		m := Mutation{Kind: "revoke", Name: record.Name, Path: record.Path, Replaces: record.Hash}
		if err := VerifyRevoke(ops, m); err == nil || err.Error() != "revoke_stale" {
			t.Fatalf("verify err=%v", err)
		}
		if err := ApplyVerified(ops, m); err == nil || err.Error() != "revoke_stale" || ops.revokeCalls != 0 {
			t.Fatalf("apply err=%v calls=%d", err, ops.revokeCalls)
		}
	})
	t.Run("matching live record revokes through confirmation", func(t *testing.T) {
		root := t.TempDir()
		putDescriptor(t, root, "svc-a", "service-a")
		scan := discovery.Scan(root)
		record := vault.Approval{Name: "service-a", Path: scan.Candidates[0].CanonicalPath, Hash: strings.Repeat("a", 64)}
		ops := &fakeVaultOps{records: []vault.Approval{record}}
		c := New(nil, root)
		c.SetRecords([]vault.Approval{record})
		c.Refresh()
		for i, entry := range c.Entries() {
			if entry.Record.Name == record.Name {
				c.Select(i)
				break
			}
		}
		c.Revoke()
		c.vault = ops
		if err := c.RevokeConfirm(); err != nil || ops.revokeCalls != 1 {
			t.Fatalf("err=%v calls=%d", err, ops.revokeCalls)
		}
	})
	t.Run("changed live hash refuses confirmation", func(t *testing.T) {
		root := t.TempDir()
		putDescriptor(t, root, "svc-a", "service-a")
		scan := discovery.Scan(root)
		record := vault.Approval{Name: "service-a", Path: scan.Candidates[0].CanonicalPath, Hash: strings.Repeat("a", 64)}
		live := vault.Approval{Name: record.Name, Path: record.Path, Hash: strings.Repeat("b", 64)}
		ops := &fakeVaultOps{records: []vault.Approval{live}}
		c := New(nil, root)
		c.SetRecords([]vault.Approval{record})
		c.Refresh()
		for i, entry := range c.Entries() {
			if entry.Record.Name == record.Name {
				c.Select(i)
				break
			}
		}
		c.Revoke()
		c.vault = ops
		if err := c.RevokeConfirm(); err == nil || err.Error() != "revoke_stale" || ops.revokeCalls != 0 {
			t.Fatalf("err=%v calls=%d", err, ops.revokeCalls)
		}
	})
}

func TestPinnedRefreshRelocatesCursor(t *testing.T) {
	t.Run("renamed pinned candidate remains selected", func(t *testing.T) {
		root := t.TempDir()
		first := putDescriptor(t, root, "svc-a", "service-a")
		putDescriptor(t, root, "svc-b", "service-b")
		c := New(nil, root)
		c.Refresh()
		c.Select(0)
		c.Arm()
		pin, ok := c.Pending()
		if !ok {
			t.Fatal("candidate was not armed")
		}
		ops := &fakeVaultOps{}
		c.vault = ops
		if err := os.Rename(first, filepath.Join(root, "svc-z")); err != nil {
			t.Fatal(err)
		}
		c.Refresh()
		entries := c.Entries()
		selected := entries[c.Cursor()]
		if selected.candidate == nil || selected.candidate.Name != pin.Name {
			t.Fatalf("selected=%+v pin=%+v", selected, pin)
		}
		if err := c.ConfirmApprove(); err != nil {
			t.Fatal(err)
		}
		if ops.approveCalls != 1 || ops.rec.Name != pin.Name {
			t.Fatalf("approved=%+v calls=%d", ops.rec, ops.approveCalls)
		}
	})
	t.Run("vanished pinned candidate clears review", func(t *testing.T) {
		root := t.TempDir()
		child := putDescriptor(t, root, "svc-a", "service-a")
		putDescriptor(t, root, "svc-b", "service-b")
		c := New(nil, root)
		c.Refresh()
		c.Select(0)
		c.Arm()
		if err := os.RemoveAll(child); err != nil {
			t.Fatal(err)
		}
		c.Refresh()
		if _, ok := c.Pending(); ok || c.Message() != "review_stale" {
			t.Fatalf("pending=%v message=%q", ok, c.Message())
		}
	})
}

func TestRejectedApprovalStaysApproved(t *testing.T) {
	t.Run("approval overrides session rejection", func(t *testing.T) {
		_, v, _ := openTestVault(t)
		root := t.TempDir()
		putDescriptor(t, root, "svc-a", "service-a")
		scan := discovery.Scan(root)
		c := New(v, root)
		c.Refresh()
		c.Select(0)
		c.Reject()
		if err := c.RejectConfirm(); err != nil {
			t.Fatal(err)
		}
		candidatePath := scan.Candidates[0].CanonicalPath
		fingerprint := hex.EncodeToString(scan.Candidates[0].Fingerprint[:])
		if err := v.ApproveApplication(vault.Approval{Name: "service-a", Path: candidatePath, Hash: fingerprint}, ""); err != nil {
			t.Fatal(err)
		}
		c.Refresh()
		if len(c.Entries()) == 0 || c.Entries()[0].Status != StatusApproved {
			for _, entry := range c.Entries() {
				if entry.Name == "service-a" {
					if entry.Status != StatusApproved {
						t.Fatalf("status=%v", entry.Status)
					}
					goto approved
				}
			}
			t.Fatalf("service-a entry missing: %+v", c.Entries())
		}
	approved:

		c.Revoke()
		if err := c.RevokeConfirm(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestFailedArmClearsPreviousPin(t *testing.T) {
	t.Run("failed approve arm clears review", func(t *testing.T) {
		c := controllerFor(t, nil)
		c.Arm()
		c.entries[c.cursor].Status = StatusRejected
		c.Arm()
		if _, ok := c.Pending(); ok || c.Message() != "not_approvable" {
			t.Fatalf("pending=%v message=%q", ok, c.Message())
		}
	})
	t.Run("failed reject arm clears review", func(t *testing.T) {
		c := controllerFor(t, nil)
		c.Arm()
		c.entries[c.cursor].Record = vault.Approval{Name: "service-a"}
		c.Reject()
		if _, ok := c.Pending(); ok || c.Message() != "reject_approved" {
			t.Fatalf("pending=%v message=%q", ok, c.Message())
		}
	})
	t.Run("failed revoke arm clears review", func(t *testing.T) {
		c := controllerFor(t, nil)
		c.Arm()
		c.entries[c.cursor].Record = vault.Approval{Name: "service-a"}
		c.Revoke()
		if _, ok := c.Pending(); ok || c.Message() != "not_revokeable" {
			t.Fatalf("pending=%v message=%q", ok, c.Message())
		}
	})
}

func TestApplyMutationValidationParity(t *testing.T) {
	check := func(ops vaultOps, mutation Mutation, want string) {
		err := ApplyMutation(ops, mutation)
		if err == nil || err.Error() != want {
			t.Fatalf("error=%v want=%s", err, want)
		}
		if f, ok := ops.(*fakeVaultOps); ok && (f.approveCalls != 0 || f.revokeCalls != 0) {
			t.Fatalf("refusal called ops: %+v", f)
		}
	}
	t.Run("invalid name", func(t *testing.T) {
		check(&fakeVaultOps{}, Mutation{Kind: "approve", Name: "Bad Name", Path: filepath.Join(t.TempDir(), "x")}, "name_invalid")
	})
	t.Run("path too long", func(t *testing.T) {
		check(&fakeVaultOps{}, Mutation{Kind: "approve", Name: "good", Path: filepath.Join(t.TempDir(), strings.Repeat("x", 600))}, "path_limit_exceeded")
	})
	t.Run("path control byte", func(t *testing.T) {
		check(&fakeVaultOps{}, Mutation{Kind: "approve", Name: "good", Path: filepath.Join(t.TempDir(), "bad\x01")}, "path_invalid")
	})
	t.Run("nil approve ops", func(t *testing.T) {
		check(nil, Mutation{Kind: "approve", Name: "good", Path: filepath.Join(t.TempDir(), "x")}, "vault_unavailable")
	})
	t.Run("nil revoke ops", func(t *testing.T) { check(nil, Mutation{Kind: "revoke", Name: "good"}, "revoke_failed") })
	t.Run("unknown kind", func(t *testing.T) { check(&fakeVaultOps{}, Mutation{Kind: "other"}, "mutation_invalid") })
}

func TestApproveWritesCandidate(t *testing.T) {
	t.Run("stores canonical path and fingerprint", func(t *testing.T) {
		path, v, _ := openTestVault(t)
		root := t.TempDir()
		putDescriptor(t, root, "svc-a", "service-a")
		scan := discovery.Scan(root)
		c := New(v, root)
		c.Refresh()
		c.Select(0)
		c.Arm()
		if err := c.ConfirmApprove(); err != nil {
			t.Fatal(err)
		}
		records, err := vault.ListApplicationApprovals(v)
		if err != nil || len(records) != 1 {
			t.Fatalf("records=%v err=%v", records, err)
		}
		scan = discovery.Scan(root)
		want := hex.EncodeToString(scan.Candidates[0].Fingerprint[:])
		canonical := discovery.Scan(root).Candidates[0].CanonicalPath
		if records[0].Name != "service-a" || records[0].Path != canonical || records[0].Hash != want || len(records[0].Hash) != 64 {
			t.Fatalf("record=%+v want hash=%s vault=%s", records[0], want, path)
		}
	})
}

func TestApproveRefusals(t *testing.T) {
	t.Run("requires selection and arm and cancel preserves empty vault", func(t *testing.T) {
		_, v, _ := openTestVault(t)
		c := controllerFor(t, v)
		c.Select(-1)
		if err := c.ConfirmApprove(); err == nil || err.Error() != "confirmation_required" || c.Message() != "confirmation_required" {
			t.Fatal("no-selection approval accepted")
		}
		c.Select(0)
		if err := c.ConfirmApprove(); err == nil || err.Error() != "confirmation_required" || c.Message() != "confirmation_required" {
			t.Fatal("unarmed approval accepted")
		}
		c.Arm()
		c.Cancel()
		if err := c.Confirm(""); err == nil || c.Message() != "cancelled" {
			t.Fatal("empty confirmation not cancelled")
		}
		records, _ := vault.ListApplicationApprovals(v)
		if len(records) != 0 {
			t.Fatalf("unexpected approvals: %v", records)
		}
	})
}

func TestRejectApproved(t *testing.T) {
	t.Run("approved row cannot be rejected", func(t *testing.T) {
		_, v, _ := openTestVault(t)
		c := controllerFor(t, v)
		c.Arm()
		if err := c.ConfirmApprove(); err != nil {
			t.Fatal(err)
		}
		c.Refresh()
		c.Select(0)
		c.Reject()
		if c.Message() != "reject_approved" {
			t.Fatalf("reject message=%q", c.Message())
		}
		if _, ok := c.Pending(); ok {
			t.Fatal("approved entry armed for rejection")
		}
		if err := c.RejectConfirm(); err == nil || c.Message() != "confirmation_required" {
			t.Fatalf("reject confirm err=%v message=%q", err, c.Message())
		}
		c.Refresh()
		if len(c.Entries()) == 0 || c.Entries()[0].Status != StatusApproved {
			t.Fatal("approved entry changed after rejected reject")
		}
	})
}

func TestRejectIsSessionLocal(t *testing.T) {
	t.Run("rejects after confirmation without vault write", func(t *testing.T) {
		_, v, _ := openTestVault(t)
		c := controllerFor(t, v)
		c.Reject()
		if err := c.RejectConfirm(); err != nil {
			t.Fatal(err)
		}
		c.Refresh()
		if len(c.Entries()) == 0 || c.Entries()[0].Status != StatusRejected {
			t.Fatal("rejection was not retained on refresh")
		}
		records, _ := vault.ListApplicationApprovals(v)
		if len(records) != 0 {
			t.Fatalf("reject wrote approvals: %v", records)
		}
	})
}

func TestRevokePersistsWithoutApprovalSection(t *testing.T) {
	t.Run("revoke omits empty approvals section", func(t *testing.T) {
		path, v, password := openTestVault(t)
		c := controllerFor(t, v)
		c.Arm()
		if err := c.ConfirmApprove(); err != nil {
			t.Fatal(err)
		}
		if err := vault.SaveUnlocked(context.Background(), path, v); err != nil {
			t.Fatal(err)
		}
		v1, err := vault.Load(path, password)
		if err != nil {
			t.Fatal(err)
		}
		if v1.Approvals == nil || len(v1.Approvals) != 1 {
			t.Fatalf("approval section missing after approve: %#v", v1.Approvals)
		}
		c = New(v1, c.workingDir)
		c.Refresh()
		c.Select(0)
		c.Revoke()
		if err := c.RevokeConfirm(); err != nil {
			t.Fatal(err)
		}
		if err := vault.SaveUnlocked(context.Background(), path, v1); err != nil {
			t.Fatal(err)
		}
		v2, err := vault.Load(path, password)
		if err != nil {
			t.Fatal(err)
		}
		if v2.Approvals != nil {
			t.Fatalf("empty approvals section was not omitted: %#v", v2.Approvals)
		}
	})
	t.Run("revoke cancel keeps record", func(t *testing.T) {
		_, v, _ := openTestVault(t)
		c := controllerFor(t, v)
		c.Arm()
		if err := c.ConfirmApprove(); err != nil {
			t.Fatal(err)
		}
		c.Select(0)
		c.Revoke()
		c.Cancel()
		if err := c.RevokeConfirm(); err == nil || c.Message() != "confirmation_required" {
			t.Fatalf("cancelled revoke err=%v message=%q", err, c.Message())
		}
		records, err := vault.ListApplicationApprovals(v)
		if err != nil || len(records) != 1 {
			t.Fatalf("record lost after cancel: %v err=%v", records, err)
		}
	})
}

func TestChangedReapprovalAndStaleConflict(t *testing.T) {
	t.Run("replaces old hash and refuses stale approval", func(t *testing.T) {
		_, v, _ := openTestVault(t)
		root := t.TempDir()
		child := putDescriptor(t, root, "svc-a", "service-a")
		scan := discovery.Scan(root)
		c := New(v, root)
		c.Refresh()
		c.Select(0)
		c.Arm()
		if err := c.ConfirmApprove(); err != nil {
			t.Fatal(err)
		}
		old, _ := vault.ListApplicationApprovals(v)
		desc := filepath.Join(child, application.DescriptorFile)
		suffix := ""
		if runtime.GOOS == "windows" {
			suffix = ".exe"
		}
		if err := os.WriteFile(desc, []byte(`{"format":"ssjack-app-v1","name":"service-a","launch":{"executable":"bin/tool2`+suffix+`"}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		c.Refresh()
		c.Select(0)
		if c.Entries()[0].Status != StatusChanged || c.Entries()[0].HashPrefix != hex.EncodeToString(discovery.Scan(root).Candidates[0].Fingerprint[:])[:12] || c.Entries()[0].ApprovedHashPrefix != old[0].Hash[:12] {
			t.Fatal("changed approval status/prefix incorrect")
		}
		newHash := hex.EncodeToString(discovery.Scan(root).Candidates[0].Fingerprint[:])
		c.Arm()
		if err := c.ConfirmApprove(); err != nil {
			t.Fatal(err)
		}
		records, _ := vault.ListApplicationApprovals(v)
		if len(records) != 1 || records[0].Hash != newHash {
			t.Fatalf("reapproval=%v", records)
		}
		if err := os.WriteFile(desc, []byte(`{"format":"ssjack-app-v1","name":"service-a","launch":{"executable":"bin/tool3`+suffix+`"}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		c.Refresh()
		c.Select(0)
		changedPath := scan.Candidates[0].CanonicalPath
		if err := v.ApproveApplication(vault.Approval{Name: "service-a", Path: changedPath, Hash: hex.EncodeToString(make([]byte, 32))}, newHash); err != nil {
			t.Fatal(err)
		}
		c.Arm()
		if err := c.ConfirmApprove(); err == nil || c.Message() != "approval_changed_retry" {
			t.Fatalf("stale confirm err=%v message=%q", err, c.Message())
		}
		latest, _ := vault.ListApplicationApprovals(v)
		if len(latest) != 1 || latest[0].Hash != hex.EncodeToString(make([]byte, 32)) {
			t.Fatal("stale confirmation replaced the concurrent record")
		}
	})
}

func TestApprovalLimitsAndPathValidation(t *testing.T) {
	t.Run("maps count limit and rejects overlong paths", func(t *testing.T) {
		if got := mapVaultError(errors.New("too many application approvals")); got != "approval_limit_reached" {
			t.Fatalf("limit message=%q", got)
		}
		if validPath("/"+string([]byte{1})) == nil {
			t.Fatal("control byte accepted")
		}
		base := t.TempDir()
		padding := strings.Repeat("x", 512-len(base)-1)
		accept := filepath.Join(base, padding)
		if len(accept) != 512 {
			t.Fatalf("test path length=%d", len(accept))
		}
		reject := accept + "x"
		if validPath(accept) != nil {
			t.Fatal("valid 512-byte absolute path rejected")
		}
		if validPath(reject) == nil {
			t.Fatal("513-byte absolute path accepted")
		}
	})
	t.Run("thirty-third approval is refused", func(t *testing.T) {
		_, v, _ := openTestVault(t)
		root := t.TempDir()
		names := make([]string, 0, 32)
		for ch := 'a'; ch <= 'z'; ch++ {
			names = append(names, string(ch))
		}
		for _, name := range []string{"aa", "ab", "ac", "ad", "ae", "af"} {
			names = append(names, name)
		}
		for i, name := range names {
			rec := vault.Approval{Name: name, Path: filepath.Join(root, name), Hash: strings.Repeat("a", 63) + string("0123456789abcdef"[i%16])}
			if err := v.ApproveApplication(rec, ""); err != nil {
				t.Fatalf("seed %s: %v", name, err)
			}
		}
		candidateRoot := t.TempDir()
		putDescriptor(t, candidateRoot, "svc-a", "service-a")
		c := New(v, candidateRoot)
		c.Refresh()
		c.Select(0)
		c.Arm()
		if err := c.ConfirmApprove(); err == nil || c.Message() != "approval_limit_reached" {
			t.Fatalf("limit err=%v message=%q", err, c.Message())
		}
	})
}

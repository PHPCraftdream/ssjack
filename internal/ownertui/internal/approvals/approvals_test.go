package approvals

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/application"
	"github.com/PHPCraftdream/ssjack/internal/application/discovery"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func putDescriptor(t *testing.T, root, child, name string) string {
	t.Helper()
	dir := filepath.Join(root, child)
	if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	suffix := ""
	if runtime.GOOS == "windows" {
		suffix = ".exe"
	}
	for _, executable := range []string{"tool", "tool2", "tool3"} {
		if err := os.WriteFile(filepath.Join(dir, "bin", executable+suffix), []byte("fixture"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	raw := `{"format":"ssjack-app-v1","name":"` + name + `","launch":{"executable":"bin/tool` + suffix + `"}}`
	if err := os.WriteFile(filepath.Join(dir, application.DescriptorFile), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestDisplay(t *testing.T) {
	t.Run("quotes printable strings", func(t *testing.T) {
		got, ok := display("svc-a")
		if !ok || got != `"svc-a"` {
			t.Fatalf("display=%q ok=%v", got, ok)
		}
	})
	t.Run("rejects controls and invalid utf8", func(t *testing.T) {
		for _, v := range []string{"bad\x01name", string([]byte{0xff})} {
			if got, ok := display(v); ok || got != "" {
				t.Fatalf("unsafe display %q", got)
			}
		}
	})
}

func TestPinnedReview(t *testing.T) {
	t.Run("refresh invalidates changed descriptor", func(t *testing.T) {
		root := t.TempDir()
		child := putDescriptor(t, root, "svc-01", "service-a")
		c := New(nil, root)
		c.Refresh()
		c.Select(0)
		c.Arm()
		suffix := ""
		if runtime.GOOS == "windows" {
			suffix = ".exe"
		}
		if err := os.WriteFile(filepath.Join(child, "bin", "tool2"+suffix), []byte("new"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(child, application.DescriptorFile), []byte(`{"format":"ssjack-app-v1","name":"service-a","launch":{"executable":"bin/tool2`+suffix+`"}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		c.Refresh()
		if _, ok := c.Pending(); ok || c.Message() != "review_stale" {
			t.Fatal("changed candidate retained review")
		}
		if err := c.ConfirmApprove(); err == nil {
			t.Fatal("stale approval accepted")
		}
	})
	t.Run("review-time stored hash is passed to vault", func(t *testing.T) {
		root := t.TempDir()
		putDescriptor(t, root, "svc-a", "service-a")
		c := New(nil, root)
		c.SetRecords([]vault.Approval{{Name: "service-a", Path: discovery.Scan(root).Candidates[0].CanonicalPath, Hash: strings.Repeat("a", 64)}})
		c.Refresh()
		c.Select(0)
		c.Arm()
		pin, ok := c.Pending()
		if !ok {
			t.Fatal("changed row not armed")
		}
		ops := &fakeVaultOps{}
		if err := ApplyMutation(ops, pin); err != nil {
			t.Fatal(err)
		}
		if ops.replacesHash != strings.Repeat("a", 64) || ops.rec.Hash != pin.Hash || ops.rec.Path != pin.Path {
			t.Fatalf("mutation=%+v pin=%+v replaces=%q", ops.rec, pin, ops.replacesHash)
		}
	})
	t.Run("stored hash change invalidates review", func(t *testing.T) {
		root := t.TempDir()
		putDescriptor(t, root, "svc-a", "service-a")
		c := New(nil, root)
		path := discovery.Scan(root).Candidates[0].CanonicalPath
		c.SetRecords([]vault.Approval{{Name: "service-a", Path: path, Hash: strings.Repeat("a", 64)}})
		c.Refresh()
		c.Select(0)
		c.Arm()
		c.SetRecords([]vault.Approval{{Name: "service-a", Path: path, Hash: strings.Repeat("b", 64)}})
		c.Refresh()
		if c.Message() != "review_stale" {
			t.Fatalf("stale refresh=%q", c.Message())
		}
		ops := &fakeVaultOps{}
		c.vault = ops
		if err := c.ConfirmApprove(); err == nil {
			t.Fatal("stale approval accepted")
		}
		if ops.approveCalls != 0 {
			t.Fatal("stale review reached vault")
		}
	})
	t.Run("unchanged refresh preserves pin", func(t *testing.T) {
		root := t.TempDir()
		putDescriptor(t, root, "svc-01", "service-a")
		c := New(nil, root)
		c.Refresh()
		c.Select(0)
		c.Arm()
		c.Refresh()
		if _, ok := c.Pending(); !ok {
			t.Fatal("unchanged review lost")
		}
	})
}

func TestRecordOnlyRevoke(t *testing.T) {
	t.Run("revokes outside-list approval", func(t *testing.T) {
		root := t.TempDir()
		record := vault.Approval{Name: "outside", Path: filepath.Join(t.TempDir(), "missing"), Hash: strings.Repeat("a", 64)}
		c := New(nil, root)
		c.SetRecords([]vault.Approval{record})
		c.Refresh()
		for i, e := range c.Entries() {
			if e.Record.Name == record.Name {
				c.Select(i)
				break
			}
		}
		c.Revoke()
		pin, ok := c.Pending()
		if !ok || pin.Path != record.Path || pin.Replaces != record.Hash {
			t.Fatalf("pin=%+v ok=%v", pin, ok)
		}
		ops := &fakeVaultOps{records: []vault.Approval{record}}
		c.vault = ops
		if err := c.RevokeConfirm(); err != nil || ops.revokeCalls != 1 {
			t.Fatalf("revoke err=%v calls=%d", err, ops.revokeCalls)
		}
	})
}

func TestListOverflowKeepsRecords(t *testing.T) {
	t.Run("overflow exposes unsafe and outside approval", func(t *testing.T) {
		root := t.TempDir()
		for i := 1; i <= 17; i++ {
			putDescriptor(t, root, fmt.Sprintf("svc-%02d", i), fmt.Sprintf("service-%02d", i))
		}
		entries := List(root, []vault.Approval{{Name: "outside", Path: filepath.Join(t.TempDir(), "missing"), Hash: strings.Repeat("a", 64)}})
		unsafe, outside := false, false
		for _, e := range entries {
			unsafe = unsafe || e.Status == StatusUnsafe && e.Reason == "candidate_cap_overflow"
			outside = outside || e.OutsideWorkdir && e.DisplayPath == ""
		}
		if !unsafe || !outside {
			t.Fatalf("unsafe=%v outside=%v", unsafe, outside)
		}
	})
}

func TestUnmatchedRecords(t *testing.T) {
	t.Run("root missing descriptor is quiet but invalid descriptor remains visible", func(t *testing.T) {
		root := t.TempDir()
		entries := List(root, nil)
		for _, entry := range entries {
			if entry.DisplayPath == `"."` {
				t.Fatalf("missing root descriptor rendered: %+v", entry)
			}
		}
		if err := os.WriteFile(filepath.Join(root, application.DescriptorFile), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		entries = List(root, nil)
		found := false
		for _, entry := range entries {
			if entry.DisplayPath == `"."` && entry.Reason == "descriptor_invalid" {
				found = true
			}
		}
		if !found {
			t.Fatalf("invalid root descriptor diagnostic missing: %+v", entries)
		}
	})
	t.Run("reports missing invalid and unscanned paths", func(t *testing.T) {
		root := t.TempDir()
		inside := filepath.Join(root, "empty")
		if err := os.Mkdir(inside, 0o700); err != nil {
			t.Fatal(err)
		}
		invalid := filepath.Join(root, "bad")
		if err := os.Mkdir(invalid, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(invalid, application.DescriptorFile), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		near := filepath.Join(root, "..tools")
		if err := os.Mkdir(near, 0o700); err != nil {
			t.Fatal(err)
		}
		records := []vault.Approval{{Name: "one", Path: inside}, {Name: "two", Path: filepath.Join(root, "gone")}, {Name: "three", Path: invalid}, {Name: "four", Path: filepath.Join(t.TempDir(), "outside")}, {Name: "five", Path: near}}
		entries := List(root, records)
		want := map[string]string{inside: "descriptor_missing", filepath.Join(root, "gone"): "descriptor_missing", invalid: "descriptor_invalid", near: "descriptor_missing"}
		found := map[string]bool{}
		for _, e := range entries {
			if reason, ok := want[e.Record.Path]; ok {
				found[e.Record.Name] = true
				if e.Reason != reason {
					t.Fatalf("reason=%s want=%s", e.Reason, reason)
				}
			}
			if e.Record.Name == "four" && (!e.OutsideWorkdir || e.DisplayPath != "") {
				t.Fatal("outside path exposed")
			}
		}
		for _, name := range []string{"one", "two", "three", "five"} {
			if !found[name] {
				t.Fatalf("record %q missing", name)
			}
		}
	})
}

func TestSetRecordsUnprintable(t *testing.T) {
	t.Run("control byte path never renders", func(t *testing.T) {
		root := t.TempDir()
		c := New(nil, root)
		c.SetRecords([]vault.Approval{{Name: "safe", Path: filepath.Join(root, "bad\x01"), Hash: strings.Repeat("a", 64)}})
		c.Refresh()
		found := false
		for _, e := range c.Entries() {
			if e.Record.Name == "safe" {
				found = true
				if e.PathSafe || e.Reason != "path_unprintable" {
					t.Fatalf("unsafe=%+v", e)
				}
			}
		}
		if !found {
			t.Fatal("unmatched record missing")
		}
	})
	t.Run("descriptor reason survives unprintable hash", func(t *testing.T) {
		root := t.TempDir()
		c := New(nil, root)
		c.SetRecords([]vault.Approval{{Name: "safe", Path: filepath.Join(root, "missing"), Hash: "bad\x01hash" + strings.Repeat("a", 56)}})
		c.Refresh()
		found := false
		for _, e := range c.Entries() {
			if e.Record.Name == "safe" {
				found = true
				if e.Reason != "descriptor_missing" || e.DisplayHash != "" {
					t.Fatalf("record=%+v", e)
				}
			}
		}
		if !found {
			t.Fatal("unmatched record missing")
		}
	})
}

func TestApprovalMutationValidationAndMapping(t *testing.T) {
	root := t.TempDir()
	good := Mutation{Kind: "approve", Name: "service-a", Path: filepath.Join(root, "service-a", "bin", "tool"), Hash: strings.Repeat("ab", 32)}
	for _, tc := range []struct {
		mutation Mutation
		want     string
	}{{good, ""}, {Mutation{Kind: "approve", Name: "bad/name", Path: good.Path}, "name_invalid"}, {Mutation{Kind: "approve", Name: good.Name, Path: "relative"}, "path_invalid"}, {Mutation{Kind: "approve", Name: good.Name, Path: filepath.Join(root, strings.Repeat("x", 600))}, "path_limit_exceeded"}, {Mutation{Kind: "wat"}, "mutation_invalid"}, {Mutation{Kind: "revoke", Name: good.Name}, ""}} {
		err := ValidateMutation(tc.mutation)
		got := ""
		if err != nil {
			got = err.Error()
		}
		if got != tc.want {
			t.Fatalf("validation=%q want=%q", got, tc.want)
		}
	}
	approve, err := BackendChange(good)
	if err != nil || approve != (ownerpacket.ApprovalChange{ApplicationName: good.Name, ApplicationPath: good.Path, ReviewedHash: good.Hash, ReplacesHash: ""}) {
		t.Fatalf("approve=%+v err=%v", approve, err)
	}
	live := strings.Repeat("cd", 32)
	revoke, err := BackendChange(Mutation{Kind: "revoke", Name: good.Name, Replaces: live})
	if err != nil || revoke != (ownerpacket.ApprovalChange{ApplicationName: good.Name, ApplicationPath: "", ReviewedHash: live, ReplacesHash: live}) {
		t.Fatalf("revoke=%+v err=%v", revoke, err)
	}
	if _, err := BackendChange(Mutation{Kind: "unknown"}); err == nil {
		t.Fatal("unknown mapping accepted")
	}
}

func TestMapWriteError(t *testing.T) {
	stale := "the reviewed application changed — re-open the approvals menu"
	for _, tc := range []struct {
		err  error
		want string
	}{{ownerpacket.ErrReviewStale, stale}, {fmt.Errorf("wrap: %w", ownerpacket.ErrReviewStale), stale}, {errors.Join(ownerpacket.ErrReviewStale, errors.New("other")), stale}, {ownerdb.ErrApprovalReview, stale}, {fmt.Errorf("wrap: %w", ownerdb.ErrApprovalReview), stale}, {errors.Join(ownerdb.ErrApprovalReview, errors.New("other")), stale}, {fmt.Errorf("wrap: %w", vault.ErrOwnerRevision), "owner state changed — reopen and retry"}, {errors.New("too many application approvals"), "approval_limit_reached"}, {errors.New("path exceeds 512 bytes"), "path_limit_exceeded"}, {errors.New("replaced approval does not match the reviewed descriptor hash"), "approval_changed_retry"}, {errors.New("application approval already exists"), "approval_exists"}, {errors.New("private failure"), "approval_failed"}} {
		if got := MapWriteError(tc.err); got != tc.want {
			t.Fatalf("MapWriteError(%v)=%q want=%q", tc.err, got, tc.want)
		}
	}
}

type backendApprovalFake struct {
	approve, revoke       []ownerpacket.ApprovalChange
	approveErr, revokeErr error
}

func (f *backendApprovalFake) ApproveApplication(c ownerpacket.ApprovalChange) error {
	f.approve = append(f.approve, c)
	return f.approveErr
}
func (f *backendApprovalFake) RevokeApplication(c ownerpacket.ApprovalChange) error {
	f.revoke = append(f.revoke, c)
	return f.revokeErr
}

func TestRunBackend(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "svc-a")
	if err := os.MkdirAll(filepath.Join(child, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(child, "bin", "tool"), []byte("fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	descriptor := `{"format":"ssjack-app-v1","name":"service-a","launch":{"executable":"bin/tool"}}`
	if err := os.WriteFile(filepath.Join(child, "ssjack-app.json"), []byte(descriptor), 0o600); err != nil {
		t.Fatal(err)
	}
	scan := discovery.Scan(root)
	if len(scan.Candidates) != 1 {
		t.Fatalf("candidates=%d", len(scan.Candidates))
	}
	path, hash := scan.Candidates[0].CanonicalPath, hex.EncodeToString(scan.Candidates[0].Fingerprint[:])
	t.Run("candidate row approve", func(t *testing.T) {
		c := New(nil, root)
		c.Refresh()
		c.Select(0)
		c.Arm()
		mutation, ok := c.Pending()
		if !ok {
			t.Fatal("not armed")
		}
		stale := New(nil, root)
		stale.SetRecords([]vault.Approval{{Name: "service-a", Path: path, Hash: strings.Repeat("cd", 32)}})
		stale.Refresh()
		stale.Select(0)
		stale.Arm()
		if pin, ok := stale.Pending(); !ok || pin.Replaces != strings.Repeat("cd", 32) {
			t.Fatalf("replace pin=%+v ok=%v", pin, ok)
		}
		stale.records = []vault.Approval{{Name: "service-a", Path: path, Hash: strings.Repeat("ef", 32)}}
		stale.entries = List(root, stale.records)
		if err := stale.CheckPin(); err == nil || err.Error() != "review_stale" {
			t.Fatalf("stale=%v", err)
		}
		if stale.Message() != "review_stale" {
			t.Fatalf("stale message=%q", stale.Message())
		}
		if _, ok := stale.Pending(); ok {
			t.Fatal("stale pin retained")
		}
		if err := WriteBackend(mutation, nil); err == nil || err.Error() != "vault_unavailable" {
			t.Fatalf("nil=%v", err)
		}
		f := &backendApprovalFake{}
		if err := WriteBackend(mutation, f); err != nil {
			t.Fatal(err)
		}
		want := ownerpacket.ApprovalChange{ApplicationName: "service-a", ApplicationPath: path, ReviewedHash: hash, ReplacesHash: ""}
		if len(f.approve) != 1 || f.approve[0] != want || len(f.revoke) != 0 {
			t.Fatalf("approve=%+v want=%+v", f.approve, want)
		}
		if _, ok := c.Pending(); !ok {
			t.Fatal("WriteBackend unexpectedly changed controller pin")
		}
		if err := c.CheckPin(); err != nil {
			t.Fatalf("WriteBackend altered pin: %v", err)
		}
		c.Complete(nil)
		if _, ok := c.Pending(); ok {
			t.Fatal("Complete retained pin")
		}
	})
	t.Run("record-only row revoke", func(t *testing.T) {
		live := strings.Repeat("cd", 32)
		record := vault.Approval{Name: "service-a", Path: filepath.Join(root, "record-only", "tool"), Hash: live}
		c := New(nil, root)
		c.SetRecords([]vault.Approval{record})
		c.Refresh()
		for i, e := range c.Entries() {
			if e.Record.Name == record.Name {
				c.Select(i)
				break
			}
		}
		c.Revoke()
		mutation, ok := c.Pending()
		if !ok {
			t.Fatal("not armed")
		}
		if err := WriteBackend(mutation, nil); err == nil || err.Error() != "revoke_failed" {
			t.Fatalf("nil=%v", err)
		}
		f := &backendApprovalFake{revokeErr: errors.New("too many application approvals")}
		if err := WriteBackend(mutation, f); err == nil || err.Error() != "approval_limit_reached" {
			t.Fatalf("mapped=%v", err)
		}
		want := ownerpacket.ApprovalChange{ApplicationName: "service-a", ApplicationPath: "", ReviewedHash: live, ReplacesHash: live}
		if len(f.revoke) != 1 || f.revoke[0] != want || len(f.approve) != 0 {
			t.Fatalf("revoke=%+v want=%+v", f.revoke, want)
		}
	})
	for _, tc := range []struct {
		name       string
		recordHash string
		changed    bool
		wantStatus Status
	}{
		{name: "candidate row revoke approved", recordHash: hash, wantStatus: StatusApproved},
		{name: "candidate row revoke changed", recordHash: strings.Repeat("cd", 32), changed: true, wantStatus: StatusChanged},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record := vault.Approval{Name: "service-a", Path: path, Hash: tc.recordHash}
			c := New(nil, root)
			c.SetRecords([]vault.Approval{record})
			c.Refresh()
			for i, entry := range c.Entries() {
				if entry.Record.Name == record.Name {
					if entry.Status != tc.wantStatus || entry.HashPrefix != hash[:12] {
						t.Fatalf("selected status=%q want=%q hashPrefix=%q want candidate %q", entry.Status, tc.wantStatus, entry.HashPrefix, hash[:12])
					}
					c.Select(i)
					break
				}
			}
			c.Revoke()
			mutation, ok := c.Pending()
			if !ok {
				t.Fatal("not armed")
			}
			f := &backendApprovalFake{}
			if err := WriteBackend(mutation, f); err != nil {
				t.Fatal(err)
			}
			want := ownerpacket.ApprovalChange{ApplicationName: "service-a", ApplicationPath: "", ReviewedHash: tc.recordHash, ReplacesHash: tc.recordHash}
			if len(f.revoke) != 1 || f.revoke[0] != want || len(f.approve) != 0 {
				t.Fatalf("revoke=%+v want=%+v", f.revoke, want)
			}
			if tc.changed && tc.recordHash == hash {
				t.Fatalf("changed record hash %q matches fingerprint %q", tc.recordHash, hash)
			}
		})
	}
}

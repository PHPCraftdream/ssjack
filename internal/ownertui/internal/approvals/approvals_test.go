package approvals

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/application"
	"github.com/PHPCraftdream/ssjack/internal/application/discovery"
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
		c := New(nil, root, nil)
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
		c := New(nil, root, nil)
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
		c := New(nil, root, nil)
		c.SetRecords([]vault.Approval{{Name: "service-a", Path: discovery.Scan(root).Candidates[0].CanonicalPath, Hash: strings.Repeat("a", 64)}})
		c.Refresh()
		c.Select(0)
		c.Arm()
		c.SetRecords([]vault.Approval{{Name: "service-a", Path: discovery.Scan(root).Candidates[0].CanonicalPath, Hash: strings.Repeat("b", 64)}})
		c.Refresh()
		if c.Message() != "review_stale" {
			t.Fatalf("stale refresh message=%q", c.Message())
		}
		ops := &fakeVaultOps{}
		c.vault = ops
		if err := c.ConfirmApprove(); err == nil {
			t.Fatal("stale approval was accepted")
		}
		if ops.approveCalls != 0 {
			t.Fatal("stale review reached vault")
		}
	})
	t.Run("unchanged refresh preserves pin", func(t *testing.T) {
		root := t.TempDir()
		putDescriptor(t, root, "svc-01", "service-a")
		c := New(nil, root, nil)
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
		c := New(nil, root, nil)
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
			t.Fatalf("record-only revoke pin=%+v ok=%v", pin, ok)
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
		want := map[string]string{inside: "descriptor_missing", filepath.Join(root, "gone"): "descriptor_missing", invalid: "descriptor_invalid", near: "not_scanned"}
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
				t.Fatalf("record %q missing from entries", name)
			}
		}
	})
}

func TestSetRecordsUnprintable(t *testing.T) {
	t.Run("control byte path never renders", func(t *testing.T) {
		root := t.TempDir()
		c := New(nil, root, nil)
		c.SetRecords([]vault.Approval{{Name: "safe", Path: filepath.Join(root, "bad\x01"), Hash: strings.Repeat("a", 64)}})
		c.Refresh()
		found := false
		for _, e := range c.Entries() {
			if e.Record.Name == "safe" {
				found = true
				if e.PathSafe || e.Reason != "path_unprintable" {
					t.Fatalf("unsafe record: %+v", e)
				}
			}
		}
		if !found {
			t.Fatal("unmatched record missing")
		}
	})
	t.Run("descriptor reason survives unprintable hash", func(t *testing.T) {
		root := t.TempDir()
		c := New(nil, root, nil)
		c.SetRecords([]vault.Approval{{Name: "safe", Path: filepath.Join(root, "missing"), Hash: "bad\x01hash" + strings.Repeat("a", 56)}})
		c.Refresh()
		found := false
		for _, e := range c.Entries() {
			if e.Record.Name == "safe" {
				found = true
				if e.Reason != "descriptor_missing" || e.DisplayHash != "" {
					t.Fatalf("descriptor reason overwritten: %+v", e)
				}
			}
		}
		if !found {
			t.Fatal("unmatched record missing")
		}
	})
}

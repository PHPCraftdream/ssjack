//go:build linux

package transferacceptance

import (
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

// scenarioRefuseOverwriteWithoutConfirm refuses overwrite without
// confirm=true at the manager boundary, before any job exists.
func scenarioRefuseOverwriteWithoutConfirm(t *testing.T) {
	s := newStack(t, transfercore.DefaultLimits(), nil)
	var c captured
	result := callTool(t, s, "remote_upload", map[string]any{
		"target": targetName, "local": "x.txt", "remote": s.sandbox + "/in/x.txt", "overwrite": true,
	})
	c.add(t, result)
	if text := refusal(t, result); text != "overwrite requires confirm=true" {
		t.Fatalf("upload refusal = %q", text)
	}
	denied := callTool(t, s, "remote_download", map[string]any{
		"target": targetName, "remote": s.sandbox + "/in/x.txt", "local": "x.txt", "overwrite": true,
	})
	c.add(t, denied)
	if text := refusal(t, denied); text != "overwrite requires confirm=true" {
		t.Fatalf("download refusal = %q", text)
	}
}

// scenarioRefuseUnknownRoot refuses an unregistered root name in both
// directions at start time.
func scenarioRefuseUnknownRoot(t *testing.T) {
	s := newStack(t, transfercore.DefaultLimits(), nil)
	var c captured
	for _, tool := range []string{"remote_upload", "remote_download"} {
		result := callTool(t, s, tool, map[string]any{
			"target": targetName, "root": "missing", "local": "x.txt", "remote": s.sandbox + "/in/x.txt",
		})
		c.add(t, result)
		if text := refusal(t, result); text != "transfer root was not registered" {
			t.Fatalf("%s refusal = %q", tool, text)
		}
	}
}

// scenarioRefuseNoRoots fails closed: without a registered root every
// transfer operation refuses.
func scenarioRefuseNoRoots(t *testing.T) {
	s := newStackRoots(t, transfercore.DefaultLimits(), nil, false)
	var c captured
	calls := []struct {
		tool string
		args map[string]any
	}{
		{"remote_upload", map[string]any{"target": targetName, "local": "x.txt", "remote": "/srv/x.txt"}},
		{"remote_download", map[string]any{"target": targetName, "remote": "/srv/x.txt", "local": "x.txt"}},
		{"transfer_status", map[string]any{"job_id": "whatever"}},
		{"transfer_cancel", map[string]any{"job_id": "whatever"}},
	}
	for _, call := range calls {
		result := callTool(t, s, call.tool, call.args)
		c.add(t, result)
		if text := refusal(t, result); text != "no transfer roots are registered" {
			t.Fatalf("%s refusal = %q", call.tool, text)
		}
	}
}

// scenarioRefuseOverLimit refuses over-limit size and entry counts in both
// directions before any mutation.
func scenarioRefuseOverLimit(t *testing.T) {
	limits := transfercore.Limits{MaxBytes: 4096, MaxEntries: 2, MaxPathBytes: 1024, MaxDepth: 64}
	s := newStack(t, limits, nil)
	var c captured
	WriteTree(t, s.rootDir, map[string][]byte{
		"big.bin":    SeedPayload(8192, 6),
		"many/1.txt": []byte("a"),
		"many/2.txt": []byte("b"),
		"many/3.txt": []byte("c"),
	}, []string{"many"})
	WriteTree(t, s.sandbox, map[string][]byte{
		"in/big.bin": SeedPayload(8192, 6),
		"tree/1.txt": []byte("a"),
		"tree/2.txt": []byte("b"),
		"tree/3.txt": []byte("c"),
	}, []string{"in", "tree"})
	out := waitStatus(t, s, &c, startUpload(t, s, &c, map[string]any{
		"target": targetName, "local": "big.bin", "remote": s.sandbox + "/in/big.bin",
	}))
	if out.State != "failed" || out.ErrorClass != string(transfercore.ClassLimit) {
		t.Fatalf("over-limit upload status = %+v", out)
	}
	down := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": s.sandbox + "/in/big.bin", "local": "big.bin",
	}))
	if down.State != "failed" || down.ErrorClass != string(transfercore.ClassLimit) {
		t.Fatalf("over-limit download status = %+v", down)
	}
	dir := waitStatus(t, s, &c, startUpload(t, s, &c, map[string]any{
		"target": targetName, "local": "many", "remote": s.sandbox + "/in/many",
	}))
	if dir.State != "failed" || dir.ErrorClass != string(transfercore.ClassLimit) {
		t.Fatalf("over-limit entry upload status = %+v", dir)
	}
	tree := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": s.sandbox + "/tree", "local": "tree",
	}))
	if tree.State != "failed" || tree.ErrorClass != string(transfercore.ClassLimit) {
		t.Fatalf("over-limit entry download status = %+v", tree)
	}
	AssertNoStaging(t, s.rootDir)
	AssertNoStaging(t, s.sandbox)
}

// scenarioRefuseUnapprovedTarget refuses a target that is not approved.
func scenarioRefuseUnapprovedTarget(t *testing.T) {
	s := newStack(t, transfercore.DefaultLimits(), nil)
	var c captured
	result := callTool(t, s, "remote_upload", map[string]any{
		"target": "other-target", "local": "x.txt", "remote": "/srv/x.txt",
	})
	c.add(t, result)
	if text := refusal(t, result); text != "target is not allowed" {
		t.Fatalf("unapproved target refusal = %q", text)
	}
}

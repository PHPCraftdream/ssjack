//go:build linux

package transferacceptance

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfer"
	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

// scenarioFailureKilledMidStream kills the transport while bytes are in
// flight in both directions: nothing may be published and no staging may
// survive locally or in the sandbox.
func scenarioFailureKilledMidStream(t *testing.T) {
	s := newStack(t, transfercore.DefaultLimits(), nil)
	var c captured
	source := SeedPayload(2*1024*1024, 12)
	remoteFile := SeedPayload(2*1024*1024, 13)
	WriteTree(t, s.rootDir, map[string][]byte{"big/blob.bin": source}, []string{"big"})
	WriteTree(t, s.sandbox, map[string][]byte{"kill-dl/f.bin": remoteFile}, []string{"kill-dl", "kill-midstream"})
	s.server.ArmKill("cat > ", 64*1024)
	out := waitStatus(t, s, &c, startUpload(t, s, &c, map[string]any{
		"target": targetName, "local": "big/blob.bin", "remote": s.sandbox + "/kill-midstream/blob.bin",
	}))
	if out.State != "failed" || out.ErrorClass != string(transfercore.ClassRemoteFailed) {
		t.Fatalf("killed upload status = %+v", out)
	}
	if _, err := os.Stat(s.sandbox + "/kill-midstream/blob.bin"); !os.IsNotExist(err) {
		t.Fatal("killed upload published a destination")
	}
	AssertNoStaging(t, s.sandbox)
	s.server.ArmKill("cat \"$path\"", 64*1024)
	down := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": s.sandbox + "/kill-dl/f.bin", "local": "big/came-back.bin",
	}))
	if down.State != "failed" || down.ErrorClass != string(transfercore.ClassRemoteFailed) {
		t.Fatalf("killed download status = %+v", down)
	}
	if _, err := os.Stat(filepath.Join(s.rootDir, "big", "came-back.bin")); !os.IsNotExist(err) {
		t.Fatal("killed download published a destination")
	}
	AssertNoStaging(t, s.rootDir)
}

// scenarioFailureCorruption flips one byte in flight and requires an
// integrity failure that publishes nothing.
func scenarioFailureCorruption(t *testing.T) {
	s := newStack(t, transfercore.DefaultLimits(), nil)
	var c captured
	source := SeedPayload(64*1024, 14)
	WriteTree(t, s.rootDir, map[string][]byte{"blob.bin": source}, nil)
	mkdirAll(t, filepath.Join(s.sandbox, "in"))
	s.server.ArmCorrupt("cat > ", 4096)
	out := waitStatus(t, s, &c, startUpload(t, s, &c, map[string]any{
		"target": targetName, "local": "blob.bin", "remote": s.sandbox + "/in/blob.bin",
	}))
	if out.State != "failed" || out.ErrorClass != string(transfercore.ClassIntegrity) {
		t.Fatalf("corrupted upload status = %+v", out)
	}
	if _, err := os.Stat(s.sandbox + "/in/blob.bin"); !os.IsNotExist(err) {
		t.Fatal("corrupted upload published a destination")
	}
	AssertNoStaging(t, s.sandbox)
}

// scenarioFailureCancel cancels a held transfer through transfer_cancel and
// requires a cancelled record with no destination and no job-owned staging.
func scenarioFailureCancel(t *testing.T) {
	s := newStack(t, transfercore.DefaultLimits(), nil)
	var c captured
	source := SeedPayload(2*1024*1024, 15)
	WriteTree(t, s.rootDir, map[string][]byte{"big/blob.bin": source}, []string{"big"})
	mkdirAll(t, filepath.Join(s.sandbox, "in"))
	s.server.ArmHold("cat > ")
	remote := s.sandbox + "/in/cancelled.bin"
	job := startUpload(t, s, &c, map[string]any{
		"target": targetName, "local": "big/blob.bin", "remote": remote,
	})
	s.server.WaitEntered(t, "cat > ")
	acknowledged := callTool(t, s, "transfer_cancel", map[string]any{"job_id": job})
	c.add(t, acknowledged)
	var ack struct {
		Cancelled bool `json:"cancelled"`
	}
	structured(t, acknowledged, &ack)
	if !ack.Cancelled {
		t.Fatal("transfer_cancel did not cancel the running job")
	}
	s.server.Release()
	out := waitStatus(t, s, &c, job)
	if out.State != "cancelled" || out.ErrorClass != string(transfercore.ClassCancelled) {
		t.Fatalf("cancelled status = %+v", out)
	}
	if _, err := os.Stat(remote); !os.IsNotExist(err) {
		t.Fatal("cancelled upload published a destination")
	}
	AssertNoStaging(t, s.sandbox)
	again := callTool(t, s, "transfer_cancel", map[string]any{"job_id": job})
	c.add(t, again)
	structured(t, again, &ack)
	if ack.Cancelled {
		t.Fatal("cancelling a cancelled job claimed success")
	}
}

// scenarioFailureUnsupportedRemote hides sha256sum from the remote PATH and
// requires unsupported_remote before any mutation.
func scenarioFailureUnsupportedRemote(t *testing.T) {
	bin := filepath.Join(evalDir(t), "bin")
	mkdirAll(t, bin)
	for _, tool := range []string{"cat", "find", "xargs", "tar", "rm", "mv", "wc", "mkdir", "chmod"} {
		found, err := exec.LookPath(tool)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(found, filepath.Join(bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	s := newStack(t, transfercore.DefaultLimits(), []string{"PATH=" + bin})
	var c captured
	WriteTree(t, s.rootDir, map[string][]byte{"blob.bin": SeedPayload(16*1024, 16)}, nil)
	mkdirAll(t, filepath.Join(s.sandbox, "in"))
	out := waitStatus(t, s, &c, startUpload(t, s, &c, map[string]any{
		"target": targetName, "local": "blob.bin", "remote": s.sandbox + "/in/blob.bin",
	}))
	if out.State != "failed" || out.ErrorClass != string(transfercore.ClassUnsupportedRemote) {
		t.Fatalf("unsupported upload status = %+v", out)
	}
	down := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": s.sandbox + "/in/missing.bin", "local": "missing.bin",
	}))
	if down.State != "failed" || down.ErrorClass != string(transfercore.ClassUnsupportedRemote) {
		t.Fatalf("unsupported download status = %+v", down)
	}
	AssertNoStaging(t, s.rootDir)
	AssertNoStaging(t, s.sandbox)
}

// scenarioManagerBounds refuses a third concurrent job and a duplicate
// destination directly at the manager boundary.
func scenarioManagerBounds(t *testing.T) {
	s := newStack(t, transfercore.DefaultLimits(), nil)
	var c captured
	WriteTree(t, s.rootDir, map[string][]byte{
		"one.bin":   SeedPayload(64*1024, 18),
		"two.bin":   SeedPayload(64*1024, 19),
		"three.bin": SeedPayload(64*1024, 20),
	}, nil)
	mkdirAll(t, filepath.Join(s.sandbox, "in"))
	s.server.ArmHold("cat > ")
	request := func(operation string, input any) wire.Reply {
		data, err := wire.Encode(input)
		if err != nil {
			t.Fatal(err)
		}
		reply, handled := s.manager.Handle(s.ctx, wire.Request{Operation: operation, Data: data})
		if !handled {
			t.Fatalf("manager refused to handle %s", operation)
		}
		return reply
	}
	first := request("transfer_upload", transfer.StartInput{Target: targetName, Local: "one.bin", Remote: s.sandbox + "/in/one.bin"})
	if !first.OK {
		t.Fatalf("first start refused: %s", first.Error)
	}
	second := request("transfer_upload", transfer.StartInput{Target: targetName, Local: "two.bin", Remote: s.sandbox + "/in/two.bin"})
	if !second.OK {
		t.Fatalf("second start refused: %s", second.Error)
	}
	if third := request("transfer_upload", transfer.StartInput{Target: targetName, Local: "three.bin", Remote: s.sandbox + "/in/three.bin"}); third.OK || third.Error != "concurrent transfer limit reached" {
		t.Fatalf("third start reply = %+v", third)
	}
	if duplicate := request("transfer_upload", transfer.StartInput{Target: targetName, Local: "three.bin", Remote: s.sandbox + "/in/one.bin"}); duplicate.OK || duplicate.Error != "another transfer is using this destination" {
		t.Fatalf("duplicate destination reply = %+v", duplicate)
	}
	s.server.Release()
	for _, reply := range []wire.Reply{first, second} {
		var started transfer.StartOutput
		if wire.Decode(reply.Data, &started) != nil || started.JobID == "" {
			t.Fatal("started job lost its id")
		}
		if out := waitStatus(t, s, &c, started.JobID); out.State != "done" {
			t.Fatalf("held job finished as %+v", out)
		}
	}
}

//go:build linux || darwin

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
// survive locally or in the sandbox. Both files are below the size that is
// worth chunking (two minimum chunks), so a dropped stream fails them as
// before; the chunked continuation of larger files, in both directions, has its
// own scenarios.
func scenarioFailureKilledMidStream(t *testing.T) {
	s := newStack(t, transfercore.DefaultLimits(), nil)
	var c captured
	source := SeedPayload(256*1024, 12)
	remoteFile := SeedPayload(256*1024, 13)
	WriteTree(t, s.rootDir, map[string][]byte{"big/blob.bin": source}, []string{"big"})
	WriteTree(t, s.sandbox, map[string][]byte{"kill-dl/f.bin": remoteFile}, []string{"kill-dl", "kill-midstream"})
	s.server.ArmKill("cat > ", 64*1024)
	out := waitStatus(t, s, &c, startUpload(t, s, &c, map[string]any{
		"target": targetName, "local": "big/blob.bin", "remote": s.sandbox + "/kill-midstream/blob.bin",
	}))
	if out.State != "failed" {
		t.Fatal("killed upload did not reach the failed state")
	}
	if out.ErrorClass != string(transfercore.ClassRemoteFailed) {
		t.Fatal("killed upload did not report remote_failed")
	}
	if _, err := os.Stat(s.sandbox + "/kill-midstream/blob.bin"); !os.IsNotExist(err) {
		t.Fatal("killed upload published a destination")
	}
	AssertNoStaging(t, s.sandbox)
	s.server.ArmKill("cat \"$path\"", 64*1024)
	down := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": s.sandbox + "/kill-dl/f.bin", "local": "big/came-back.bin",
	}))
	if down.State != "failed" {
		t.Fatal("killed download did not reach the failed state")
	}
	if down.ErrorClass != string(transfercore.ClassRemoteFailed) {
		t.Fatal("killed download did not report remote_failed")
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
	if out.State != "failed" {
		t.Fatal("corrupted upload did not reach the failed state")
	}
	if out.ErrorClass != string(transfercore.ClassIntegrity) {
		t.Fatal("corrupted upload did not report integrity")
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
	var ack transfer.CancelOutput
	structured(t, acknowledged, &ack)
	if !ack.Cancelled {
		t.Fatal("transfer_cancel did not cancel the running job")
	}
	s.server.Release()
	out := waitStatus(t, s, &c, job)
	if out.State != "cancelled" {
		t.Fatal("cancelled upload did not reach the cancelled state")
	}
	if out.ErrorClass != string(transfercore.ClassCancelled) {
		t.Fatal("cancelled upload did not report cancelled")
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

// scenarioFailureUnsupportedRemote hides every SHA-256 utility from the
// remote PATH and requires unsupported_remote before any mutation.
func scenarioFailureUnsupportedRemote(t *testing.T) {
	bin := filepath.Join(evalDir(t), "bin")
	mkdirAll(t, bin)
	busyboxDir := os.Getenv("SSJACK_TRANSFER_BUSYBOX_BIN")
	tools := []string{"cat", "find", "xargs", "tar", "rm", "mv", "wc", "mkdir", "chmod", "ln", "sh"}
	for _, tool := range tools {
		found := ""
		var err error
		if busyboxDir != "" {
			found = filepath.Join(busyboxDir, tool)
			_, err = os.Stat(found)
		} else {
			found, err = exec.LookPath(tool)
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(found, filepath.Join(bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	env := []string{"PATH=" + bin}
	if busyboxDir != "" {
		env = append(env, "SSJACK_REMOTE_SHELL="+filepath.Join(busyboxDir, "sh"))
	}
	s := newStack(t, transfercore.DefaultLimits(), env)
	var c captured
	WriteTree(t, s.rootDir, map[string][]byte{"blob.bin": SeedPayload(16*1024, 16)}, nil)
	mkdirAll(t, filepath.Join(s.sandbox, "in"))
	out := waitStatus(t, s, &c, startUpload(t, s, &c, map[string]any{
		"target": targetName, "local": "blob.bin", "remote": s.sandbox + "/in/blob.bin",
	}))
	if out.State != "failed" {
		t.Fatal("unsupported upload did not reach the failed state")
	}
	if out.ErrorClass != string(transfercore.ClassUnsupportedRemote) {
		t.Fatal("unsupported upload did not report unsupported_remote")
	}
	down := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": s.sandbox + "/in/missing.bin", "local": "missing.bin",
	}))
	if down.State != "failed" {
		t.Fatal("unsupported download did not reach the failed state")
	}
	if down.ErrorClass != string(transfercore.ClassUnsupportedRemote) {
		t.Fatal("unsupported download did not report unsupported_remote")
	}
	AssertNoStaging(t, s.rootDir)
	AssertNoStaging(t, s.sandbox)
}

// scenarioFailureUnsupportedPublicationPrimitive constrains the remote PATH
// to real required tools while omitting Perl and substituting a failing mv.
// The real transfer stack must refuse both directions before changing either
// fixture tree or leaving staging paths behind.
func scenarioFailureUnsupportedPublicationPrimitive(t *testing.T) {
	bin := filepath.Join(evalDir(t), "bin")
	mkdirAll(t, bin)
	for _, tool := range []string{"cat", "find", "xargs", "tar", "rm", "wc", "mkdir", "chmod", "ln", "sh"} {
		found, err := exec.LookPath(tool)
		if err != nil {
			t.Fatalf("required fixture tool %s is unavailable: %v", tool, err)
		}
		if err := os.Symlink(found, filepath.Join(bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	hashTools := 0
	for _, tool := range []string{"sha256sum", "shasum", "sha256"} {
		found, err := exec.LookPath(tool)
		if err != nil {
			continue
		}
		if err := os.Symlink(found, filepath.Join(bin, tool)); err != nil {
			t.Fatal(err)
		}
		hashTools++
	}
	if hashTools == 0 {
		t.Fatal("no SHA-256 utility is available for the restricted fixture")
	}
	mv := filepath.Join(bin, "mv")
	if err := os.WriteFile(mv, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(mv, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(bin, "perl")); !os.IsNotExist(err) {
		t.Fatalf("restricted fixture unexpectedly contains Perl: %v", err)
	}

	s := newStack(t, transfercore.DefaultLimits(), []string{
		"PATH=" + bin,
		"SSJACK_REMOTE_SHELL=/bin/sh",
	})
	var c captured
	local := []byte("local-publication-source-4cbf92")
	remote := []byte("remote-publication-source-73e1ad")
	WriteTree(t, s.rootDir, map[string][]byte{"upload-source.bin": local}, []string{"downloads"})
	WriteTree(t, s.sandbox, map[string][]byte{"remote-source.bin": remote}, []string{"upload-dest"})
	localFiles, localDirs := treeState(t, s.rootDir)
	remoteFiles, remoteDirs := treeState(t, s.sandbox)

	upload := waitStatus(t, s, &c, startUpload(t, s, &c, map[string]any{
		"target": targetName, "local": "upload-source.bin", "remote": s.sandbox + "/upload-dest/new.bin",
	}))
	if upload.State != "failed" {
		t.Fatal("unsupported upload publication did not reach the failed state")
	}
	if upload.ErrorClass != string(transfercore.ClassUnsupportedRemote) {
		t.Fatal("unsupported upload publication did not report unsupported_remote")
	}
	download := waitStatus(t, s, &c, startDownload(t, s, &c, map[string]any{
		"target": targetName, "remote": s.sandbox + "/remote-source.bin", "local": "downloads/new.bin",
	}))
	if download.State != "failed" {
		t.Fatal("unsupported download publication did not reach the failed state")
	}
	if download.ErrorClass != string(transfercore.ClassUnsupportedRemote) {
		t.Fatal("unsupported download publication did not report unsupported_remote")
	}
	assertTreeSnapshot(t, s.rootDir, localFiles, localDirs)
	assertTreeSnapshot(t, s.sandbox, remoteFiles, remoteDirs)
	AssertNoStaging(t, s.rootDir)
	AssertNoStaging(t, s.sandbox)
	assertNoLeaks(t, c, local)
	assertNoLeaks(t, c, remote)
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
		t.Fatal("first start refused")
	}
	second := request("transfer_upload", transfer.StartInput{Target: targetName, Local: "two.bin", Remote: s.sandbox + "/in/two.bin"})
	if !second.OK {
		t.Fatal("second start refused")
	}
	third := request("transfer_upload", transfer.StartInput{Target: targetName, Local: "three.bin", Remote: s.sandbox + "/in/three.bin"})
	if third.OK {
		t.Fatal("third start unexpectedly succeeded")
	}
	if third.Error != "concurrent transfer limit reached" {
		t.Fatal("third start did not report concurrent transfer limit reached")
	}
	duplicate := request("transfer_upload", transfer.StartInput{Target: targetName, Local: "three.bin", Remote: s.sandbox + "/in/one.bin"})
	if duplicate.OK {
		t.Fatal("duplicate destination start unexpectedly succeeded")
	}
	if duplicate.Error != "another transfer is using this destination" {
		t.Fatal("duplicate destination start did not report another transfer is using this destination")
	}
	s.server.Release()
	for _, reply := range []wire.Reply{first, second} {
		var started transfer.StartOutput
		if wire.Decode(reply.Data, &started) != nil {
			t.Fatal("started job reply did not decode")
		}
		if started.JobID == "" {
			t.Fatal("started job reply returned an empty job id")
		}
		if out := waitStatus(t, s, &c, started.JobID); out.State != "done" {
			t.Fatal("held job did not reach the done state")
		}
	}
}

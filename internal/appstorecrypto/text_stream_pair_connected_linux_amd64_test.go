//go:build linux && amd64

package appstorecrypto_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
)

const streamPairChild = "SSJACK_CLAWWRIGHT_STREAM_PAIR_CHILD"

func TestClawwrightTextStreamPairConnected(t *testing.T) {
	if os.Getenv(pairGate) != "1" {
		t.Skip("explicit paired CI gate disabled")
	}
	if os.Getenv(streamPairChild) == "1" {
		streamPairConnectedChild(t)
		return
	}
	if os.Geteuid() != 0 || !filepath.IsAbs(os.Getenv(pairRoot)) {
		t.Fatal("stream pair acceptance requires root and a pinned Clawwright checkout")
	}
	grantR, grantW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer grantR.Close()
	ackR, ackW, err := os.Pipe()
	if err != nil {
		grantW.Close()
		t.Fatal(err)
	}
	defer ackW.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	deadline, _ := ctx.Deadline()
	if err := grantR.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	child := exec.CommandContext(ctx, os.Args[0], "-test.v", "-test.run", "^TestClawwrightTextStreamPairConnected$")
	child.Dir = "/tmp"
	child.ExtraFiles = []*os.File{grantW, ackR}
	child.Env = []string{"PATH=" + os.Getenv("PATH"), "TMPDIR=/tmp", pairGate + "=1", streamPairChild + "=1", pairRoot + "=" + os.Getenv(pairRoot)}
	child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
	log := &boundedChildLog{}
	child.Stdout, child.Stderr = log, log
	if err := child.Start(); err != nil {
		grantW.Close()
		ackR.Close()
		t.Fatal(err)
	}
	grantW.Close()
	ackR.Close()
	waited := false
	defer func() {
		if !waited {
			child.Process.Kill()
			child.Wait()
		}
		if t.Failed() {
			if strings.Contains(log.String(), pairShortSecret) {
				t.Log("private stream pair diagnostics withheld")
			} else {
				t.Logf("stream pair child diagnostics:\n%s", log.String())
			}
		}
	}()
	var grants []declarativeauthority.TextAdapterGrant
	if err := json.NewDecoder(grantR).Decode(&grants); err != nil {
		t.Fatal(err)
	}
	if len(grants) != 4 {
		t.Fatal("stream pair requires four finite grants")
	}
	if err := declarativeauthority.LoadSetup(); err != nil {
		if err := declarativeauthority.Setup(); err != nil {
			t.Fatal(err)
		}
	}
	for _, grant := range grants {
		if grant.RecipientUID != 65534 || grant.Profile != "pair-target" || (grant.Mode != "hydrate-stream-v2" && grant.Mode != "reverse-copy-stream-v2") {
			t.Fatal("unexpected stream pair grant subject")
		}
		if err := declarativeauthority.RegisterTextStream(grant); err != nil {
			t.Fatalf("register stream pair grant: %v", err)
		}
		id := grant.ID
		t.Cleanup(func() { declarativeauthority.RevokeTextStream(id) })
		if _, err := declarativeauthority.LoadTextAdapter(id, 65534, time.Now()); err == nil {
			t.Fatal("v1 acquired a stream pair grant")
		}
	}
	if _, err := ackW.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		waited = true
		t.Fatalf("stream pair child failed: %v", err)
	}
	waited = true
	if log.truncated || strings.Contains(log.String(), pairShortSecret) {
		t.Fatal("stream pair diagnostics exceeded bounds or disclosed private data")
	}
}

//go:build linux && amd64

package appstorecrypto_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
)

// TestConsumerStreamConformance runs the v2 streaming scenarios (documents
// above the v1 limits) against the consumer named by SSJACK_CONSUMER_COMMAND.
func TestConsumerStreamConformance(t *testing.T) {
	if os.Getenv(consumerGate) != "1" {
		t.Skip("explicit consumer conformance gate disabled")
	}
	if os.Getenv(consumerStreamChild) == "1" {
		consumerStreamChildRun(t)
		return
	}
	if os.Geteuid() != 0 {
		t.Fatal("stream consumer conformance requires root")
	}
	loadConsumerConfig(t)
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
	child := exec.CommandContext(ctx, os.Args[0], "-test.v", "-test.run", "^TestConsumerStreamConformance$")
	child.Dir = "/tmp"
	child.ExtraFiles = []*os.File{grantW, ackR}
	child.Env = consumerChildEnv(consumerStreamChild)
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
				t.Log("private stream conformance diagnostics withheld")
			} else {
				t.Logf("stream conformance child diagnostics:\n%s", log.String())
			}
		}
	}()
	var grants []declarativeauthority.TextAdapterGrant
	if err := json.NewDecoder(grantR).Decode(&grants); err != nil {
		t.Fatal(err)
	}
	if len(grants) != 4 {
		t.Fatal("stream conformance requires four finite grants")
	}
	if err := declarativeauthority.LoadSetup(); err != nil {
		if err := declarativeauthority.Setup(); err != nil {
			t.Fatal(err)
		}
	}
	for _, grant := range grants {
		if grant.RecipientUID != 65534 || grant.Profile != consumerProfile || (grant.Mode != "hydrate-stream-v2" && grant.Mode != "reverse-copy-stream-v2") {
			t.Fatal("unexpected stream conformance grant subject")
		}
		if err := declarativeauthority.RegisterTextStream(grant); err != nil {
			t.Fatalf("register stream conformance grant: %v", err)
		}
		id := grant.ID
		t.Cleanup(func() { declarativeauthority.RevokeTextStream(id) })
		if _, err := declarativeauthority.LoadTextAdapter(id, 65534, time.Now()); err == nil {
			t.Fatal("v1 acquired a stream conformance grant")
		}
	}
	if _, err := ackW.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		waited = true
		t.Fatalf("stream conformance child failed: %v", err)
	}
	waited = true
	if log.truncated || strings.Contains(log.String(), pairShortSecret) {
		t.Fatal("stream conformance diagnostics exceeded bounds or disclosed private data")
	}
}

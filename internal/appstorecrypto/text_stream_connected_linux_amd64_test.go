//go:build linux && amd64

package appstorecrypto_test

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
)

const streamConnectedChild = "SSJACK_TEXT_STREAM_CONNECTED_CHILD"

func TestTextStreamConnected(t *testing.T) {
	if os.Getenv(connectedGate) != "1" {
		t.Skip("CI acceptance gate is disabled")
	}
	if os.Getenv(streamConnectedChild) == "1" {
		connectedStreamChild(t)
		return
	}
	if os.Geteuid() != 0 {
		t.Fatal("stream acceptance parent requires root")
	}
	grantR, grantW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	ackR, ackW, err := os.Pipe()
	if err != nil {
		grantR.Close()
		grantW.Close()
		t.Fatal(err)
	}
	defer grantR.Close()
	defer ackW.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run", "^TestTextStreamConnected$")
	child.Dir = "/tmp"
	child.ExtraFiles = []*os.File{grantW, ackR}
	child.Env = append(os.Environ(), connectedGate+"=1", streamConnectedChild+"=1", "TMPDIR=/tmp")
	log := &boundedChildLog{}
	child.Stdout, child.Stderr = log, log
	child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
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
			t.Logf("synthetic stream child: %s", log.String())
		}
	}()
	var grant declarativeauthority.TextAdapterGrant
	if err := json.NewDecoder(grantR).Decode(&grant); err != nil {
		t.Fatal(err)
	}
	if grant.RecipientUID != 65534 || grant.Mode != "hydrate-stream-v2" {
		t.Fatal("stream child requested another scope")
	}
	if err := declarativeauthority.LoadSetup(); err != nil {
		if err := declarativeauthority.Setup(); err != nil {
			t.Fatal(err)
		}
	}
	if err := declarativeauthority.RegisterTextStream(grant); err != nil {
		t.Fatal(err)
	}
	defer declarativeauthority.RevokeTextStream(grant.ID)
	if _, err := declarativeauthority.LoadTextAdapter(grant.ID, 65534, time.Now()); err == nil {
		t.Fatal("v1 acquired the stream-only registration")
	}
	if _, err := io.WriteString(ackW, "1"); err != nil {
		t.Fatal(err)
	}
	ackW.Close()
	if err := child.Wait(); err != nil {
		waited = true
		t.Fatal("root-granted streaming child failed")
	}
	waited = true
}

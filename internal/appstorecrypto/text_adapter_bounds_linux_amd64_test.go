//go:build linux && amd64

package appstorecrypto_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
	"github.com/PHPCraftdream/ssjack/internal/remote"
)

const boundsChild = "SSJACK_TEXT_ADAPTER_BOUNDS_CASE"

func TestTextAdapterBounds(t *testing.T) {
	if os.Getenv(connectedGate) != "1" {
		t.Skip("CI acceptance gate is disabled")
	}
	if name := os.Getenv(boundsChild); name != "" {
		textAdapterBoundsChild(t, name)
		return
	}
	if os.Geteuid() != 0 {
		t.Fatal("bounds parent requires root")
	}
	for _, name := range []string{"multi", "aggregate", "aggregatecontrol", "output", "outputcontrol", "deadline60", "deadlinegrant", "deadlinecaller"} {
		t.Run(name, func(t *testing.T) {
			runTextAdapterBoundsChild(t, name)
		})
	}
}

func runTextAdapterBoundsChild(t *testing.T, name string) {
	grantR, grantW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	ackR, ackW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer grantR.Close()
	defer ackW.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run", "^TestTextAdapterBounds$")
	cmd.Dir = "/tmp"
	cmd.ExtraFiles = []*os.File{grantW, ackR}
	cmd.Env = append(os.Environ(), connectedGate+"=1", boundsChild+"="+name, "TMPDIR=/tmp")
	log := &boundedChildLog{}
	cmd.Stdout = log
	cmd.Stderr = log
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	reap := func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			waited = true
		}
	}
	defer reap()
	grantW.Close()
	ackR.Close()
	var grant declarativeauthority.TextAdapterGrant
	if err = json.NewDecoder(grantR).Decode(&grant); err != nil {
		reap()
		t.Fatalf("grant: %v: %s", err, log.String())
	}
	if grant.RecipientUID != 65534 {
		reap()
		t.Fatalf("recipient UID=%d", grant.RecipientUID)
	}
	if err = declarativeauthority.LoadSetup(); err != nil {
		if err = declarativeauthority.Setup(); err != nil {
			reap()
			t.Fatal(err)
		}
	}
	if name == "deadlinegrant" {
		grant.ExpiresAt = time.Now().Add(30 * time.Second).UTC().Format(time.RFC3339)
	}
	if err = declarativeauthority.RegisterTextAdapter(grant); err != nil {
		reap()
		t.Fatal(err)
	}
	defer declarativeauthority.RevokeTextAdapter(grant.ID)
	if _, err = ackW.Write([]byte{1}); err != nil {
		reap()
		t.Fatal(err)
	}
	if err = cmd.Wait(); err != nil {
		waited = true
		t.Fatalf("child: %v: %s", err, log.String())
	}
	waited = true
}

func textAdapterBoundsChild(t *testing.T, name string) {
	grantFD, ackFD := os.NewFile(3, "grant"), os.NewFile(4, "ack")
	if grantFD == nil || ackFD == nil {
		t.Fatal("missing metadata pipes")
	}
	defer grantFD.Close()
	defer ackFD.Close()
	var values [][]byte
	switch name {
	case "multi":
		values = [][]byte{[]byte("alpha"), []byte("beta")}
	case "aggregate":
		values = [][]byte{bytes.Repeat([]byte{'a'}, 512<<10+1), bytes.Repeat([]byte{'b'}, 512<<10+1)}
	case "aggregatecontrol":
		values = [][]byte{bytes.Repeat([]byte{'a'}, 512<<10), []byte("b")}
	case "output", "outputcontrol":
		values = [][]byte{bytes.Repeat([]byte{'a'}, 64<<10)}
	default:
		values = [][]byte{[]byte("secret")}
	}
	installation, grant, refs := appstorecrypto.TextAdapterFixtureValues(t, values)
	grant.RecipientUID = os.Geteuid()
	if err := json.NewEncoder(grantFD).Encode(grant); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(ackFD, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	loaded, err := declarativeauthority.LoadTextAdapter(grant.ID, os.Geteuid(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var calls int
	var started time.Time
	var callerDeadline time.Time
	var gotInput []byte
	runner := remote.StreamRunner(func(ctx context.Context, profile, command string, input io.Reader, stdout, stderr io.Writer) (int, error) {
		calls++
		if profile != grant.Profile || command != grant.Command {
			t.Errorf("runner profile/command=%q/%q", profile, command)
		}
		if stdout != io.Discard || stderr != io.Discard {
			t.Errorf("runner outputs are not discarded")
		}
		gotInput, err = io.ReadAll(input)
		if name == "deadline60" || name == "deadlinegrant" || name == "deadlinecaller" {
			d, ok := ctx.Deadline()
			if !ok {
				t.Error("runner context has no deadline")
			} else {
				var want time.Time
				switch name {
				case "deadline60":
					if d.Before(started.Add(time.Minute)) || d.After(started.Add(time.Minute+time.Second)) || d.After(time.Now().Add(time.Minute)) {
						t.Errorf("deadline=%s outside 60-second bounds from %s", d, started)
					}
					return 0, err
				case "deadlinegrant":
					want, _ = time.Parse(time.RFC3339, loaded.ExpiresAt)
				case "deadlinecaller":
					want = callerDeadline
				}
				if !d.Equal(want) {
					t.Errorf("deadline=%s, want exactly %s", d, want)
				}
			}
		}
		return 0, err
	})
	adapter, err := appstorecrypto.NewTextAdapter(context.Background(), installation, grant.ID, grant.Profile, grant.CredentialSHA256, runner)
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	selected, want := []byte(refs[0]), []byte("secret")
	switch name {
	case "multi":
		selected = []byte("x=" + refs[0] + ";y=" + refs[1] + ";z=" + refs[0])
		want = []byte("x=alpha;y=beta;z=alpha")
	case "aggregate", "aggregatecontrol":
		// Keep selected output under the output limit so this isolates aggregate expansion.
		selected = []byte(refs[0])
		want = values[0]
	case "output":
		selected = []byte(strings.Repeat(refs[0], 17))
	case "outputcontrol":
		selected = []byte(refs[0])
		want = values[0]
	}
	ctx := context.Background()
	var cancel context.CancelFunc = func() {}
	if name == "deadlinecaller" {
		callerDeadline = time.Now().Add(20 * time.Second)
		ctx, cancel = context.WithDeadline(ctx, callerDeadline)
	}
	defer cancel()
	started = time.Now()
	outcome := adapter.Hydrate(ctx, "AAECAwQFBgcICQoLDA0ODw", grant.File, selected)
	if name == "multi" || name == "aggregatecontrol" || name == "outputcontrol" {
		if outcome.Status != appstorecrypto.DeliveryReceived || calls != 1 || !bytes.Equal(gotInput, want) {
			t.Fatalf("%s outcome=%v calls=%d input mismatch", name, outcome.Status, calls)
		}
		return
	}
	if name == "aggregate" || name == "output" {
		if outcome.Status != appstorecrypto.DeliveryWithheld || calls != 0 {
			t.Fatalf("%s outcome=%v calls=%d", name, outcome.Status, calls)
		}
		return
	}
	if outcome.Status != appstorecrypto.DeliveryReceived || calls != 1 || !bytes.Equal(gotInput, []byte("secret")) {
		t.Fatalf("%s outcome=%v calls=%d", name, outcome.Status, calls)
	}
}

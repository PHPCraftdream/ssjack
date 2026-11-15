//go:build linux

package appstoresink

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func setPeerSettle(t *testing.T, d time.Duration) {
	t.Helper()
	old := peerSettle
	peerSettle = d
	t.Cleanup(func() { peerSettle = old })
}

// A freshly started child can still show the forked parent image in /proc; the
// shell holds the pre-exec state open until the test releases it.
func TestWaitPeerFollowsExecIntoExpectedProgram(t *testing.T) {
	path, _ := fixedFixture(t)
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	identity := [2]uint64{uint64(st.Dev), st.Ino}
	cmd := exec.Command("/bin/sh", "-c", `read line; exec /usr/bin/env -i "$0"`, path)
	cmd.Env = []string{}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	pid := cmd.Process.Pid
	if err := checkPeer(pid, identity); !errors.Is(err, ErrDenied) {
		t.Fatalf("a different program was accepted before exec: %v", err)
	}
	release := time.AfterFunc(100*time.Millisecond, func() { _, _ = stdin.Write([]byte("\n")) })
	defer release.Stop()
	if err := waitPeer(context.Background(), pid, identity); err != nil {
		t.Fatalf("expected program was not recognised after exec: %v", err)
	}
}

func TestWaitPeerStopsOnWrongProgramUnreadablePeerAndCancellation(t *testing.T) {
	setPeerSettle(t, 500*time.Millisecond)
	start := time.Now()
	if err := waitPeer(context.Background(), os.Getpid(), [2]uint64{}); !errors.Is(err, ErrDenied) {
		t.Fatalf("wrong program was accepted: %v", err)
	}
	if time.Since(start) < 450*time.Millisecond {
		t.Fatal("a mismatching peer was not retried for the settle window")
	}
	start = time.Now()
	if err := waitPeer(context.Background(), 1<<30, [2]uint64{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unreadable peer: %v", err)
	}
	if time.Since(start) > 400*time.Millisecond {
		t.Fatal("an unreadable peer was retried")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start = time.Now()
	if err := waitPeer(ctx, os.Getpid(), [2]uint64{}); !errors.Is(err, ErrDenied) {
		t.Fatalf("cancelled wait: %v", err)
	}
	if time.Since(start) > 400*time.Millisecond {
		t.Fatal("a cancelled wait kept retrying")
	}
}

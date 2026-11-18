package engine

import (
	"context"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferengine/internal/testfixture"
	"github.com/PHPCraftdream/ssjack/internal/transferremote"
)

func TestStallErrorClassification(t *testing.T) {
	live := &uploadJob{ctx: context.Background()}
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	dead := &uploadJob{ctx: gone}
	remoteExit := &transfercore.Error{Class: transfercore.ClassRemoteFailed, Message: "remote operation failed", ExitCode: 24}

	if err := live.stallError(nil, true); err != nil {
		t.Fatalf("nil error became %v", err)
	}
	if err := live.stallError(testfixture.CancelledError(), true); !transferremote.IsLinkFailure(err) {
		t.Fatalf("stalled cancellation = %v, want a link failure", err)
	}
	if err := live.stallError(context.Canceled, true); !transferremote.IsLinkFailure(err) {
		t.Fatalf("stalled raw cancellation = %v, want a link failure", err)
	}
	if err := live.stallError(testfixture.CancelledError(), false); transfercore.ClassOf(err) != transfercore.ClassCancelled {
		t.Fatalf("unstalled cancellation = %v, want cancelled", err)
	}
	if err := dead.stallError(testfixture.CancelledError(), true); transfercore.ClassOf(err) != transfercore.ClassCancelled || transferremote.IsLinkFailure(err) {
		t.Fatalf("manager cancel with a stall = %v, want cancelled", err)
	}
	if err := live.stallError(remoteExit, true); err != remoteExit {
		t.Fatalf("a remote exit status was rewritten to %v", err)
	}
}

func TestDownloadStallErrorClassification(t *testing.T) {
	live := &downloadJob{ctx: context.Background()}
	gone, cancel := context.WithCancel(context.Background())
	cancel()
	dead := &downloadJob{ctx: gone}
	remoteExit := &transfercore.Error{Class: transfercore.ClassRemoteFailed, Message: "remote operation failed", ExitCode: 24}

	if err := live.stallError(nil, true); err != nil {
		t.Fatalf("nil error became %v", err)
	}
	if err := live.stallError(testfixture.CancelledError(), true); !transferremote.IsLinkFailure(err) {
		t.Fatalf("stalled cancellation = %v, want a link failure", err)
	}
	if err := live.stallError(testfixture.CancelledError(), false); transfercore.ClassOf(err) != transfercore.ClassCancelled {
		t.Fatalf("unstalled cancellation = %v, want cancelled", err)
	}
	if err := dead.stallError(testfixture.CancelledError(), true); transfercore.ClassOf(err) != transfercore.ClassCancelled || transferremote.IsLinkFailure(err) {
		t.Fatalf("job cancel with a stall = %v, want cancelled", err)
	}
	if err := live.stallError(remoteExit, true); err != remoteExit {
		t.Fatalf("a remote exit status was rewritten to %v", err)
	}
}

func TestNewWithOptionsRejectsNegativeStallLimit(t *testing.T) {
	if _, err := NewWithOptions(testfixture.NewFakeChunkRemote(testfixture.NewVClock()), transfercore.DefaultLimits(), Options{StallLimit: -1}); err == nil {
		t.Fatal("NewWithOptions accepted a negative stall limit")
	}
}

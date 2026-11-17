package transfer

import (
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

func TestStatusLinkUnstableHasItsFixedMessage(t *testing.T) {
	fake := &fakeEngine{err: transfercore.Fail(transfercore.ClassLinkUnstable, transfercore.MsgLinkUnstable)}
	m := newTestManager(t, fake)
	start := startJob(t, m, false, "a", "/a")
	out := waitForState(t, m, start.JobID, "")
	if out.State != string(stateFailed) || out.ErrorClass != "link_unstable" {
		t.Fatalf("status = %+v", out)
	}
	if out.Message != "transfer link was too unstable to finish; a retry can resume" {
		t.Fatalf("message = %q", out.Message)
	}
}

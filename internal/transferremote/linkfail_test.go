package transferremote

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferremote/core"
)

func TestIsLinkFailureRecognizesOnlySessionsWithoutExitStatus(t *testing.T) {
	if !IsLinkFailure(LinkFailure()) {
		t.Fatal("LinkFailure() is not a link failure")
	}
	if !IsLinkFailure(fmt.Errorf("wrapped: %w", LinkFailure())) {
		t.Fatal("a wrapped link failure is not recognised")
	}
	for name, err := range map[string]error{
		"nil":            nil,
		"plain":          errors.New("boom"),
		"remote exit":    core.Classed(transfercore.ClassRemoteFailed, core.MsgRemoteFailed, core.ExitRemoteFailed),
		"local failure":  core.Classed(transfercore.ClassRemoteFailed, core.MsgRemoteFailed, -1),
		"cancelled":      core.Classed(transfercore.ClassCancelled, core.MsgCancelled, -1),
		"integrity":      core.Classed(transfercore.ClassIntegrity, core.MsgIntegrity, -1),
		"unsupported":    core.Classed(transfercore.ClassUnsupportedRemote, core.MsgUnsupported, core.ExitUnsupported),
		"staging absent": core.Classed(transfercore.ClassRemoteFailed, core.MsgRemoteFailed, ExitStageMissing),
	} {
		if IsLinkFailure(err) {
			t.Errorf("%s was classified as a link failure", name)
		}
	}
}

func TestExecuteReportsATransportErrorAsLinkFailure(t *testing.T) {
	runner := &fakeRunner{Respond: func(string, io.Reader, io.Writer, io.Writer) (int, error) {
		return -1, errors.New("SSH command did not terminate normally")
	}}
	r := New(runner.Run, "target", transfercore.DefaultLimits())
	_, err := r.CreateStaging(context.Background(), "/data")
	if !IsLinkFailure(err) {
		t.Fatalf("transport error = %v, want a link failure", err)
	}
	expectClass(t, err, transfercore.ClassRemoteFailed)
}

func TestExecuteDoesNotReportAnExitStatusAsLinkFailure(t *testing.T) {
	runner := &fakeRunner{Respond: func(string, io.Reader, io.Writer, io.Writer) (int, error) {
		return core.ExitRemoteFailed, nil
	}}
	r := New(runner.Run, "target", transfercore.DefaultLimits())
	_, err := r.CreateStaging(context.Background(), "/data")
	if err == nil || IsLinkFailure(err) {
		t.Fatalf("remote exit status = %v, want a non-link failure", err)
	}
	expectClass(t, err, transfercore.ClassRemoteFailed)
}

func TestExecuteDoesNotReportCancellationAsLinkFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	runner := &fakeRunner{Respond: func(string, io.Reader, io.Writer, io.Writer) (int, error) {
		cancel()
		return -1, ctx.Err()
	}}
	r := New(runner.Run, "target", transfercore.DefaultLimits())
	_, err := r.CreateStaging(ctx, "/data")
	if IsLinkFailure(err) {
		t.Fatalf("cancellation = %v, want not a link failure", err)
	}
	expectClass(t, err, transfercore.ClassCancelled)
}

package transferremote

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
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
		"remote exit":    classed(transfercore.ClassRemoteFailed, msgRemoteFailed, exitRemoteFailed),
		"local failure":  classed(transfercore.ClassRemoteFailed, msgRemoteFailed, -1),
		"cancelled":      classed(transfercore.ClassCancelled, msgCancelled, -1),
		"integrity":      classed(transfercore.ClassIntegrity, msgIntegrity, -1),
		"unsupported":    classed(transfercore.ClassUnsupportedRemote, msgUnsupported, exitUnsupported),
		"staging absent": classed(transfercore.ClassRemoteFailed, msgRemoteFailed, ExitStageMissing),
	} {
		if IsLinkFailure(err) {
			t.Errorf("%s was classified as a link failure", name)
		}
	}
}

func TestExecuteReportsATransportErrorAsLinkFailure(t *testing.T) {
	runner := &fakeRunner{respond: func(string, io.Reader, io.Writer, io.Writer) (int, error) {
		return -1, errors.New("SSH command did not terminate normally")
	}}
	r := New(runner.run, "target", transfercore.DefaultLimits())
	_, err := r.CreateStaging(context.Background(), "/data")
	if !IsLinkFailure(err) {
		t.Fatalf("transport error = %v, want a link failure", err)
	}
	expectClass(t, err, transfercore.ClassRemoteFailed)
}

func TestExecuteDoesNotReportAnExitStatusAsLinkFailure(t *testing.T) {
	runner := &fakeRunner{respond: func(string, io.Reader, io.Writer, io.Writer) (int, error) {
		return exitRemoteFailed, nil
	}}
	r := New(runner.run, "target", transfercore.DefaultLimits())
	_, err := r.CreateStaging(context.Background(), "/data")
	if err == nil || IsLinkFailure(err) {
		t.Fatalf("remote exit status = %v, want a non-link failure", err)
	}
	expectClass(t, err, transfercore.ClassRemoteFailed)
}

func TestExecuteDoesNotReportCancellationAsLinkFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	runner := &fakeRunner{respond: func(string, io.Reader, io.Writer, io.Writer) (int, error) {
		cancel()
		return -1, ctx.Err()
	}}
	r := New(runner.run, "target", transfercore.DefaultLimits())
	_, err := r.CreateStaging(ctx, "/data")
	if IsLinkFailure(err) {
		t.Fatalf("cancellation = %v, want not a link failure", err)
	}
	expectClass(t, err, transfercore.ClassCancelled)
}

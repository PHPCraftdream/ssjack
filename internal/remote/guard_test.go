package remote

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/outputguard"
)

func jobGuard(t *testing.T) GuardProvider {
	t.Helper()
	snapshot, err := outputguard.New([][]byte{[]byte("synthetic-secret"), {'b', 0, 255}})
	if err != nil {
		t.Fatal(err)
	}
	return func(context.Context) (*outputguard.Snapshot, error) { return snapshot, nil }
}

func TestGuardedJobsCaptureOnlyFilteredBytesAcrossWritesAndReads(t *testing.T) {
	m := NewGuardedManager(context.Background(), []string{"test"}, func(_ context.Context, _, _ string, out, errOut io.Writer) (int, error) {
		for _, value := range []byte("before|synthetic-secret|b\x00\xff|after\xfe") {
			if _, err := out.Write([]byte{value}); err != nil {
				return -1, err
			}
		}
		_, err := errOut.Write([]byte("synthetic-secret"))
		return 7, err
	}, jobGuard(t))
	defer m.Close()
	started, err := m.Start(StartInput{Target: "test", Command: "synthetic"})
	if err != nil {
		t.Fatal(err)
	}
	awaitJob(t, m, started.JobID)
	out, err := m.Read(ReadInput{JobID: started.JobID})
	want := []byte("before|[REDACTED]|[REDACTED]|after\xfe")
	if err != nil || !out.Done || out.ExitCode != 7 || out.Error != "" || !bytes.Equal(out.Stdout, want) || string(out.Stderr) != outputguard.Marker || out.StdoutOffset != int64(len(want)) || out.StderrOffset != int64(len(outputguard.Marker)) {
		t.Fatal("guard changed control fields or captured raw output")
	}
	for offset := range len(want) + 1 {
		reread, err := m.Read(ReadInput{JobID: started.JobID, StdoutOffset: int64(offset)})
		if err != nil || !bytes.Equal(reread.Stdout, want[offset:]) {
			t.Fatal("arbitrary read offsets did not address the filtered view")
		}
	}
}

func TestGuardedJobWithholdsPotentialPrefixUntilContinuation(t *testing.T) {
	ready, release := make(chan struct{}), make(chan struct{})
	m := NewGuardedManager(context.Background(), []string{"test"}, func(ctx context.Context, _, _ string, out, errOut io.Writer) (int, error) {
		if _, err := out.Write([]byte("synthetic-")); err != nil {
			return -1, err
		}
		close(ready)
		select {
		case <-ctx.Done():
			return -1, ctx.Err()
		case <-release:
		}
		if _, err := out.Write([]byte("secret")); err != nil {
			return -1, err
		}
		_, err := errOut.Write([]byte("public-tail"))
		return 0, err
	}, jobGuard(t))
	defer m.Close()
	started, err := m.Start(StartInput{Target: "test", Command: "synthetic"})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("runner did not reach controlled prefix barrier")
	}
	out, err := m.Read(ReadInput{JobID: started.JobID})
	if err != nil || out.Done || len(out.Stdout) != 0 || out.StdoutOffset != 0 {
		t.Fatal("running read released an undecided secret prefix")
	}
	close(release)
	awaitJob(t, m, started.JobID)
	out, err = m.Read(ReadInput{JobID: started.JobID})
	if err != nil || !out.Done || string(out.Stdout) != outputguard.Marker || string(out.Stderr) != "public-tail" {
		t.Fatal("stream completion lost replacement or safe final tail")
	}
}

func TestGuardUnavailablePreventsRunnerAndNeverFormatsPrivateErrors(t *testing.T) {
	for _, provider := range []GuardProvider{nil,
		func(context.Context) (*outputguard.Snapshot, error) { return nil, privateJobError{} },
		func(context.Context) (*outputguard.Snapshot, error) { return &outputguard.Snapshot{}, nil },
	} {
		var calls atomic.Int32
		m := NewGuardedManager(context.Background(), []string{"test"}, func(context.Context, string, string, io.Writer, io.Writer) (int, error) {
			calls.Add(1)
			return 0, nil
		}, provider)
		started, err := m.Start(StartInput{Target: "test", Command: "synthetic"})
		if err != nil {
			m.Close()
			t.Fatal(err)
		}
		awaitJob(t, m, started.JobID)
		out, err := m.Read(ReadInput{JobID: started.JobID})
		m.Close()
		if err != nil || calls.Load() != 0 || !out.Done || out.Error != outputguard.ErrGuard.Error() || len(out.Stdout)+len(out.Stderr) != 0 {
			t.Fatal("guard refusal executed runner or exposed private diagnostics")
		}
	}
}

type privateJobError struct{}

func (privateJobError) Error() string { panic("private error must never be formatted") }

func TestGuardedRunnerErrorUsesFixedDiagnosticAndClosesBothStreams(t *testing.T) {
	m := NewGuardedManager(context.Background(), []string{"test"}, func(_ context.Context, _, _ string, out, errOut io.Writer) (int, error) {
		_, first := out.Write([]byte("synthetic-secret|safe"))
		_, second := errOut.Write([]byte("synthetic-secret|tail"))
		if first != nil || second != nil {
			return -1, errors.New("synthetic sink failure")
		}
		return 23, privateJobError{}
	}, jobGuard(t))
	defer m.Close()
	started, err := m.Start(StartInput{Target: "test", Command: "synthetic"})
	if err != nil {
		t.Fatal(err)
	}
	awaitJob(t, m, started.JobID)
	out, err := m.Read(ReadInput{JobID: started.JobID})
	if err != nil || !out.Done || out.ExitCode != 23 || out.Error != ErrJob.Error() || string(out.Stdout) != "[REDACTED]|safe" || string(out.Stderr) != "[REDACTED]|tail" {
		t.Fatal("runner error leaked diagnostics, lost safe tails or changed exit code")
	}
}

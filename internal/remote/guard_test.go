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

func admittedGuard(t *testing.T, secret string) *outputguard.Snapshot {
	t.Helper()
	snapshot, err := outputguard.New([][]byte{[]byte(secret)})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestAdmittedOperationIsCapturedBeforeStartReturns(t *testing.T) {
	guard := admittedGuard(t, "admitted-secret")
	var issued atomic.Int32
	h := newAdmissionTestHarness(t, func(h *admissionTestHarness) AdmissionProvider {
		return func(_ context.Context, _, _ string) (AdmittedOperation, error) {
			close(h.entered)
			select {
			case <-h.release:
			case <-h.ctx.Done():
				return AdmittedOperation{}, h.ctx.Err()
			}
			return AdmittedOperation{
				Guard:  guard,
				Issued: func() { issued.Add(1) },
				Runner: func(_ context.Context, _, _ string, stdout, _ io.Writer) (int, error) {
					if issued.Load() != 1 {
						return -1, errors.New("runner started before issuance")
					}
					_, err := stdout.Write([]byte("admitted-secret"))
					return 0, err
				},
			}, nil
		}
	})
	h.start(StartInput{Target: "test", Command: "run"})
	h.wait(t, h.entered, "admission provider did not reach barrier")
	select {
	case <-h.startResult:
		t.Fatal("Start returned before admission completed")
	default:
	}
	h.openGate()
	if !h.awaitStart(t) {
		return
	}
	if h.startErr != nil || issued.Load() != 1 {
		t.Fatal("admission failed or issuance did not precede the worker")
	}
	awaitJob(t, h.manager, h.started.JobID)
	out, err := h.manager.Read(ReadInput{JobID: h.started.JobID})
	if err != nil || !out.Done || string(out.Stdout) != outputguard.Marker {
		t.Fatal("admitted runner did not use its captured guard")
	}
}

func TestAdmissionFailureAndIncompleteCaptureScheduleNoJob(t *testing.T) {
	var issued atomic.Int32
	validRunner := Runner(func(context.Context, string, string, io.Writer, io.Writer) (int, error) { return 0, nil })
	cases := []struct {
		name     string
		provider AdmissionProvider
	}{
		{"provider error", func(context.Context, string, string) (AdmittedOperation, error) {
			return AdmittedOperation{Issued: func() { issued.Add(1) }}, privateJobError{}
		}},
		{"missing runner", func(context.Context, string, string) (AdmittedOperation, error) {
			return AdmittedOperation{Guard: admittedGuard(t, "secret"), Issued: func() { issued.Add(1) }}, nil
		}},
		{"missing guard", func(context.Context, string, string) (AdmittedOperation, error) {
			return AdmittedOperation{Runner: validRunner, Issued: func() { issued.Add(1) }}, nil
		}},
		{"invalid guard", func(context.Context, string, string) (AdmittedOperation, error) {
			return AdmittedOperation{Runner: validRunner, Guard: &outputguard.Snapshot{}, Issued: func() { issued.Add(1) }}, nil
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			issued.Store(0)
			m := NewAdmittedManager(context.Background(), []string{"test"}, test.provider)
			started, err := m.Start(StartInput{Target: "test", Command: "run"})
			m.Close()
			if err != ErrAdmission || started.JobID != "" || len(m.jobs) != 0 || m.active != 0 || issued.Load() != 0 {
				t.Fatal("failed admission created a scheduled job or exposed provider diagnostics")
			}
		})
	}
}

func TestCapturedAdmissionSurvivesProviderChangeBeforeReturn(t *testing.T) {
	oldGuard := admittedGuard(t, "old-secret")
	newGuard := admittedGuard(t, "new-secret")
	current := AdmittedOperation{
		Guard: oldGuard,
		Runner: func(_ context.Context, _, _ string, stdout, _ io.Writer) (int, error) {
			_, err := stdout.Write([]byte("old-secret"))
			return 0, err
		},
	}
	var providerCalls atomic.Int32
	h := newAdmissionTestHarness(t, func(h *admissionTestHarness) AdmissionProvider {
		return func(_ context.Context, _, _ string) (AdmittedOperation, error) {
			providerCalls.Add(1)
			admitted := current
			close(h.entered)
			select {
			case <-h.release:
			case <-h.ctx.Done():
				return AdmittedOperation{}, h.ctx.Err()
			}
			return admitted, nil
		}
	})
	h.start(StartInput{Target: "test", Command: "run"})
	h.wait(t, h.entered, "admission provider did not reach barrier")
	current = AdmittedOperation{
		Guard: newGuard,
		Runner: func(_ context.Context, _, _ string, stdout, _ io.Writer) (int, error) {
			_, err := stdout.Write([]byte("new-runner"))
			return 0, err
		},
	}
	h.openGate()
	if !h.awaitStart(t) {
		return
	}
	if h.startErr != nil || providerCalls.Load() != 1 {
		t.Fatal("admission was not captured synchronously")
	}
	awaitJob(t, h.manager, h.started.JobID)
	out, err := h.manager.Read(ReadInput{JobID: h.started.JobID})
	if err != nil || !out.Done || string(out.Stdout) != outputguard.Marker {
		t.Fatal("worker did not use the admitted runner and guard")
	}
}

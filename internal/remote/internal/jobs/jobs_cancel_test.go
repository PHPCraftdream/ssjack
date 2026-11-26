package remote

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

func blockingRunner(ctx context.Context, _, _ string, _, _ io.Writer) (int, error) {
	<-ctx.Done()
	return -1, ctx.Err()
}

func TestCancelAnswersTruthfully(t *testing.T) {
	t.Run("cancel running job reports cancelled and ends cancelled", func(t *testing.T) {
		m := NewManager(context.Background(), []string{"test"}, blockingRunner)
		defer m.Close()
		started, err := m.Start(StartInput{Target: "test", Command: "wait"})
		if err != nil {
			t.Fatal(err)
		}
		result, err := m.Cancel(started.JobID)
		if err != nil || !result.Cancelled {
			t.Fatalf("Cancel() = %+v, %v", result, err)
		}
		awaitJob(t, m, started.JobID)
		got, err := m.Read(ReadInput{JobID: started.JobID})
		if err != nil {
			t.Fatal(err)
		}
		if !got.Done || got.ExitCode != -1 || got.Error != "context canceled" {
			t.Fatalf("Read() = %+v, want fixed error text %q", got, "context canceled")
		}
	})

	t.Run("cancel of done job reports not cancelled and keeps recorded state", func(t *testing.T) {
		runner := func(_ context.Context, _, _ string, stdout, _ io.Writer) (int, error) {
			_, _ = io.WriteString(stdout, "ok")
			return 0, nil
		}
		m := NewManager(context.Background(), []string{"test"}, runner)
		defer m.Close()
		started, err := m.Start(StartInput{Target: "test", Command: "done"})
		if err != nil {
			t.Fatal(err)
		}
		awaitJob(t, m, started.JobID)
		snapshot, err := m.Read(ReadInput{JobID: started.JobID})
		if err != nil {
			t.Fatal(err)
		}
		result, err := m.Cancel(started.JobID)
		if err != nil || result.Cancelled {
			t.Fatalf("Cancel() = %+v, %v", result, err)
		}
		got, err := m.Read(ReadInput{JobID: started.JobID})
		if err != nil {
			t.Fatal(err)
		}
		if string(got.Stdout) != string(snapshot.Stdout) || got.Done != snapshot.Done || got.ExitCode != snapshot.ExitCode || got.Error != snapshot.Error {
			t.Fatalf("state changed: before %+v after %+v", snapshot, got)
		}
	})

	t.Run("cancel of failed job reports not cancelled", func(t *testing.T) {
		runner := func(context.Context, string, string, io.Writer, io.Writer) (int, error) { return 3, errors.New("boom") }
		m := NewManager(context.Background(), []string{"test"}, runner)
		defer m.Close()
		started, err := m.Start(StartInput{Target: "test", Command: "fail"})
		if err != nil {
			t.Fatal(err)
		}
		awaitJob(t, m, started.JobID)
		snapshot, err := m.Read(ReadInput{JobID: started.JobID})
		if err != nil {
			t.Fatal(err)
		}
		result, err := m.Cancel(started.JobID)
		if err != nil || result.Cancelled {
			t.Fatalf("Cancel() = %+v, %v", result, err)
		}
		got, err := m.Read(ReadInput{JobID: started.JobID})
		if err != nil {
			t.Fatal(err)
		}
		if snapshot.ExitCode != 3 || snapshot.Error != "boom" || string(got.Stdout) != string(snapshot.Stdout) || got.Done != snapshot.Done || got.ExitCode != snapshot.ExitCode || got.Error != snapshot.Error {
			t.Fatalf("state changed: before %+v after %+v", snapshot, got)
		}
	})

	t.Run("cancel of timed out job reports not cancelled", func(t *testing.T) {
		m := NewManager(context.Background(), []string{"test"}, blockingRunner)
		defer m.Close()
		started, err := m.Start(StartInput{Target: "test", Command: "wait", TimeoutSeconds: 1})
		if err != nil {
			t.Fatal(err)
		}
		awaitJob(t, m, started.JobID)
		snapshot, err := m.Read(ReadInput{JobID: started.JobID})
		if err != nil {
			t.Fatal(err)
		}
		result, err := m.Cancel(started.JobID)
		if err != nil || result.Cancelled {
			t.Fatalf("Cancel() = %+v, %v", result, err)
		}
		got, err := m.Read(ReadInput{JobID: started.JobID})
		if err != nil {
			t.Fatal(err)
		}
		if !snapshot.Done || snapshot.Error != context.DeadlineExceeded.Error() || string(got.Stdout) != string(snapshot.Stdout) || got.Done != snapshot.Done || got.ExitCode != snapshot.ExitCode || got.Error != snapshot.Error {
			t.Fatalf("state changed: before %+v after %+v", snapshot, got)
		}
	})

	t.Run("cancel of already cancelled job reports not cancelled", func(t *testing.T) {
		m := NewManager(context.Background(), []string{"test"}, blockingRunner)
		defer m.Close()
		started, err := m.Start(StartInput{Target: "test", Command: "wait"})
		if err != nil {
			t.Fatal(err)
		}
		first, err := m.Cancel(started.JobID)
		if err != nil || !first.Cancelled {
			t.Fatalf("first Cancel() = %+v, %v", first, err)
		}
		awaitJob(t, m, started.JobID)
		second, err := m.Cancel(started.JobID)
		if err != nil || second.Cancelled {
			t.Fatalf("second Cancel() = %+v, %v", second, err)
		}
		got, err := m.Read(ReadInput{JobID: started.JobID})
		if err != nil {
			t.Fatal(err)
		}
		if got.ExitCode != -1 || !strings.Contains(got.Error, "canceled") {
			t.Fatalf("Read() = %+v", got)
		}
	})

	t.Run("cancel of unknown id errors", func(t *testing.T) {
		m := NewManager(context.Background(), []string{"test"}, blockingRunner)
		defer m.Close()
		_, err := m.Cancel("no-such-job")
		if err == nil || !strings.Contains(err.Error(), "unknown operation") {
			t.Fatalf("Cancel() error = %v", err)
		}
	})

	t.Run("cancel racing finish keeps the runner's own outcome", func(t *testing.T) {
		for i := range 25 {
			release := make(chan struct{})
			wantExit := 0
			var wantErr error
			if i%2 != 0 {
				wantExit, wantErr = 3, errors.New("boom")
			}
			runner := func(ctx context.Context, _, _ string, stdout, _ io.Writer) (int, error) {
				select {
				case <-ctx.Done():
					return -1, ctx.Err()
				case <-release:
					_, _ = io.WriteString(stdout, "ok")
					return wantExit, wantErr
				}
			}
			m := NewManager(context.Background(), []string{"test"}, runner)
			started, err := m.Start(StartInput{Target: "test", Command: "race"})
			if err != nil {
				t.Fatalf("iteration %d: Start() error = %v", i, err)
			}
			close(release)
			result, err := m.Cancel(started.JobID)
			if err != nil {
				t.Fatalf("iteration %d: Cancel() error = %v", i, err)
			}
			awaitJob(t, m, started.JobID)
			got, err := m.Read(ReadInput{JobID: started.JobID})
			if err != nil {
				t.Fatalf("iteration %d: Read() error = %v", i, err)
			}
			wantError := ""
			if wantErr != nil {
				wantError = wantErr.Error()
			}
			isReleased := got.ExitCode == wantExit && got.Error == wantError && string(got.Stdout) == "ok"
			if !result.Cancelled {
				if !isReleased {
					t.Fatalf("iteration %d: Cancel=%+v Read=%+v, want released outcome", i, result, got)
				}
			} else {
				isCancelled := got.ExitCode == -1 && got.Error == context.Canceled.Error()
				if !isReleased && !isCancelled {
					t.Fatalf("iteration %d: Cancel=%+v Read=%+v, want released or cancellation outcome", i, result, got)
				}
			}
			m.Close()
		}
	})

	t.Run("cancel while the runner is still running, then the runner succeeds, keeps the runner's own success", func(t *testing.T) {
		started := make(chan struct{})
		release := make(chan struct{})
		releaseOnce := sync.OnceFunc(func() { close(release) })
		m := NewManager(context.Background(), []string{"test"}, func(_ context.Context, _, _ string, stdout, _ io.Writer) (int, error) {
			close(started)
			<-release
			_, _ = io.WriteString(stdout, "late output")
			return 0, nil
		})
		defer m.Close()
		defer releaseOnce()
		job, err := m.Start(StartInput{Target: "test", Command: "wait"})
		if err != nil {
			t.Fatal(err)
		}
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("runner never started")
		}
		result, err := m.Cancel(job.JobID)
		if err != nil || !result.Cancelled {
			t.Fatalf("Cancel() = %+v, %v", result, err)
		}
		releaseOnce()
		awaitJob(t, m, job.JobID)
		got, err := m.Read(ReadInput{JobID: job.JobID})
		if err != nil {
			t.Fatal(err)
		}
		if !got.Done || got.ExitCode != 0 || got.Error != "" || string(got.Stdout) != "late output" {
			t.Fatalf("runner outcome rewritten: Read() = %+v", got)
		}
	})

	t.Run("cancel while the runner is still running, then the runner fails, keeps the runner's own failure", func(t *testing.T) {
		started := make(chan struct{})
		release := make(chan struct{})
		releaseOnce := sync.OnceFunc(func() { close(release) })
		m := NewManager(context.Background(), []string{"test"}, func(_ context.Context, _, _ string, _, _ io.Writer) (int, error) {
			close(started)
			<-release
			return 3, errors.New("boom")
		})
		defer m.Close()
		defer releaseOnce()
		job, err := m.Start(StartInput{Target: "test", Command: "wait"})
		if err != nil {
			t.Fatal(err)
		}
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("runner never started")
		}
		result, err := m.Cancel(job.JobID)
		if err != nil || !result.Cancelled {
			t.Fatalf("Cancel() = %+v, %v", result, err)
		}
		releaseOnce()
		awaitJob(t, m, job.JobID)
		got, err := m.Read(ReadInput{JobID: job.JobID})
		if err != nil {
			t.Fatal(err)
		}
		if !got.Done || got.ExitCode != 3 || got.Error != "boom" {
			t.Fatalf("runner outcome rewritten: Read() = %+v", got)
		}
	})

	t.Run("cancel of an evicted id errors like an unknown id", func(t *testing.T) {
		runner := func(context.Context, string, string, io.Writer, io.Writer) (int, error) { return 0, nil }
		m := NewManager(context.Background(), []string{"test"}, runner)
		defer m.Close()
		var firstID string
		for i := 0; i < maxJobs; i++ {
			started, err := m.Start(StartInput{Target: "test", Command: "done"})
			if err != nil {
				t.Fatalf("start %d: %v", i, err)
			}
			if i == 0 {
				firstID = started.JobID
			}
			awaitJob(t, m, started.JobID)
		}
		if _, err := m.Start(StartInput{Target: "test", Command: "evict"}); err != nil {
			t.Fatal(err)
		}
		evictedErr := func() error {
			_, err := m.Cancel(firstID)
			return err
		}()
		unknownErr := func() error {
			_, err := m.Cancel("no-such-job")
			return err
		}()
		if evictedErr == nil || unknownErr == nil || evictedErr.Error() != unknownErr.Error() {
			t.Fatalf("Cancel(evicted) error = %v, Cancel(unknown) error = %v", evictedErr, unknownErr)
		}
	})
}

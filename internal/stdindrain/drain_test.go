package stdindrain

import (
	"bytes"
	"testing"
	"time"
)

func TestDrainClampsPollWaitToOverallDeadline(t *testing.T) {
	var got time.Duration
	err := Drain(MaxDuration+time.Second, MaxBytes, func(wait time.Duration) (bool, error) {
		got = wait
		return false, nil
	}, func([]byte) (int, error) { t.Fatal("read called without readiness"); return 0, nil })
	if err != nil {
		t.Fatalf("Drain() error = %v", err)
	}
	if got <= 0 || got > MaxDuration {
		t.Fatalf("poll wait=%v, want >0 and <= %v", got, MaxDuration)
	}
}

func TestDrainOverallDeadlineWithQueuedData(t *testing.T) {
	readCalled := false
	err := Drain(time.Millisecond, MaxBytes, func(time.Duration) (bool, error) {
		time.Sleep(MaxDuration + time.Millisecond)
		return true, nil
	}, func([]byte) (int, error) {
		readCalled = true
		return 1, nil
	})
	if err != ErrDrain {
		t.Fatalf("Drain() error = %v, want %v", err, ErrDrain)
	}
	if readCalled {
		t.Fatal("read called after overall deadline")
	}
}

func TestDrainByteLimitWithQueuedData(t *testing.T) {
	input := bytes.NewBufferString("more data than the drain limit")
	poll := func(time.Duration) (bool, error) { return input.Len() != 0, nil }
	read := func(p []byte) (int, error) { return input.Read(p) }
	if err := Drain(time.Millisecond, 4, poll, read); err != ErrDrain {
		t.Fatalf("Drain() error = %v, want %v", err, ErrDrain)
	}
	if input.Len() == 0 {
		t.Fatal("test requires queued input after byte limit")
	}
}

func TestDrainConsumesRejectedInputBeforeResumedReader(t *testing.T) {
	const secretLimit = 4
	const sentinel = "-TAIL-SENTINEL"
	run := func(t *testing.T, inputText string, parserRead int, marker string) {
		t.Helper()
		input := bytes.NewBufferString(inputText)
		parserReadBytes := make([]byte, parserRead)
		n, err := input.Read(parserReadBytes)
		if err != nil || n != parserRead {
			t.Fatalf("setup read length=%d, want=%d (marker=%s)", n, parserRead, marker)
		}
		if got := input.Len(); got != len(sentinel) {
			t.Fatalf("setup tail length=%d, want=%d (marker=%s)", got, len(sentinel), marker)
		}

		var drained bytes.Buffer
		poll := func(time.Duration) (bool, error) { return input.Len() != 0, nil }
		read := func(p []byte) (int, error) {
			n, err := input.Read(p)
			if n > 0 {
				_, _ = drained.Write(p[:n])
			}
			return n, err
		}
		if err := Drain(time.Millisecond, 64, poll, read); err != nil {
			t.Fatalf("bounded drain rejected tail (marker=%s, length=%d): %v", marker, input.Len(), err)
		}
		if got := drained.Len(); got != len(sentinel) {
			t.Fatalf("drained length=%d, want=%d (marker=%s)", got, len(sentinel), marker)
		}
		if input.Len() != 0 {
			t.Fatalf("remaining input length=%d (marker=%s)", input.Len(), marker)
		}

		ready, err := poll(time.Millisecond)
		if err != nil {
			t.Fatal("resumed-reader readiness check failed")
		}
		if ready {
			t.Fatalf("resumed reader observed queued data (marker=%s, length=%d)", marker, input.Len())
		}
	}
	t.Run("invalid-control", func(t *testing.T) { run(t, "a\x01"+sentinel, 2, "control") })
	t.Run("over-limit", func(t *testing.T) { run(t, "abcde"+sentinel, secretLimit+1, "limit") })
	t.Run("escape", func(t *testing.T) { run(t, "\x1b"+sentinel, 1, "escape") })
	t.Run("ctrl-c", func(t *testing.T) { run(t, "\x03"+sentinel, 1, "ctrl-c") })
}

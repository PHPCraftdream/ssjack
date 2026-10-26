package apptransport

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"testing"
	"time"
)

func sendInput(ctx context.Context, s *streams, id string, data []byte) error {
	for len(data) > 0 {
		n := min(len(data), ChunkSize)
		out, err := s.write(InputInput{JobID: id, Data: base64.StdEncoding.EncodeToString(data[:n])})
		if err != nil {
			return err
		}
		if out.Accepted {
			data = data[n:]
		} else {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Millisecond):
			}
		}
	}
	for {
		out, err := s.write(InputInput{JobID: id, EOF: true})
		if err != nil {
			return err
		}
		if out.Accepted {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Millisecond):
		}
	}
}

func TestStreamsBinaryRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	payload := bytes.Repeat([]byte{0, 255, 128, '\n', 0xC3, 0xA9}, 180000)
	stderr := []byte{0xFF, 0, 42}
	s := newStreams(ctx, "selected", func(ctx context.Context, target, command string, stdin io.Reader, stdout, errorOut io.Writer) (int, error) {
		if target != "selected" || command != "copy" {
			return -1, errors.New("unexpected scope")
		}
		if _, err := io.Copy(stdout, stdin); err != nil {
			return -1, err
		}
		_, err := errorOut.Write(stderr)
		return 23, err
	})
	defer s.close()
	started, err := s.start(StartInput{Command: "copy"})
	if err != nil {
		t.Fatal(err)
	}
	sent := make(chan error, 1)
	go func() { sent <- sendInput(ctx, s, started.JobID, payload) }()
	var output, errorOutput bytes.Buffer
	for {
		out, err := s.read(ctx, JobInput{JobID: started.JobID})
		if err != nil {
			t.Fatal(err)
		}
		if out.Done {
			if out.ExitCode != 23 || out.Error != "" || out.TimedOut {
				t.Fatalf("unexpected result: %+v", out)
			}
			break
		}
		if out.Pending {
			continue
		}
		data, err := base64.StdEncoding.Strict().DecodeString(out.Data)
		if err != nil || len(data) > ChunkSize {
			t.Fatal("invalid binary frame")
		}
		switch out.Stream {
		case "stdout":
			output.Write(data)
		case "stderr":
			errorOutput.Write(data)
		default:
			t.Fatal("unknown output stream")
		}
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output.Bytes(), payload) || !bytes.Equal(errorOutput.Bytes(), stderr) {
		t.Fatal("transport corrupted binary data")
	}
}

func TestStreamsBackpressureCancellation(t *testing.T) {
	full := make(chan struct{})
	finished := make(chan struct{})
	s := newStreams(context.Background(), "selected", func(ctx context.Context, _, _ string, _ io.Reader, stdout, _ io.Writer) (int, error) {
		defer close(finished)
		chunk := make([]byte, ChunkSize)
		for range 16 {
			if _, err := stdout.Write(chunk); err != nil {
				return -1, err
			}
		}
		close(full)
		_, err := stdout.Write(chunk)
		return -1, err
	})
	defer s.close()
	started, err := s.start(StartInput{Command: "produce"})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-full:
	case <-time.After(5 * time.Second):
		t.Fatal("producer did not fill its bounded queue")
	}
	select {
	case <-finished:
		t.Fatal("producer bypassed output backpressure")
	default:
	}
	if _, err := s.stop(JobInput{JobID: started.JobID}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation did not release a blocked producer")
	}
}

func TestStreamsDeadlineAndValidation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s := newStreams(ctx, "selected", func(_ context.Context, _, _ string, stdin io.Reader, _, _ io.Writer) (int, error) {
		_, err := io.Copy(io.Discard, stdin)
		return -1, err
	})
	defer s.close()
	for _, input := range []StartInput{{}, {Command: "a\x00b"}, {Command: "x", TimeoutMS: -1}, {Command: "x", TimeoutMS: 3600001}} {
		if _, err := s.start(input); err == nil {
			t.Fatalf("accepted invalid start: %+v", input)
		}
	}
	started, err := s.start(StartInput{Command: "wait", TimeoutMS: 25})
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []InputInput{
		{JobID: started.JobID, Data: "not base64"},
		{JobID: started.JobID, Data: "YQ==", EOF: true},
		{JobID: "unknown", Data: "YQ=="},
	} {
		if _, err := s.write(input); err == nil {
			t.Fatal("accepted invalid input")
		}
	}
	for {
		out, err := s.read(ctx, JobInput{JobID: started.JobID})
		if err != nil {
			t.Fatal(err)
		}
		if out.Done {
			if !out.TimedOut || out.Error != context.DeadlineExceeded.Error() {
				t.Fatalf("missing deadline evidence: %+v", out)
			}
			break
		}
	}
}

func TestStreamsInputEOFAndConcurrency(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s := newStreams(ctx, "selected", func(ctx context.Context, _, _ string, _ io.Reader, _, _ io.Writer) (int, error) {
		<-ctx.Done()
		return -1, ctx.Err()
	})
	defer s.close()
	var id string
	for range maxActive {
		out, err := s.start(StartInput{Command: "wait"})
		if err != nil {
			t.Fatal(err)
		}
		id = out.JobID
	}
	if _, err := s.start(StartInput{Command: "excess"}); err == nil {
		t.Fatal("concurrency limit was bypassed")
	}
	if out, err := s.write(InputInput{JobID: id, EOF: true}); err != nil || !out.Accepted {
		t.Fatal("EOF was not accepted")
	}
	if out, err := s.write(InputInput{JobID: id, EOF: true}); err != nil || !out.Accepted {
		t.Fatal("repeated EOF was not idempotent")
	}
	if _, err := s.write(InputInput{JobID: id, Data: "YQ=="}); err == nil {
		t.Fatal("input was accepted after EOF")
	}
}

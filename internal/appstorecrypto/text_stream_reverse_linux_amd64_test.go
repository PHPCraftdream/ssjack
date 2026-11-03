//go:build linux && amd64

package appstorecrypto

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
)

type reverseStreamOutput struct{ bytes.Buffer }

func (*reverseStreamOutput) Close() error { return nil }

func TestReverseTextStreamLargeExactCopy(t *testing.T) {
	_, _, mappings := streamPipelineFixture(t, []byte("template"))
	placeholder, err := appstoreplaceholder.Encode(mappings[0].Reference)
	if err != nil {
		t.Fatal(err)
	}
	prefix := bytes.Repeat([]byte("synthetic large config\n"), 70000)
	input := append(append([]byte(nil), prefix...), mappings[0].Value...)
	want := append(append([]byte(nil), prefix...), placeholder...)
	output := &reverseStreamOutput{}
	calls := 0
	runner := TextAdapterRunner(func(_ context.Context, profile, command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		calls++
		if profile != "profile" || command != "fixed-read" || stderr != io.Discard {
			return 1, ErrDelivery
		}
		data, err := io.ReadAll(stdin)
		if err != nil || len(data) != 0 {
			return 1, ErrDelivery
		}
		_, err = io.Copy(stdout, bytes.NewReader(input))
		return 0, err
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result := runReverseTextStream(ctx, runner, "profile", "fixed-read", output, mappings, func() error { return nil })
	if result.Status != DeliveryReceived || calls != 1 || !bytes.Equal(output.Bytes(), want) || bytes.Contains(output.Bytes(), mappings[0].Value) {
		t.Fatal("large reverse stream did not return the exact reference-only copy")
	}
}

func TestReverseTextStreamLateErrorsAreUnknown(t *testing.T) {
	_, _, mappings := streamPipelineFixture(t, []byte("template"))
	placeholder, err := appstoreplaceholder.Encode(mappings[0].Reference)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		tail []byte
		exit int
	}{
		{"nul", []byte{0}, 0},
		{"invalid-utf8", []byte{0xff}, 0},
		{"truncated-utf8", []byte{0xe2, 0x82}, 0},
		{"reserved-marker", []byte("$ssjack invalid"), 0},
		{"raw-placeholder", placeholder, 0},
		{"nonzero-exit", nil, 7},
	} {
		t.Run(test.name, func(t *testing.T) {
			output := &reverseStreamOutput{}
			calls := 0
			runner := TextAdapterRunner(func(_ context.Context, _, _ string, _ io.Reader, stdout, _ io.Writer) (int, error) {
				calls++
				_, err := stdout.Write(bytes.Repeat([]byte("synthetic prefix\n"), 70000))
				if err == nil {
					_, err = stdout.Write(test.tail)
				}
				return test.exit, err
			})
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			result := runReverseTextStream(ctx, runner, "profile", "fixed-read", output, mappings, func() error { return nil })
			if result.Status != DeliveryUnknown || calls != 1 {
				t.Fatal("late reverse failure was not unknown")
			}
		})
	}
}

type blockedReverseOutput struct {
	started, closed chan struct{}
	startOnce       sync.Once
	closeOnce       sync.Once
}

func (w *blockedReverseOutput) Write([]byte) (int, error) {
	w.startOnce.Do(func() { close(w.started) })
	<-w.closed
	return 0, io.ErrClosedPipe
}

func (w *blockedReverseOutput) Close() error {
	w.closeOnce.Do(func() { close(w.closed) })
	return nil
}

func TestReverseTextStreamCancellationClosesOutputAndJoins(t *testing.T) {
	_, _, mappings := streamPipelineFixture(t, []byte("template"))
	output := &blockedReverseOutput{started: make(chan struct{}), closed: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	runner := TextAdapterRunner(func(ctx context.Context, _, _ string, _ io.Reader, stdout, _ io.Writer) (int, error) {
		written := make(chan error, 1)
		go func() {
			_, err := stdout.Write(bytes.Repeat([]byte("config\n"), 20000))
			written <- err
		}()
		select {
		case <-output.started:
			cancel()
		case <-ctx.Done():
		}
		<-written
		return 1, ctx.Err()
	})
	result := runReverseTextStream(ctx, runner, "profile", "fixed-read", output, mappings, func() error { return nil })
	if result.Status != DeliveryUnknown {
		t.Fatal("cancelled reverse stream was not unknown")
	}
	select {
	case <-output.closed:
	default:
		t.Fatal("reverse stream returned with blocked output")
	}
}

func TestReverseTextStreamAuthorityRefusalDoesNotDispatch(t *testing.T) {
	_, _, mappings := streamPipelineFixture(t, []byte("template"))
	calls := 0
	runner := TextAdapterRunner(func(context.Context, string, string, io.Reader, io.Writer, io.Writer) (int, error) {
		calls++
		return 0, nil
	})
	result := runReverseTextStream(context.Background(), runner, "profile", "fixed-read", &reverseStreamOutput{}, mappings, func() error { return ErrDelivery })
	if result.Status != DeliveryWithheld || calls != 0 {
		t.Fatal("reverse authority refusal dispatched the runner")
	}
}

//go:build linux && amd64

package appstorecrypto

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/appstoretext"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
)

func streamPipelineFixture(t *testing.T, input []byte) (*textBinding, *textStreamTicket, []appstoretext.Mapping) {
	t.Helper()
	ref, err := appstoreref.New([16]byte{1}, [16]byte{2}, [16]byte{3}, [16]byte{4})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := newTextBinding()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(binding.key[:]) })
	base := strings.Repeat("a", 64)
	mac, count, err := streamTemplateBinding(context.Background(), &binding, base, bytes.NewReader(input), []appstoreref.Ref{ref})
	if err != nil {
		t.Fatal(err)
	}
	return &binding, &textStreamTicket{base: base, mac: mac, bytes: count}, []appstoretext.Mapping{{Reference: ref, Value: []byte("synthetic-stream-secret")}}
}

func TestTextStreamPipelineHydratesLargeInputAndJoins(t *testing.T) {
	ref, err := appstoreref.New([16]byte{1}, [16]byte{2}, [16]byte{3}, [16]byte{4})
	if err != nil {
		t.Fatal(err)
	}
	placeholder, err := appstoreplaceholder.Encode(ref)
	if err != nil {
		t.Fatal(err)
	}
	input := append(bytes.Repeat([]byte("synthetic input\n"), 150000), placeholder...)
	binding, ticket, mappings := streamPipelineFixture(t, input)
	var output bytes.Buffer
	calls := 0
	runner := TextAdapterRunner(func(_ context.Context, profile, command string, source io.Reader, stdout, stderr io.Writer) (int, error) {
		calls++
		if profile != "profile" || command != "fixed-command" || stdout != io.Discard || stderr != io.Discard {
			return 1, ErrDelivery
		}
		_, err := io.Copy(&output, source)
		return 0, err
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result := runTextStream(ctx, runner, "profile", "fixed-command", io.NopCloser(bytes.NewReader(input)), mappings, binding, ticket, func() error { return nil })
	want := append(append([]byte(nil), input[:len(input)-len(placeholder)]...), []byte("synthetic-stream-secret")...)
	if result.Status != DeliveryReceived || calls != 1 || !bytes.Equal(output.Bytes(), want) {
		t.Fatal("stream did not deliver the exact hydrated large document")
	}
}

func TestTextStreamPipelineChangedSourceAndUnconsumedInputAreUnknown(t *testing.T) {
	input := []byte("approved template")
	binding, ticket, mappings := streamPipelineFixture(t, input)
	for _, early := range []bool{false, true} {
		calls := 0
		runner := TextAdapterRunner(func(_ context.Context, _, _ string, source io.Reader, _, _ io.Writer) (int, error) {
			calls++
			if early {
				return 0, nil
			}
			_, err := io.Copy(io.Discard, source)
			return 0, err
		})
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		result := runTextStream(ctx, runner, "profile", "fixed-command", io.NopCloser(bytes.NewReader(append(input, '!'))), mappings, binding, ticket, func() error { return nil })
		cancel()
		if result.Status != DeliveryUnknown || calls != 1 {
			t.Fatal("post-dispatch source change or unconsumed input was not unknown")
		}
	}
}

type blockedStreamInput struct {
	started   chan struct{}
	closed    chan struct{}
	startOnce sync.Once
	closeOnce sync.Once
}

func (r *blockedStreamInput) Read([]byte) (int, error) {
	r.startOnce.Do(func() { close(r.started) })
	<-r.closed
	return 0, ErrDelivery
}

func (r *blockedStreamInput) Close() error { r.closeOnce.Do(func() { close(r.closed) }); return nil }

func TestTextStreamEarlyRunnerFailureClosesBlockedInputAndJoins(t *testing.T) {
	binding, ticket, mappings := streamPipelineFixture(t, []byte("template"))
	input := &blockedStreamInput{started: make(chan struct{}), closed: make(chan struct{})}
	runner := TextAdapterRunner(func(ctx context.Context, _, _ string, _ io.Reader, _, _ io.Writer) (int, error) {
		select {
		case <-input.started:
			return 7, nil
		case <-ctx.Done():
			return 1, ctx.Err()
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result := runTextStream(ctx, runner, "profile", "fixed-command", input, mappings, binding, ticket, func() error { return nil })
	if result.Status != DeliveryUnknown {
		t.Fatal("failed runner produced a received result")
	}
	select {
	case <-input.closed:
	default:
		t.Fatal("blocked stream input was not closed before return")
	}
}

func TestTextStreamPipelinePreRunRefusalDoesNotInvokeRunner(t *testing.T) {
	binding, ticket, mappings := streamPipelineFixture(t, []byte("template"))
	calls := 0
	runner := TextAdapterRunner(func(context.Context, string, string, io.Reader, io.Writer, io.Writer) (int, error) {
		calls++
		return 0, nil
	})
	result := runTextStream(context.Background(), runner, "profile", "fixed-command", io.NopCloser(strings.NewReader("template")), mappings, binding, ticket, func() error { return ErrDelivery })
	if result.Status != DeliveryWithheld || calls != 0 {
		t.Fatal("pre-run authority refusal invoked SSH")
	}
}

func TestStreamExecuteConsumesMatchedExpiredTicketBeforeReading(t *testing.T) {
	operation, id := "AAECAwQFBgcICQoLDA0ODw", "EBESExQVFhcYGRobHB0eHw"
	prepared := &textStreamTicket{id: id, operation: operation, file: "/approved/config", mac: [32]byte{1}, expires: time.Now().Add(-time.Second)}
	adapter := &TextStreamAdapter{adapter: &TextAdapter{grant: declarativeauthority.TextAdapterGrant{Mode: "hydrate-stream-v2", File: prepared.file}}, prepared: prepared}
	input := &streamStepReader{input: strings.NewReader("unread template")}
	result := adapter.Execute(context.Background(), id, operation, prepared.file, io.NopCloser(input))
	if result.Status != DeliveryWithheld || !adapter.adapter.used || adapter.prepared != nil || input.calls != 0 || prepared.mac != ([32]byte{}) {
		t.Fatal("expired ticket was read, reusable or retained private state")
	}
	if result := adapter.Execute(context.Background(), id, operation, prepared.file, io.NopCloser(input)); result.Status != DeliveryWithheld || input.calls != 0 {
		t.Fatal("consumed stream ticket was replayed")
	}
}

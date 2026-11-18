//go:build linux && amd64

package textadapter

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/delivery"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/appstoretext"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
)

func TestStreamGrantCannotInvokeV1Delivery(t *testing.T) {
	calls := 0
	runner := TextAdapterRunner(func(context.Context, string, string, io.Reader, io.Writer, io.Writer) (int, error) {
		calls++
		return 0, nil
	})
	for _, mode := range []string{"hydrate-stream-v2", "reverse-copy-stream-v2"} {
		base := &TextAdapter{grant: declarativeauthority.TextAdapterGrant{Mode: mode, File: "/approved/config"}, runner: runner}
		if result := base.Hydrate(context.Background(), "AAECAwQFBgcICQoLDA0ODw", "/approved/config", []byte("template")); result != (delivery.DeliveryOutcome{Status: delivery.DeliveryWithheld}) {
			t.Fatal("stream grant crossed into v1 forward delivery")
		}
		if base.used {
			t.Fatal("v1 forward consumed a v2 operation before rejecting its profile")
		}
		if result := base.ReverseCopy(context.Background(), "AAECAwQFBgcICQoLDA0ODw", "/approved/config"); result.Status != delivery.DeliveryWithheld || result.Text != nil {
			t.Fatal("stream grant crossed into v1 reverse delivery")
		}
		if base.used {
			t.Fatal("v1 reverse consumed a v2 operation before rejecting its profile")
		}
	}
	if calls != 0 {
		t.Fatal("profile mismatch invoked SSH")
	}
}

func TestStreamScopeDirectionsRemainSeparate(t *testing.T) {
	for _, mode := range []string{"hydrate-stream-v2", "reverse-copy-stream-v2"} {
		c := &TextStreamAdapter{adapter: &TextAdapter{grant: declarativeauthority.TextAdapterGrant{Mode: mode, Profile: "selected", File: "/approved/config", References: []string{"selected-ref"}}}}
		forward := c.MatchScope("selected", "/approved/config", []string{"selected-ref"})
		reverse := c.MatchReverseScope("selected", "/approved/config", []string{"selected-ref"})
		if (forward == nil) != (mode == "hydrate-stream-v2") || (reverse == nil) != (mode == "reverse-copy-stream-v2") {
			t.Fatal("stream scope crossed its granted direction")
		}
		if c.MatchReverseScope("selected", "/approved/config", []string{"selected-ref", "selected-ref"}) == nil || c.MatchReverseScope("selected", "/other/config", []string{"selected-ref"}) == nil {
			t.Fatal("reverse scope accepted another file or duplicate references")
		}
		if c.adapter.used {
			t.Fatal("metadata matching consumed execution authority")
		}
	}
}

func TestStreamConstructionRequiresAuthenticatedInstallationAndRunner(t *testing.T) {
	if adapter, err := NewTextStreamAdapter(context.Background(), nil, "grant", "profile", "digest", nil); err == nil || adapter != nil {
		t.Fatal("stream construction accepted missing authenticated state")
	}
	if adapter, err := NewReverseTextStreamAdapter(context.Background(), nil, "grant", "profile", "digest", nil); err == nil || adapter != nil {
		t.Fatal("reverse stream construction accepted missing authenticated state")
	}
	if validTextAdapterMode("unknown") {
		t.Fatal("unknown adapter authority mode accepted")
	}
	if _, err := loadTextAdapterGrant("unknown", "caller-approval", 1000, time.Now()); err == nil {
		t.Fatal("unknown profile acquired authority")
	}
	if err := (*TextStreamAdapter)(nil).Close(); err != nil {
		t.Fatal(err)
	}
}

func streamPipelineFixture(t *testing.T, input []byte) (*delivery.TextBinding, *textStreamTicket, []appstoretext.Mapping) {
	t.Helper()
	ref, err := appstoreref.New([16]byte{1}, [16]byte{2}, [16]byte{3}, [16]byte{4})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := delivery.NewTextBinding()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { binding.Clear() })
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
			return 1, delivery.ErrDelivery
		}
		_, err := io.Copy(&output, source)
		return 0, err
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result := runTextStream(ctx, runner, "profile", "fixed-command", io.NopCloser(bytes.NewReader(input)), mappings, binding, ticket, func() error { return nil })
	want := append(append([]byte(nil), input[:len(input)-len(placeholder)]...), []byte("synthetic-stream-secret")...)
	if result.Status != delivery.DeliveryReceived || calls != 1 || !bytes.Equal(output.Bytes(), want) {
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
		if result.Status != delivery.DeliveryUnknown || calls != 1 {
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
	return 0, delivery.ErrDelivery
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
	if result.Status != delivery.DeliveryUnknown {
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
	result := runTextStream(context.Background(), runner, "profile", "fixed-command", io.NopCloser(strings.NewReader("template")), mappings, binding, ticket, func() error { return delivery.ErrDelivery })
	if result.Status != delivery.DeliveryWithheld || calls != 0 {
		t.Fatal("pre-run authority refusal invoked SSH")
	}
}

func TestStreamExecuteConsumesMatchedExpiredTicketBeforeReading(t *testing.T) {
	operation, id := "AAECAwQFBgcICQoLDA0ODw", "EBESExQVFhcYGRobHB0eHw"
	prepared := &textStreamTicket{id: id, operation: operation, file: "/approved/config", mac: [32]byte{1}, expires: time.Now().Add(-time.Second)}
	adapter := &TextStreamAdapter{adapter: &TextAdapter{grant: declarativeauthority.TextAdapterGrant{Mode: "hydrate-stream-v2", File: prepared.file}}, prepared: prepared}
	input := &streamStepReader{input: strings.NewReader("unread template")}
	result := adapter.Execute(context.Background(), id, operation, prepared.file, io.NopCloser(input))
	if result.Status != delivery.DeliveryWithheld || !adapter.adapter.used || adapter.prepared != nil || input.calls != 0 || prepared.mac != ([32]byte{}) {
		t.Fatal("expired ticket was read, reusable or retained private state")
	}
	if result := adapter.Execute(context.Background(), id, operation, prepared.file, io.NopCloser(input)); result.Status != delivery.DeliveryWithheld || input.calls != 0 {
		t.Fatal("consumed stream ticket was replayed")
	}
}

type streamStepReader struct {
	input io.Reader
	calls int
}

func (r *streamStepReader) Read(p []byte) (int, error) {
	r.calls++
	if len(p) > 1 {
		p = p[:1]
	}
	return r.input.Read(p)
}

func TestPrivateStreamTemplateBindingOwnsContentAndOperation(t *testing.T) {
	ref, err := appstoreref.New([16]byte{1}, [16]byte{2}, [16]byte{3}, [16]byte{4})
	if err != nil {
		t.Fatal(err)
	}
	placeholder, err := appstoreplaceholder.Encode(ref)
	if err != nil {
		t.Fatal(err)
	}
	input := append([]byte("synthetic \xe2\x82\xac\n"), placeholder...)
	binding, err := delivery.NewTextBinding()
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Clear()
	base := strings.Repeat("a", 64)
	first, count, err := streamTemplateBinding(context.Background(), &binding, base, bytes.NewReader(input), []appstoreref.Ref{ref})
	if err != nil || count != uint64(len(input)) {
		t.Fatal("private preparation binding failed")
	}
	chunked, _, err := streamTemplateBinding(context.Background(), &binding, base, &streamStepReader{input: bytes.NewReader(input)}, []appstoreref.Ref{ref})
	if err != nil || first != chunked {
		t.Fatal("read boundaries changed a private operation MAC")
	}
	changed, _, err := streamTemplateBinding(context.Background(), &binding, base, bytes.NewReader(append(input, '!')), []appstoreref.Ref{ref})
	if err != nil || changed == first {
		t.Fatal("changed second-pass content retained its private binding")
	}
	changed, _, err = streamTemplateBinding(context.Background(), &binding, strings.Repeat("b", 64), bytes.NewReader(input), []appstoreref.Ref{ref})
	if err != nil || changed == first {
		t.Fatal("another operation retained the template binding")
	}
}

func TestStreamPreparationRefusesBeforeReadingWithoutAuthority(t *testing.T) {
	input := &streamStepReader{input: strings.NewReader("unread template")}
	adapter := &TextStreamAdapter{adapter: &TextAdapter{grant: declarativeauthority.TextAdapterGrant{Mode: "hydrate-stream-v2", File: "/approved/config"}}}
	result, err := adapter.Prepare(context.Background(), "AAECAwQFBgcICQoLDA0ODw", "/approved/config", input)
	if err == nil || result.Ticket != "" || input.calls != 0 || adapter.prepared != nil || adapter.adapter.used {
		t.Fatal("unauthenticated preparation read input or created usable state")
	}
	ticket := &textStreamTicket{mac: [32]byte{1}}
	adapter.prepared = ticket
	if err := adapter.Close(); err != nil || adapter.prepared != nil || ticket.mac != ([32]byte{}) {
		t.Fatal("stream close retained private ticket state")
	}
}

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
			return 1, delivery.ErrDelivery
		}
		data, err := io.ReadAll(stdin)
		if err != nil || len(data) != 0 {
			return 1, delivery.ErrDelivery
		}
		_, err = io.Copy(stdout, bytes.NewReader(input))
		return 0, err
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result := runReverseTextStream(ctx, runner, "profile", "fixed-read", output, mappings, func() error { return nil })
	if result.Status != delivery.DeliveryReceived || calls != 1 || !bytes.Equal(output.Bytes(), want) || bytes.Contains(output.Bytes(), mappings[0].Value) {
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
			if result.Status != delivery.DeliveryUnknown || calls != 1 {
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
	if result.Status != delivery.DeliveryUnknown {
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
	result := runReverseTextStream(context.Background(), runner, "profile", "fixed-read", &reverseStreamOutput{}, mappings, func() error { return delivery.ErrDelivery })
	if result.Status != delivery.DeliveryWithheld || calls != 0 {
		t.Fatal("reverse authority refusal dispatched the runner")
	}
}

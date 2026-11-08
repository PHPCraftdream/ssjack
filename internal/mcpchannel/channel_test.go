package mcpchannel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

type testHandler struct {
	ordinal int
	entered chan struct{}
	release <-chan struct{}
}

func (h *testHandler) Describe(context.Context) ([]byte, error) {
	return []byte(fmt.Sprintf(`{"ordinal":%d}`, h.ordinal)), nil
}
func (h *testHandler) Call(_ context.Context, tool string, input []byte) ([]byte, error) {
	if h.entered != nil {
		select {
		case h.entered <- struct{}{}:
		default:
		}
	}
	if h.release != nil {
		<-h.release
	}
	return []byte(fmt.Sprintf(`{"ordinal":%d,"tool":%q,"input":%s}`, h.ordinal, tool, input)), nil
}

type handlerFunc struct {
	describe func(context.Context) ([]byte, error)
}

func (h handlerFunc) Describe(ctx context.Context) ([]byte, error) { return h.describe(ctx) }
func (handlerFunc) Call(context.Context, string, []byte) ([]byte, error) {
	return nil, errors.New("unused")
}

type captureHandler struct {
	calls int
	input []byte
}

func (*captureHandler) Describe(context.Context) ([]byte, error) { return []byte(`{}`), nil }
func (h *captureHandler) Call(_ context.Context, _ string, input []byte) ([]byte, error) {
	h.calls++
	h.input = append([]byte(nil), input...)
	return []byte(`{}`), nil
}

func request(operation string) wire.Request {
	data, err := wire.Encode(struct{}{})
	if err != nil {
		return wire.Request{Operation: operation}
	}
	return wire.Request{Operation: operation, Data: data}
}

func TestSelectedBindingsArePrivateAndScoped(t *testing.T) {
	set, err := Open(context.Background(), 2, time.Minute, func(i int) Handler { return &testHandler{ordinal: i} })
	if err != nil {
		t.Fatal("Open failed")
	}
	defer set.Close(context.Background())
	descriptors := set.Descriptors()
	if len(descriptors) != 2 || descriptors[0].Token == descriptors[1].Token || descriptors[0].Session == descriptors[1].Session || descriptors[0].Pin == descriptors[1].Pin || descriptors[0].Endpoint == descriptors[1].Endpoint {
		t.Fatal("bindings not independent")
	}
	for _, d := range descriptors {
		client, err := Connect(context.Background(), d)
		if err != nil {
			t.Fatal("connect failed")
		}
		got, err := client.Describe(context.Background())
		client.Close()
		if err != nil || string(got) != fmt.Sprintf(`{"ordinal":%d}`, d.Ordinal) {
			t.Fatalf("wrong binding response: %s", got)
		}
	}
	if set.OutputGuard() == nil {
		t.Fatal("channel token guard missing")
	}
}

func TestFixedCallEnvelopeAndRestrictedOperations(t *testing.T) {
	set, err := Open(context.Background(), 1, time.Minute, func(i int) Handler { return &testHandler{ordinal: i} })
	if err != nil {
		t.Fatal("Open failed")
	}
	defer set.Close(context.Background())
	client, err := Connect(context.Background(), set.Descriptors()[0])
	if err != nil {
		t.Fatal("connect failed")
	}
	defer client.Close()
	if _, err := client.request(context.Background(), "call", callEnvelope{Tool: "x", Input: `{}`}); err != nil {
		t.Fatal("valid fixed call failed")
	}
	if _, err := client.request(context.Background(), "call", map[string]any{"tool": "x", "input": "{}", "ordinal": 0}); err == nil {
		t.Fatal("caller-selected ordinal accepted")
	}
	if _, err := client.request(context.Background(), "session.describe", struct{}{}); err == nil {
		t.Fatal("SSH broker operation accepted")
	}
}

func TestWrongCapabilityReplayAndSSHVersionAreRefused(t *testing.T) {
	set, err := Open(context.Background(), 1, time.Minute, func(int) Handler { return &testHandler{} })
	if err != nil {
		t.Fatal("Open failed")
	}
	defer set.Close(context.Background())
	d := set.Descriptors()[0]
	wrong := d
	wrong.Token = strings.Repeat("0", 64)
	if _, err := Connect(context.Background(), wrong); err == nil {
		t.Fatal("wrong token accepted")
	}
	wrong = d
	wrong.Version = 2
	if _, err := Connect(context.Background(), wrong); err == nil {
		t.Fatal("SSH bootstrap version accepted")
	}
	client, err := Connect(context.Background(), d)
	if err != nil {
		t.Fatal("correct capability refused")
	}
	client.Close()
	if _, err := Connect(context.Background(), d); err == nil {
		t.Fatal("one-use capability replayed")
	}
}

func TestOutputGuardMasksKnownToken(t *testing.T) {
	set, err := Open(context.Background(), 1, time.Minute, func(int) Handler { return &testHandler{} })
	if err != nil {
		t.Fatal("Open failed")
	}
	defer set.Close(context.Background())
	empty, err := outputguard.New(nil)
	if err != nil {
		t.Fatal("empty guard failed")
	}
	guard, err := set.GuardWith(empty)
	if err != nil {
		t.Fatal("guard union failed")
	}
	var output bytes.Buffer
	writer, err := outputguard.NewWriter(guard, &output)
	if err != nil {
		t.Fatal("writer creation failed")
	}
	if _, err = writer.Write([]byte(set.Descriptors()[0].Token)); err != nil || writer.Close() != nil || output.String() != outputguard.Marker {
		t.Fatal("token escaped guard")
	}
}

func TestClientInput48KiBBound(t *testing.T) {
	input := []byte(`{"x":"` + strings.Repeat("a", MaxClientInputBytes-8) + `"}`)
	if _, err := MarshalCall("x", input); err != nil {
		t.Fatal("valid 48 KiB argument refused")
	}
	if _, err := MarshalCall("x", []byte(strings.Repeat("x", MaxClientInputBytes+1))); err == nil {
		t.Fatal("oversized input accepted")
	}
}

func TestRawJSONPreservesLargeIntegersAndRejectsDuplicateKeys(t *testing.T) {
	const exact = `{"value":9007199254740993}`
	h := &captureHandler{}
	serve := channelHandler(h)
	data, err := wire.Encode(callEnvelope{Tool: "exact", Input: exact})
	if err != nil || !serve(context.Background(), wire.Request{Operation: "call", Data: data}).OK {
		t.Fatal("valid envelope refused")
	}
	if string(h.input) != exact {
		t.Fatalf("raw JSON changed: %s", h.input)
	}
	before := h.calls
	data, err = wire.Encode(callEnvelope{Tool: "duplicate", Input: `{"value":1,"value":2}`})
	if err != nil || serve(context.Background(), wire.Request{Operation: "call", Data: data}).OK || h.calls != before {
		t.Fatal("duplicate argument key reached handler")
	}
}

func TestInventoryAndEncodedFrameBudgets(t *testing.T) {
	inventory := []byte(`{"text":"` + strings.Repeat("a", MaxInventoryBytes-11) + `"}`)
	h := handlerFunc{describe: func(context.Context) ([]byte, error) { return inventory, nil }}
	if !channelHandler(h)(context.Background(), request("describe")).OK {
		t.Fatal("192 KiB raw inventory refused")
	}
	tooLarge := []byte(`{"text":"` + strings.Repeat(`\"`, (MaxInventoryBytes-11)/2) + `"}`)
	h.describe = func(context.Context) ([]byte, error) { return tooLarge, nil }
	if channelHandler(h)(context.Background(), request("describe")).OK {
		t.Fatal("Ktav-oversized inventory reply accepted")
	}
}

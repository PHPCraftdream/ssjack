package mcpchannel

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/wire"
)

func sampleDescriptor(ordinal int) Descriptor {
	return Descriptor{Version: VersionRemoteMCP, Ordinal: ordinal, Session: strings.Repeat("1", 64), Endpoint: "127.0.0.1:23456", Pin: strings.Repeat("a", 64), Token: strings.Repeat("b", 64), ExpiresUnix: time.Now().Add(time.Minute).Unix()}
}

func TestDescriptorEnvironmentCodecIsStrict(t *testing.T) {
	a, b := sampleDescriptor(0), sampleDescriptor(1)
	b.Session, b.Endpoint, b.Pin, b.Token = strings.Repeat("2", 64), "127.0.0.1:23457", strings.Repeat("c", 64), strings.Repeat("d", 64)
	encoded, err := EncodeDescriptors([]Descriptor{a, b})
	if err != nil || len(encoded) > 16<<10 {
		t.Fatal("valid descriptors refused")
	}
	decoded, err := DecodeDescriptors(encoded)
	if err != nil || len(decoded) != 2 {
		t.Fatal("valid descriptors did not round-trip")
	}
	for _, malformed := range []string{
		`[]`,
		strings.Replace(encoded, `"version":1`, `"version":2`, 1),
		strings.Replace(encoded, `"ordinal":0`, `"ordinal":0,"ordinal":1`, 1),
		strings.Replace(encoded, `"ordinal":0`, `"foreign":0,"ordinal":0`, 1),
		strings.Replace(encoded, `127.0.0.1:23456`, `localhost:23456`, 1),
		strings.Replace(encoded, strings.Repeat("b", 64), strings.Repeat("z", 64), 1),
	} {
		if _, err := DecodeDescriptors(malformed); err == nil {
			t.Fatalf("accepted malformed descriptor %q", malformed)
		}
	}
}

func TestDescriptorDuplicatesAndExpirationRejected(t *testing.T) {
	a := sampleDescriptor(0)
	b := sampleDescriptor(0)
	b.Session, b.Endpoint, b.Pin, b.Token = strings.Repeat("2", 64), "127.0.0.1:23457", strings.Repeat("c", 64), strings.Repeat("d", 64)
	if _, err := EncodeDescriptors([]Descriptor{a, b}); err == nil {
		t.Fatal("duplicate ordinal accepted")
	}
	b.Ordinal = 1
	b.Token = a.Token
	if _, err := EncodeDescriptors([]Descriptor{a, b}); err == nil {
		t.Fatal("duplicate token accepted")
	}
	a.ExpiresUnix = time.Now().Add(-time.Second).Unix()
	encoded, _ := json.Marshal([]Descriptor{a})
	if _, err := DecodeDescriptors(string(encoded)); err == nil {
		t.Fatal("expired bootstrap accepted")
	}
	if _, err := Connect(nil, a); err == nil {
		t.Fatal("invalid ctx unexpectedly accepted")
	}
}

func TestDescriptorCrossFieldCollisionsAreRejected(t *testing.T) {
	a := sampleDescriptor(0)
	b := sampleDescriptor(1)
	b.Session, b.Endpoint, b.Pin, b.Token = a.Token, "127.0.0.1:23457", strings.Repeat("c", 64), strings.Repeat("d", 64)
	if _, err := EncodeDescriptors([]Descriptor{a, b}); err == nil {
		t.Fatal("session/token collision accepted")
	}
	b.Session, b.Pin, b.Token = strings.Repeat("2", 64), a.Pin, strings.Repeat("d", 64)
	if _, err := EncodeDescriptors([]Descriptor{a, b}); err == nil {
		t.Fatal("session/pin collision accepted")
	}
	b.Session, b.Pin, b.Token = strings.Repeat("2", 64), strings.Repeat("c", 64), a.Pin
	if _, err := EncodeDescriptors([]Descriptor{a, b}); err == nil {
		t.Fatal("pin/token collision accepted")
	}
}

func TestLifecycleCloseRunsOnIdleDisconnectAndFailureIsSticky(t *testing.T) {
	for _, fail := range []bool{false, true} {
		handler := &lifecycleTestHandler{closed: make(chan struct{})}
		if fail {
			handler.err = errors.New("cleanup failed")
		}
		set, err := Open(context.Background(), 1, time.Minute, func(int) Handler { return handler })
		if err != nil {
			t.Fatal(err)
		}
		client, err := Connect(context.Background(), set.Descriptors()[0])
		if err != nil {
			t.Fatal(err)
		}
		client.Close()
		select {
		case <-set.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("idle disconnect did not join channel")
		}
		select {
		case <-handler.closed:
		default:
			t.Fatal("handler lifecycle callback was not invoked")
		}
		closeErr := set.Close(context.Background())
		if fail {
			if closeErr != ErrCleanup || len(set.Descriptors()) != 1 {
				t.Fatal("failed lifecycle cleanup was not sticky or references were dropped")
			}
		} else if closeErr != nil || len(set.Descriptors()) != 0 {
			t.Fatal("successful lifecycle cleanup did not release references")
		}
	}
}

type lifecycleTestHandler struct {
	closed chan struct{}
	err    error
}

func (*lifecycleTestHandler) Describe(context.Context) ([]byte, error) { return []byte(`{}`), nil }
func (*lifecycleTestHandler) Call(context.Context, string, []byte) ([]byte, error) {
	return []byte(`{}`), nil
}
func (h *lifecycleTestHandler) Close(context.Context) error {
	close(h.closed)
	return h.err
}

func TestDescriptorEnvironmentStripsInheritedNameCaseInsensitively(t *testing.T) {
	base := []string{"PATH=/bin", "ssjack_remote_mcp_channels=old", "SSJACK_REMOTE_MCP_CHANNELS=stale", "other=x"}
	got := Environment(base, "fresh")
	if len(got) != 3 || got[0] != "PATH=/bin" || got[1] != "other=x" || got[2] != Env+"=fresh" {
		t.Fatalf("unexpected child env: %#v", got)
	}
	if len(base) != 4 || base[1] != "ssjack_remote_mcp_channels=old" {
		t.Fatal("parent environment was modified")
	}
	if got := Environment(base, ""); len(got) != 2 {
		t.Fatalf("empty encoded value not scrubbed: %#v", got)
	}
}

func TestEnvelopeRejectsExtraFieldsAndInputOverLimit(t *testing.T) {
	encoded, err := wire.Encode(callEnvelope{Tool: "x", Input: `{}`})
	if err != nil || strictDecode(encoded, new(callEnvelope), "tool", "input") != nil {
		t.Fatal("valid Ktav envelope refused")
	}
	for _, invalid := range []string{`{"tool":"x","input":"{}","ordinal":0}`, `{"tool":"x","tool":"y","input":"{}"}`, `{"tool":"x","input":"{}"} trailing`} {
		var call callEnvelope
		if strictDecode(invalid, &call, "tool", "input") == nil {
			t.Fatal("invalid Ktav envelope accepted")
		}
	}
	if _, err := MarshalCall("x", []byte(`{"value":"ok"}`)); err != nil {
		t.Fatal("valid call rejected")
	}
	if _, err := MarshalCall("x", []byte(strings.Repeat("x", MaxClientInputBytes+1))); err == nil {
		t.Fatal("oversized input accepted")
	}
}

func cleanupChannelSet(t *testing.T, set *ChannelSet) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := set.Close(ctx); err != nil {
		t.Errorf("channel set did not join before cleanup deadline")
	}
}

func TestCloseTimeoutRetainsOwnerUntilServerJoins(t *testing.T) {
	release, entered := make(chan struct{}), make(chan struct{}, 1)
	set, err := Open(context.Background(), 1, time.Minute, func(int) Handler { return &testHandler{entered: entered, release: release} })
	if err != nil {
		t.Fatal("Open failed")
	}
	t.Cleanup(func() { cleanupChannelSet(t, set) })
	client, err := Connect(context.Background(), set.Descriptors()[0])
	if err != nil {
		t.Fatal("connect failed")
	}
	callDone := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() {
		select {
		case <-callDone:
		case <-time.After(2 * time.Second):
			t.Errorf("blocked call goroutine did not join after gate release")
		}
	})
	t.Cleanup(client.Close)
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	go func() { defer close(callDone); _, _ = client.Call(context.Background(), "block", []byte(`{}`)) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not start")
	}
	short, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if set.Close(short) != ErrCleanup {
		t.Fatal("incomplete close not reported")
	}
	if len(set.Descriptors()) != 1 {
		t.Fatal("owner dropped references before join")
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case <-set.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("server join stalled")
	}
	if set.Close(context.Background()) != nil {
		t.Fatal("owner could not retry join")
	}
	client.Close()
	select {
	case <-callDone:
	case <-time.After(2 * time.Second):
		t.Fatal("call goroutine did not join after owner retry close")
	}
}

func TestClientCancellationAndCloseInterruptBlockedCall(t *testing.T) {
	for _, closeClient := range []bool{false, true} {
		release, entered := make(chan struct{}), make(chan struct{}, 1)
		set, err := Open(context.Background(), 1, time.Minute, func(int) Handler { return &testHandler{entered: entered, release: release} })
		if err != nil {
			t.Fatal("Open failed")
		}
		t.Cleanup(func() { cleanupChannelSet(t, set) })
		client, err := Connect(context.Background(), set.Descriptors()[0])
		if err != nil {
			t.Fatal("connect failed")
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		var releaseOnce sync.Once
		t.Cleanup(func() {
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Errorf("blocked call goroutine did not join after gate release")
			}
		})
		t.Cleanup(client.Close)
		t.Cleanup(cancel)
		t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
		go func() { defer close(done); _, _ = client.Call(ctx, "block", []byte(`{}`)) }()
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("handler did not start")
		}
		if closeClient {
			closed := make(chan struct{})
			go func() { client.Close(); close(closed) }()
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("Close blocked behind call")
			}
		} else {
			cancel()
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("interruption did not unblock call")
		}
		if _, err := client.Call(context.Background(), "retry", []byte(`{}`)); err == nil {
			t.Fatal("interrupted connection retried")
		}
		releaseOnce.Do(func() { close(release) })
		select {
		case <-set.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("server goroutine did not join")
		}
		if set.Close(context.Background()) != nil {
			t.Fatal("cleanup failed")
		}
		client.Close()
		cancel()
	}
}

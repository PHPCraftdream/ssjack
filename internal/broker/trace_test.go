package broker

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/wire"
)

type traceRecorder struct {
	mu     sync.Mutex
	events []string
}

func (r *traceRecorder) record(event string, pairs ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event+" "+strings.Join(pairs, " "))
}

func (r *traceRecorder) find(prefix string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, event := range r.events {
		if strings.HasPrefix(event, prefix) {
			return event
		}
	}
	return ""
}

func TestTraceExplainsWhyTheChannelEnded(t *testing.T) {
	auth := wire.Auth{Version: 2, Session: strings.Repeat("7", 64), Token: strings.Repeat("8", 64)}
	recorder := &traceRecorder{}
	keeper, err := ListenTraced(context.Background(), auth.Session, auth.Token, time.Minute, func(_ context.Context, req wire.Request) wire.Reply {
		return wire.Reply{OK: req.Operation == "good", Data: req.Data}
	}, recorder.record)
	if err != nil {
		t.Fatal(err)
	}
	defer keeper.Close()
	wrong := auth
	wrong.Token = strings.Repeat("9", 64)
	if _, err := Connect(context.Background(), keeper.Endpoint(), keeper.Pin(), wrong); !errors.Is(err, ErrRejected) {
		t.Fatalf("wrong token = %v", err)
	}
	client, err := Connect(context.Background(), keeper.Endpoint(), keeper.Pin(), auth)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.CallRaw(context.Background(), "good", map[string]string{"secret": "request-data"}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CallRaw(context.Background(), "bad", nil); err == nil {
		t.Fatal("refused operation succeeded")
	}
	var failures traceRecorder
	client.SetTrace(failures.record)
	client.Close()
	select {
	case <-keeper.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("keeper outlived its attached connection")
	}
	keeper.Close()
	if _, err := client.CallRaw(context.Background(), "good", nil); err == nil {
		t.Fatal("call on a closed client succeeded")
	}
	if got := failures.find("call-failed "); !strings.HasPrefix(got, "call-failed op good stage write cause ") {
		t.Fatalf("client failure trace = %q", got)
	}
	if _, err := Connect(context.Background(), keeper.Endpoint(), keeper.Pin(), auth); !errors.Is(err, ErrDial) {
		t.Fatalf("re-attach after shutdown = %v", err)
	}
	for _, want := range []string{
		"listen ttl_ms 60000",
		"connection-end attached false stage claim cause credentials requests 0 ",
		"attached ",
		"request op good ok true ",
		"request op bad ok false ",
		"connection-end attached true stage request-read cause eof requests 2 ",
		"shutdown reason attached-connection-ended",
	} {
		if recorder.find(want) == "" {
			t.Fatalf("trace lacks %q in %q", want, recorder.events)
		}
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	shutdowns := 0
	for _, event := range recorder.events {
		if strings.HasPrefix(event, "shutdown ") {
			shutdowns++
		}
		if strings.Contains(event, "request-data") || strings.Contains(event, auth.Token) || strings.Contains(event, auth.Session) {
			t.Fatalf("trace carried request data or a credential: %q", event)
		}
	}
	if shutdowns != 1 {
		t.Fatalf("shutdown was traced %d times", shutdowns)
	}
}

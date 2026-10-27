package broker

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/wire"
)

func fixture(t *testing.T) (*Server, wire.Auth) {
	t.Helper()
	auth := wire.Auth{Version: 2, Session: strings.Repeat("1", 64), Token: strings.Repeat("2", 64)}
	s, err := Listen(context.Background(), auth.Session, auth.Token, time.Minute, func(_ context.Context, req wire.Request) wire.Reply {
		return wire.Reply{OK: true, Data: req.Data}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, auth
}

func TestFullCompatibilityAndInvalidDescriptor(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	auth := wire.Auth{Version: 2, Session: strings.Repeat("c", 64), Token: strings.Repeat("d", 64)}
	called := false
	handler := Dispatch(ModeFull, func(context.Context, wire.Request) wire.Reply {
		called = true
		return Result(map[string]string{"ok": "yes"}, nil)
	})
	keeper, err := Listen(ctx, auth.Session, auth.Token, time.Minute, handler)
	if err != nil {
		t.Fatal(err)
	}
	defer keeper.Close()
	client, err := Connect(ctx, keeper.Endpoint(), keeper.Pin(), auth)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	d, err := Describe(ctx, client)
	if err != nil || d.Mode != ModeFull || !d.Complete || len(d.Tools) != 8 {
		t.Fatalf("full descriptor: %+v %v", d, err)
	}
	var response map[string]string
	if err := client.Call(ctx, "legacy-op", struct{}{}, &response); err != nil || response["ok"] != "yes" || !called {
		t.Fatal("full compatibility path failed")
	}
	called = false
	if err := client.Call(ctx, "session.describe", map[string]any{"discovery": DiscoveryRequest, "mode": "declarative"}, &response); err == nil {
		t.Fatal("accepted mode switch attempt")
	}
	d, err = Describe(ctx, client)
	if err != nil || d.Mode != ModeFull || !d.Complete || len(d.Tools) != 8 {
		t.Fatalf("mode changed after rejected attempt: %+v %v", d, err)
	}
	if called {
		t.Fatal("mode-switch attempt invoked full callback")
	}
}

func TestRequiresTokenSessionAndProtocolVersion(t *testing.T) {
	s, auth := fixture(t)
	for _, field := range []string{"token", "version", "session"} {
		bad := auth
		switch field {
		case "token":
			bad.Token = strings.Repeat("0", 64)
		case "version":
			bad.Version = 1
		case "session":
			bad.Session = strings.Repeat("0", 64)
		}
		if c, err := Connect(context.Background(), s.Endpoint(), s.Pin(), bad); err == nil {
			c.Close()
			t.Fatalf("accepted incorrect %s", field)
		}
	}
	c, err := Connect(context.Background(), s.Endpoint(), s.Pin(), auth)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var got map[string]string
	if err := c.Call(context.Background(), "echo", map[string]string{"value": "data"}, &got); err != nil || got["value"] != "data" {
		t.Fatalf("unexpected response: %v, %v", got, err)
	}
}

func TestRejectWrongCertificateWithoutConsuming(t *testing.T) {
	s, auth := fixture(t)
	if c, err := Connect(context.Background(), s.Endpoint(), strings.Repeat("0", 64), auth); err == nil {
		c.Close()
		t.Fatal("accepted an untrusted certificate")
	}
	c, err := Connect(context.Background(), s.Endpoint(), s.Pin(), auth)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestExactlyOneConcurrentAttachAndNoReplay(t *testing.T) {
	s, auth := fixture(t)
	start := make(chan struct{})
	results := make(chan *Client, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			c, _ := Connect(context.Background(), s.Endpoint(), s.Pin(), auth)
			results <- c
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	var winner *Client
	for c := range results {
		if c != nil {
			if winner != nil {
				c.Close()
				t.Fatal("two clients obtained access")
			}
			winner = c
		}
	}
	if winner == nil {
		t.Fatal("no client obtained access")
	}
	winner.Close()
	select {
	case <-s.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("disconnect did not close the session")
	}
	if c, err := Connect(context.Background(), s.Endpoint(), s.Pin(), auth); err == nil {
		c.Close()
		t.Fatal("replay was allowed")
	}
}

func TestAttachedSessionOutlivesBootstrapDeadline(t *testing.T) {
	auth := wire.Auth{Version: 2, Session: strings.Repeat("1", 64), Token: strings.Repeat("2", 64)}
	s, err := Listen(context.Background(), auth.Session, auth.Token, 2*time.Second, func(_ context.Context, req wire.Request) wire.Reply {
		return wire.Reply{OK: true, Data: req.Data}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	client, err := Connect(context.Background(), s.Endpoint(), s.Pin(), auth)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	timer := time.NewTimer(time.Until(s.expires) + 50*time.Millisecond)
	defer timer.Stop()
	select {
	case <-s.Done():
		t.Fatal("bootstrap timer closed an attached session")
	case <-timer.C:
	}
	if err := client.Call(context.Background(), "echo", struct{}{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestMemoryBootstrap(t *testing.T) {
	s, auth := fixture(t)
	bootstrap := Bootstrap{Session: auth.Session, Endpoint: s.Endpoint(), Pin: s.Pin(), Token: auth.Token}
	bad := bootstrap
	bad.Token = strings.Repeat("0", 64)
	if client, err := ConnectBootstrap(context.Background(), bad); err == nil {
		client.Close()
		t.Fatal("wrong token accepted")
	}
	client, err := ConnectBootstrap(context.Background(), bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.Call(context.Background(), "echo", struct{}{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestExpiryAndRejectedMemoryBootstrap(t *testing.T) {
	s, err := Listen(context.Background(), strings.Repeat("1", 64), strings.Repeat("2", 64), time.Millisecond, func(context.Context, wire.Request) wire.Reply { return wire.Reply{OK: true} })
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	select {
	case <-s.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("bootstrap did not expire")
	}
	for _, token := range []string{"", "secret", strings.Repeat("z", 64)} {
		if _, err := ConnectBootstrap(context.Background(), Bootstrap{Session: strings.Repeat("1", 64), Token: token}); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("invalid token accepted or exposed")
		}
	}
}

func TestCancellationAndHandlerError(t *testing.T) {
	s, auth := fixture(t)
	client, err := Connect(context.Background(), s.Endpoint(), s.Pin(), auth)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.Call(ctx, "echo", nil, nil); err == nil {
		t.Fatal("cancelled request was executed")
	}
	reply := Result(nil, context.Canceled)
	if reply.OK || reply.Error == "" {
		t.Fatal("handler error was lost")
	}
	var raw map[string]int
	if err := client.Call(context.Background(), "echo", map[string]int{"n": 1}, &raw); err != nil {
		t.Fatal(err)
	}
}

package broker

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"storagehost/internal/wire"
)

func fixture(t *testing.T) (*Server, wire.Auth) {
	t.Helper()
	auth := wire.Auth{Session: strings.Repeat("1", 64), EnvToken: strings.Repeat("2", 64), DiskToken: strings.Repeat("3", 64)}
	s, err := Listen(context.Background(), auth.Session, auth.EnvToken, auth.DiskToken, time.Minute, func(_ context.Context, req wire.Request) wire.Reply {
		return wire.Reply{OK: true, Data: req.Data}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, auth
}

func TestRequiresBothTokensAndSession(t *testing.T) {
	s, auth := fixture(t)
	for _, field := range []string{"env", "disk", "session"} {
		bad := auth
		switch field {
		case "env":
			bad.EnvToken = strings.Repeat("0", 64)
		case "disk":
			bad.DiskToken = strings.Repeat("0", 64)
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
	auth := wire.Auth{Session: strings.Repeat("1", 64), EnvToken: strings.Repeat("2", 64), DiskToken: strings.Repeat("3", 64)}
	s, err := Listen(context.Background(), auth.Session, auth.EnvToken, auth.DiskToken, 2*time.Second, func(_ context.Context, req wire.Request) wire.Reply {
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

func TestBootstrapFileConsumption(t *testing.T) {
	s, auth := fixture(t)
	path, cleanup, err := WriteBootstrap(t.TempDir(), Bootstrap{Version: 1, Session: auth.Session, Endpoint: s.Endpoint(), Pin: s.Pin(), DiskToken: auth.DiskToken})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	data, err := os.ReadFile(path)
	if err != nil || strings.Contains(string(data), auth.EnvToken) {
		t.Fatal("environment token must not be written to disk")
	}
	if _, err := ConnectFile(context.Background(), path, strings.Repeat("0", 64)); err == nil {
		t.Fatal("incorrect environment token was accepted")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("file was removed before confirmed attachment")
	}
	client, err := ConnectFile(context.Background(), path, auth.EnvToken)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("consumed file was not removed")
	}
}

func TestExpiryAndRejectedFiles(t *testing.T) {
	s, err := Listen(context.Background(), strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64), time.Millisecond, func(context.Context, wire.Request) wire.Reply { return wire.Reply{OK: true} })
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	select {
	case <-s.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("bootstrap did not expire")
	}
	path := filepath.Join(t.TempDir(), "bad.ktav")
	if err := os.WriteFile(path, []byte(`version: 1
disk_token: secret
`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ConnectFile(context.Background(), path, strings.Repeat("1", 64)); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("error must reject the file without exposing secrets")
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

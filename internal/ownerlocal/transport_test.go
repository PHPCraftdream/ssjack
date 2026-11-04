package ownerlocal

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func endpointFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault.ktav")
	if err := os.WriteFile(path, []byte("synthetic encrypted database marker"), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

type contextReader struct {
	context.Context
	connection Connection
}

func (r contextReader) Read(p []byte) (int, error) { return r.connection.Read(r.Context, p) }
func writeAll(ctx context.Context, connection Connection, data []byte) error {
	for len(data) != 0 {
		n, err := connection.Write(ctx, data)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(data) {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func pair(t *testing.T, path string) (Listener, Connection, Connection) {
	t.Helper()
	listener, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type result struct {
		connection Connection
		err        error
	}
	accepted := make(chan result, 1)
	go func() { connection, err := listener.Accept(ctx); accepted <- result{connection, err} }()
	client, err := Dial(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	var server Connection
	select {
	case got := <-accepted:
		if got.err != nil {
			t.Fatal(got.err)
		}
		server = got.connection
	case <-ctx.Done():
		t.Fatal("native owner accept did not finish")
	}
	t.Cleanup(func() { server.Close() })
	return listener, client, server
}

func TestNativeOwnerTransportTransfersBothDirectionsAndRemainsExclusive(t *testing.T) {
	path := endpointFixture(t)
	listener, client, server := pair(t, path)
	if second, err := Listen(path); !errors.Is(err, ErrBusy) {
		if second != nil {
			second.Close()
		}
		t.Fatal("a second owner acquired the live endpoint")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	payload := bytes.Repeat([]byte("synthetic ciphertext frame;"), 4096)
	finished := make(chan error, 1)
	go func() {
		got := make([]byte, len(payload))
		_, err := io.ReadFull(contextReader{ctx, server}, got)
		if err == nil && !bytes.Equal(got, payload) {
			err = errors.New("native frame changed")
		}
		if err == nil {
			err = writeAll(ctx, server, []byte("accepted"))
		}
		finished <- err
	}()
	if err := writeAll(ctx, client, payload); err != nil {
		t.Fatal(err)
	}
	var reply [8]byte
	if _, err := io.ReadFull(contextReader{ctx, client}, reply[:]); err != nil || string(reply[:]) != "accepted" {
		t.Fatal("native owner reply failed")
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	client.Close()
	server.Close()
	if second, err := Listen(path); !errors.Is(err, ErrBusy) {
		if second != nil {
			second.Close()
		}
		t.Fatal("owner endpoint ownership was lost between peer sessions")
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	replacement, err := Listen(path)
	if err != nil {
		t.Fatal("closed owner did not release its endpoint")
	}
	replacement.Close()
}

func TestNativeOwnerCancellationJoinsAcceptAndRead(t *testing.T) {
	path := endpointFixture(t)
	listener, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		connection, err := listener.Accept(ctx)
		if connection != nil {
			connection.Close()
		}
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled native accept succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled native accept did not join")
	}
	if second, err := Listen(path); !errors.Is(err, ErrBusy) {
		if second != nil {
			second.Close()
		}
		t.Fatal("cancelled accept released the coordinator ownership claim")
	}
	listener.Close()
	_, client, _ := pair(t, path)
	ctx, cancel = context.WithCancel(context.Background())
	go func() { var b [1]byte; _, err := client.Read(ctx, b[:]); done <- err }()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled native read succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled native read did not join")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestEndpointIdentityHasNoPlaintextPathAndRejectsNonFiles(t *testing.T) {
	path := endpointFixture(t)
	first, err := Identity(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Identity(filepath.Join(filepath.Dir(path), ".", filepath.Base(path)))
	if err != nil || first != second || bytes.Contains([]byte(first.Address), []byte(path)) {
		t.Fatal("endpoint identity exposed a path or changed for the same database")
	}
	if _, err := Identity(filepath.Dir(path)); !errors.Is(err, ErrEndpoint) {
		t.Fatal("directory was accepted as a database")
	}
}

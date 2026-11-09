package mcpfixturetest

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

func TestPublishedWriteFailuresWinOverClose(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(*connection, error)
	}{
		{name: "write", setup: func(conn *connection, sentinel error) { conn.writeErr = sentinel }},
		{name: "encode", setup: func(conn *connection, sentinel error) {
			conn.encode = func(jsonrpc.Message) ([]byte, error) { return nil, sentinel }
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			leftTransport, _ := NewPair()
			conn := leftTransport.(*transport).conn
			sentinel := errors.New("admitted " + test.name + " failure")
			entered, release := make(chan struct{}), make(chan struct{})
			closeEntered, releaseClose := make(chan struct{}), make(chan struct{})
			var releaseOnce, releaseCloseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			unblockClose := func() { releaseCloseOnce.Do(func() { close(releaseClose) }) }
			conn.writeHook = func() { close(entered); <-release }
			conn.closeHook = func() { close(closeEntered); <-releaseClose }
			test.setup(conn, sentinel)
			ctx, cancelWrite := context.WithTimeout(context.Background(), helperLimit)
			defer cancelWrite()
			writeResult, joinWrite := startWrite(t, conn, ctx, &jsonrpc.Request{Method: "fixture/test"})
			closeResult, joinClose := (<-chan error)(nil), func() {}
			defer func() {
				cleanupWorkers(t, conn, func() { unblockClose(); unblock() }, []context.CancelFunc{cancelWrite}, joinWrite, joinClose)
			}()

			if _, ok := await(t, "write barrier", entered); !ok {
				return
			}
			closeResult, joinClose = startClose(t, conn)
			if _, ok := await(t, "close commitment", closeEntered); !ok {
				return
			}
			if result, ok := nonblockingError(writeResult); ok {
				t.Fatalf("Write returned before its injected failure was released: %v", result)
			}
			unblock()
			if err, ok := await(t, "admitted write failure", writeResult); !ok || err != sentinel {
				t.Fatalf("Write error = %v, want identical error %v", err, sentinel)
			}
			unblockClose()
			if err, ok := await(t, "Close", closeResult); !ok || err != nil {
				t.Fatalf("Close = %v", err)
			}
			if err := conn.Write(context.Background(), &jsonrpc.Request{Method: "after-close"}); err != io.EOF {
				t.Fatalf("Write after own Close = %v, want EOF", err)
			}
		})
	}
}

func TestWriteAdmissionDistinguishesOwnedAndPeerClose(t *testing.T) {
	for _, test := range []struct {
		name       string
		closeOrder []string
		want       error
	}{
		{name: "owned close", closeOrder: []string{"writer"}, want: io.EOF},
		{name: "peer close", closeOrder: []string{"peer"}, want: io.ErrClosedPipe},
		{name: "peer then writer close", closeOrder: []string{"peer", "writer"}, want: io.ErrClosedPipe},
		{name: "writer then peer close", closeOrder: []string{"writer", "peer"}, want: io.EOF},
	} {
		t.Run(test.name, func(t *testing.T) {
			leftTransport, rightTransport := NewPair()
			conn := leftTransport.(*transport).conn
			peer := rightTransport.(*transport).conn
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			conn.publishHook = func() { close(entered); <-release }
			ctx, cancel := context.WithTimeout(context.Background(), helperLimit)
			defer cancel()
			writeResult, joinWrite := startWrite(t, conn, ctx, &jsonrpc.Request{Method: "fixture/test"})
			var closeJoins []func()
			defer func() {
				joins := append([]func(){joinWrite}, closeJoins...)
				cleanupWorkers(t, conn, unblock, []context.CancelFunc{cancel}, joins...)
			}()

			if _, ok := await(t, "encoded write before publication", entered); !ok {
				return
			}
			for _, owner := range test.closeOrder {
				closeConn := conn
				if owner == "peer" {
					closeConn = peer
				}
				closeResult, joinClose := startClose(t, closeConn)
				closeJoins = append(closeJoins, joinClose)
				if err, ok := await(t, owner+" Close", closeResult); !ok || err != nil {
					t.Errorf("%s Close = %v", owner, err)
					return
				}
			}
			if conn.closed.Load() != (test.name != "peer close") {
				t.Fatalf("writer closed state = %v after %s", conn.closed.Load(), test.name)
			}
			unblock()
			if err, ok := await(t, "write admission result", writeResult); !ok || err != test.want {
				t.Fatalf("Write error = %v, want identical error %v", err, test.want)
			}
			joinWrite()
			conn.publishHook = nil
			if err := conn.Write(context.Background(), &jsonrpc.Request{Method: "after-close"}); err != test.want {
				t.Fatalf("Write after close = %v, want identical error %v", err, test.want)
			}
		})
	}
}

func nonblockingError(ch <-chan error) (error, bool) {
	select {
	case err := <-ch:
		return err, true
	default:
		return nil, false
	}
}

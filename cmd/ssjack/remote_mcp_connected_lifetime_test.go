package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRemoteMCPConnectedWaitLifetime(t *testing.T) {
	for _, source := range []string{"request", "tool", "shutdown"} {
		t.Run(source, func(t *testing.T) {
			fixture := &remoteMCPConnectedServer{waitStarted: make(chan struct{}), waitFinish: make(chan struct{})}
			fixture.initLifetime()
			toolCtx, cancelTool := context.WithCancel(context.Background())
			requestCtx, cancelRequest := context.WithCancel(context.Background())
			done := make(chan struct{})
			t.Cleanup(func() {
				cancelTool()
				cancelRequest()
				fixture.closeAdmission()
				cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				for _, signal := range []<-chan struct{}{done, fixture.activeDone} {
					select {
					case <-signal:
					case <-cleanup.Done():
						t.Error("connected fixture wait cleanup did not join")
					}
				}
			})
			if !fixture.beginWork() {
				t.Fatal("fresh fixture refused wait worker")
			}
			go func() {
				defer close(done)
				defer fixture.endWork()
				_, _ = fixture.wait(toolCtx, requestCtx)
			}()
			operation, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			select {
			case <-fixture.waitStarted:
			case <-operation.Done():
				t.Fatal("wait worker did not start")
			}
			select {
			case <-fixture.waitFinish:
				t.Fatal("live wait finished before cancellation")
			default:
			}
			switch source {
			case "request":
				cancelRequest()
			case "tool":
				cancelTool()
			case "shutdown":
				fixture.closeAdmission()
			}
			select {
			case <-done:
			case <-operation.Done():
				t.Fatal("wait worker did not finish after cancellation")
			}
			select {
			case <-fixture.waitFinish:
			default:
				t.Fatal("wait completion omitted its handler barrier")
			}
			wantDone := int32(1)
			if source == "shutdown" {
				wantDone = 0
			}
			if fixture.calls.Load() != 1 || fixture.waitCalls.Load() != 1 || fixture.waitDone.Load() != wantDone {
				t.Fatal("wait replayed or fixture shutdown became cancellation evidence")
			}
			if source != "tool" && toolCtx.Err() != nil || source != "request" && requestCtx.Err() != nil {
				t.Fatal("cancellation crossed an independent context owner")
			}
		})
	}
}

func TestRemoteMCPConnectedRequestHandlerLifetime(t *testing.T) {
	fixture := &remoteMCPConnectedServer{waitStarted: make(chan struct{}), waitFinish: make(chan struct{})}
	fixture.initLifetime()
	requestOwner, cancelRequestOwner := context.WithCancel(context.Background())
	transportCtx, cancelTransport := context.WithCancel(context.Background())
	done := make(chan struct{})
	t.Cleanup(func() {
		fixture.closeAdmission()
		cancelRequestOwner()
		cancelTransport()
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		for _, signal := range []<-chan struct{}{done, fixture.activeDone} {
			select {
			case <-signal:
			case <-cleanup.Done():
				t.Error("connected request handler cleanup did not join")
			}
		}
	})
	if !fixture.beginWork() {
		t.Fatal("fresh fixture refused HTTP handler worker")
	}

	// Keep the transport live so only the captured request owner can release
	// the tool; SDK transport-context cancellation must not satisfy this oracle.
	request := httptest.NewRequest(http.MethodPost, "https://coordinator.invalid/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"wait","arguments":{}}}`)).WithContext(transportCtx)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("Mcp-Protocol-Version", "2025-06-18")
	response := httptest.NewRecorder()
	handler := fixture.handlerForRequest(requestOwner)
	go func() {
		defer close(done)
		defer fixture.endWork()
		handler.ServeHTTP(response, request)
	}()

	operation, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	select {
	case <-fixture.waitStarted:
	case <-operation.Done():
		t.Fatal("SDK HTTP handler did not start wait tool")
	}
	if requestOwner.Err() != nil || transportCtx.Err() != nil {
		t.Fatal("request contexts ended before request-owner cancellation")
	}
	select {
	case <-fixture.waitFinish:
		t.Fatal("SDK HTTP wait finished before request-owner cancellation")
	default:
	}
	cancelRequestOwner()
	select {
	case <-done:
	case <-operation.Done():
		t.Fatal("SDK HTTP handler did not finish after captured request-owner cancellation")
	}
	select {
	case <-fixture.waitFinish:
	default:
		t.Fatal("wait completion omitted its handler barrier")
	}
	if fixture.calls.Load() != 1 || fixture.waitCalls.Load() != 1 || fixture.waitDone.Load() != 1 {
		t.Fatal("SDK HTTP handler replayed wait or omitted cancellation evidence")
	}
	if transportCtx.Err() != nil {
		t.Fatal("captured request-owner cancellation crossed into the live HTTP transport")
	}
}

func TestRemoteMCPConnectedWorkAdmission(t *testing.T) {
	fixture := &remoteMCPConnectedServer{}
	fixture.initLifetime()
	if !fixture.beginWork() {
		t.Fatal("fresh fixture refused work")
	}
	fixture.closeAdmission()
	fixture.closeAdmission()
	select {
	case <-fixture.activeDone:
		t.Fatal("fixture joined before admitted worker finished")
	default:
	}
	if fixture.beginWork() {
		t.Fatal("closing fixture admitted new work")
	}
	fixture.endWork()
	select {
	case <-fixture.activeDone:
	default:
		t.Fatal("fixture did not join its last worker")
	}
}

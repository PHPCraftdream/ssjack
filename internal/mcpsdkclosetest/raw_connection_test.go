package mcpsdkclosetest

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	trialCount     = 100
	operationLimit = 3 * time.Second
)

type readOutcome struct {
	err      error
	received bool
}

type rawCloseCounts struct {
	eof        int
	closedPipe int
}

func boundedResult[T any](t *testing.T, label string, result <-chan T) (T, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), operationLimit)
	defer cancel()
	select {
	case value := <-result:
		return value, true
	case <-ctx.Done():
		t.Errorf("%s did not complete within the bound", label)
		var zero T
		return zero, false
	}
}

func errorCategory(err error) string {
	switch {
	case err == nil:
		return "nil"
	case errors.Is(err, io.EOF):
		return "eof"
	case errors.Is(err, io.ErrClosedPipe):
		return "closed-pipe"
	default:
		return "unknown"
	}
}

func reportError(t *testing.T, label string, err error) {
	t.Helper()
	t.Errorf("%s: category=%s type=%T", label, errorCategory(err), err)
}

func startConnClose(conn mcp.Connection) <-chan error {
	result := make(chan error, 1)
	go func() { result <- conn.Close() }()
	return result
}

func checkClose(t *testing.T, label string, result *<-chan error) bool {
	t.Helper()
	err, ok := boundedResult(t, label, *result)
	if !ok {
		return false
	}
	*result = nil
	if err != nil {
		reportError(t, label, err)
		return false
	}
	return true
}

// rawCloseTrial compares one local close with a fresh peer-close control. The
// entry signal is emitted by this test goroutine immediately before Read; it
// is not an SDK-internal barrier and does not force an internal scheduling gap.
func rawCloseTrial(t *testing.T, closeReader bool) readOutcome {
	t.Helper()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithTimeout(context.Background(), operationLimit)
	defer cancel()
	readCtx, cancelRead := context.WithCancel(context.Background())

	var readerConn, peerConn mcp.Connection
	var readerResult <-chan readOutcome
	var readerJoined bool
	var readerClose, peerClose <-chan error
	var readerCloseStarted, peerCloseStarted bool
	defer func() {
		cancelRead()
		if readerConn != nil && !readerCloseStarted {
			readerClose = startConnClose(readerConn)
			readerCloseStarted = true
		}
		if peerConn != nil && !peerCloseStarted {
			peerClose = startConnClose(peerConn)
			peerCloseStarted = true
		}
		if readerClose != nil {
			checkClose(t, "cleanup reader connection close", &readerClose)
		}
		if peerClose != nil {
			checkClose(t, "cleanup peer connection close", &peerClose)
		}
		if readerResult != nil && !readerJoined {
			_, readerJoined = boundedResult(t, "cleanup reader join", readerResult)
		}
	}()

	var err error
	readerConn, err = serverTransport.Connect(ctx)
	if err != nil {
		reportError(t, "reader connection setup", err)
		return readOutcome{}
	}
	peerConn, err = clientTransport.Connect(ctx)
	if err != nil {
		reportError(t, "peer connection setup", err)
		return readOutcome{}
	}

	entered := make(chan struct{}, 1)
	readResult := make(chan readOutcome, 1)
	readerResult = readResult
	go func() {
		entered <- struct{}{}
		_, readErr := readerConn.Read(readCtx)
		readResult <- readOutcome{err: readErr, received: true}
	}()
	if _, ok := boundedResult(t, "reader entry", entered); !ok {
		return readOutcome{}
	}

	if closeReader {
		readerClose = startConnClose(readerConn)
		readerCloseStarted = true
		if !checkClose(t, "local reader connection close", &readerClose) {
			return readOutcome{}
		}
	} else {
		peerClose = startConnClose(peerConn)
		peerCloseStarted = true
		if !checkClose(t, "peer connection close", &peerClose) {
			return readOutcome{}
		}
	}

	outcome, ok := boundedResult(t, "connection Read join", readerResult)
	if !ok {
		return readOutcome{}
	}
	readerJoined = true

	if closeReader {
		peerClose = startConnClose(peerConn)
		peerCloseStarted = true
		checkClose(t, "peer connection close", &peerClose)
	} else {
		readerClose = startConnClose(readerConn)
		readerCloseStarted = true
		checkClose(t, "reader connection close", &readerClose)
	}
	return outcome
}

func TestRawConnectionCloseErrors(t *testing.T) {
	var local, peer rawCloseCounts
	var localReads, peerReads int
	for i := 0; i < trialCount; i++ {
		for _, trial := range []struct {
			name        string
			closeReader bool
			counts      *rawCloseCounts
		}{
			{name: "local", closeReader: true, counts: &local},
			{name: "peer", counts: &peer},
		} {
			outcome := rawCloseTrial(t, trial.closeReader)
			if t.Failed() {
				return
			}
			if !outcome.received {
				return
			}
			if trial.name == "local" {
				localReads++
			} else {
				peerReads++
			}
			category := errorCategory(outcome.err)
			switch category {
			case "eof":
				trial.counts.eof++
			case "closed-pipe":
				trial.counts.closedPipe++
			default:
				reportError(t, trial.name+" Read", outcome.err)
				return
			}
			if trial.name == "peer" && category != "eof" {
				reportError(t, "peer-close Read must be EOF", outcome.err)
				return
			}
		}
	}
	t.Logf("local close trials=%d reads=%d eof=%d closed-pipe=%d", trialCount, localReads, local.eof, local.closedPipe)
	t.Logf("peer close trials=%d reads=%d eof=%d closed-pipe=%d", trialCount, peerReads, peer.eof, peer.closedPipe)
}

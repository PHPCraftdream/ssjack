package apptransport

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstoretextstream"
	"github.com/PHPCraftdream/ssjack/internal/remote"
)

const TextStreamReversePath = "/text-stream-v2/reverse-copy"

type TextStreamReverseCopier interface {
	MatchReverseScope(string, string, []string) error
	ReverseCopyStream(context.Context, string, string, io.WriteCloser) appstorecrypto.DeliveryOutcome
}

func ListenWithReverseTextStreamAdapter(parent context.Context, profile string, runner remote.StreamRunner, adapter TextStreamReverseCopier) (*Server, error) {
	if adapter == nil {
		return nil, errors.New("invalid reverse streaming text adapter")
	}
	return listen(parent, profile, runner, nil, nil, nil, adapter)
}

type reverseStreamCompletion struct {
	input   io.Reader
	done    <-chan struct{}
	outcome *appstorecrypto.DeliveryOutcome
}

func (r reverseStreamCompletion) Read(output []byte) (int, error) {
	n, err := r.input.Read(output)
	if err == io.EOF {
		<-r.done
		if r.outcome.Status != appstorecrypto.DeliveryReceived {
			return n, appstoretextstream.ErrFrame
		}
	}
	return n, err
}

type reverseStreamResponse struct {
	writer  http.ResponseWriter
	started bool
}

func (w *reverseStreamResponse) Write(data []byte) (int, error) {
	w.started = true
	return w.writer.Write(data)
}

func (s *Server) serveReverseTextStream(writer http.ResponseWriter, request *http.Request, profile string) {
	if s.reverseStream == nil || len(request.Header.Values("Content-Type")) != 1 || request.Header.Get("Content-Type") != "application/x-ndjson" {
		http.Error(writer, "invalid private stream request", http.StatusBadRequest)
		return
	}
	deadline := time.Now().Add(time.Minute)
	controller := http.NewResponseController(writer)
	if controller.SetReadDeadline(deadline) != nil || controller.SetWriteDeadline(deadline) != nil {
		http.Error(writer, "private stream deadlines unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithDeadline(request.Context(), deadline)
	defer cancel()
	request.Body = http.MaxBytesReader(writer, request.Body, textStreamHeaderLimit+1)
	defer request.Body.Close()
	reader := bufio.NewReaderSize(request.Body, textStreamHeaderLimit+1)
	header, err := readTextStreamHeader(reader, false)
	if err != nil || header.Profile != profile || s.reverseStream.MatchReverseScope(header.Profile, header.File, header.References) != nil {
		http.Error(writer, "private stream scope refused", http.StatusForbidden)
		return
	}
	if _, err := reader.ReadByte(); err != io.EOF {
		http.Error(writer, "private stream body refused", http.StatusBadRequest)
		return
	}
	input, feed := io.Pipe()
	defer input.Close()
	defer feed.Close()
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		input.CloseWithError(appstoretextstream.ErrFrame)
		feed.CloseWithError(appstoretextstream.ErrFrame)
		close(closed)
	})
	defer func() {
		if !stop() {
			<-closed
		}
	}()
	outcome := appstorecrypto.DeliveryOutcome{Status: appstorecrypto.DeliveryUnknown}
	done := make(chan struct{})
	go func() {
		outcome = s.reverseStream.ReverseCopyStream(ctx, header.OperationID, header.File, feed)
		feed.Close()
		close(done)
	}()
	writer.Header().Set("Content-Type", "application/x-ndjson")
	writer.Header().Set("Cache-Control", "no-store")
	response := &reverseStreamResponse{writer: writer}
	err = appstoretextstream.Encode(ctx, reverseStreamCompletion{input: input, done: done, outcome: &outcome}, response, header.OperationID, appstoretextstream.MaxBytes)
	if err != nil {
		cancel()
		input.CloseWithError(appstoretextstream.ErrFrame)
		feed.CloseWithError(appstoretextstream.ErrFrame)
	}
	<-done
	if err != nil && !response.started {
		status := "unknown"
		if outcome.Status == appstorecrypto.DeliveryWithheld {
			status = "withheld"
		}
		writeTextStreamReply(writer, TextStreamReply{Format: TextStreamFormat, OperationID: header.OperationID, Status: status})
	}
}

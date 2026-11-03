package apptransport

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstoretextstream"
	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
	"github.com/PHPCraftdream/ssjack/internal/remote"
)

const TextStreamFormat = "ssjack-text-stream-v2"
const textStreamHeaderLimit = 16 * 1024

const (
	TextStreamPreparePath = "/text-stream-v2/prepare"
	TextStreamExecutePath = "/text-stream-v2/execute"
)

type TextStreamHydrator interface {
	MatchScope(string, string, []string) error
	Prepare(context.Context, string, string, io.Reader) (appstorecrypto.TextStreamPreparation, error)
	Execute(context.Context, string, string, string, io.ReadCloser) appstorecrypto.DeliveryOutcome
}

type TextStreamHeader struct {
	Format      string   `json:"format"`
	OperationID string   `json:"operation_id"`
	Profile     string   `json:"profile"`
	File        string   `json:"file"`
	References  []string `json:"references"`
	Ticket      string   `json:"ticket,omitempty"`
}

type TextStreamReply struct {
	Format      string `json:"format"`
	OperationID string `json:"operation_id"`
	Status      string `json:"status"`
	Ticket      string `json:"ticket,omitempty"`
	Bytes       uint64 `json:"bytes,omitempty"`
}

func ListenWithTextStreamAdapter(parent context.Context, profile string, runner remote.StreamRunner, adapter TextStreamHydrator) (*Server, error) {
	if adapter == nil {
		return nil, errors.New("invalid streaming text adapter")
	}
	return listen(parent, profile, runner, nil, nil, adapter)
}

func textStreamPath(path string) bool {
	return path == TextStreamPreparePath || path == TextStreamExecutePath
}

func textStreamID(id string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(id)
	return err == nil && len(decoded) == 16 && base64.RawURLEncoding.EncodeToString(decoded) == id
}

func readTextStreamHeader(reader *bufio.Reader, execute bool) (TextStreamHeader, error) {
	var header TextStreamHeader
	line, err := reader.ReadSlice('\n')
	if err != nil || len(line) > textStreamHeaderLimit+1 {
		return header, appstoretextstream.ErrFrame
	}
	defer clear(line)
	canonical, err := canonicaljson.Canonicalize(line[:len(line)-1])
	if err != nil {
		return header, appstoretextstream.ErrFrame
	}
	defer clear(canonical)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &fields); err != nil {
		return header, appstoretextstream.ErrFrame
	}
	keys := []string{"format", "operation_id", "profile", "file", "references"}
	if execute {
		keys = append(keys, "ticket")
	}
	if len(fields) != len(keys) {
		return header, appstoretextstream.ErrFrame
	}
	for _, key := range keys {
		if _, exists := fields[key]; !exists || bytes.Equal(fields[key], []byte("null")) {
			return header, appstoretextstream.ErrFrame
		}
	}
	if err := json.Unmarshal(canonical, &header); err != nil || header.Format != TextStreamFormat || !textStreamID(header.OperationID) || header.Profile == "" || len(header.Profile) > 64 || header.File == "" || len(header.File) > 4096 || len(header.References) == 0 || len(header.References) > 16 || (execute && !textStreamID(header.Ticket)) {
		return TextStreamHeader{}, appstoretextstream.ErrFrame
	}
	for _, ref := range header.References {
		if len(ref) == 0 || len(ref) > 1024 {
			return TextStreamHeader{}, appstoretextstream.ErrFrame
		}
	}
	return header, nil
}

func writeTextStreamReply(writer http.ResponseWriter, reply TextStreamReply) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(writer).Encode(reply)
}

func (s *Server) serveTextStream(writer http.ResponseWriter, request *http.Request, profile string) {
	if s.textStream == nil || len(request.Header.Values("Content-Type")) != 1 || request.Header.Get("Content-Type") != "application/x-ndjson" {
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
	request.Body = http.MaxBytesReader(writer, request.Body, appstoretextstream.MaxWireBytes+textStreamHeaderLimit+1)
	defer request.Body.Close()
	reader := bufio.NewReaderSize(request.Body, textStreamHeaderLimit+1)
	execute := request.URL.Path == TextStreamExecutePath
	header, err := readTextStreamHeader(reader, execute)
	if err != nil || header.Profile != profile || s.textStream.MatchScope(header.Profile, header.File, header.References) != nil {
		http.Error(writer, "private stream scope refused", http.StatusForbidden)
		return
	}
	input, feed := io.Pipe()
	defer input.Close()
	defer feed.Close()
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		request.Body.Close()
		input.CloseWithError(appstoretextstream.ErrFrame)
		feed.CloseWithError(appstoretextstream.ErrFrame)
		close(closed)
	})
	defer func() {
		if !stop() {
			<-closed
		}
	}()
	decoded := make(chan error, 1)
	go func() {
		err := appstoretextstream.Decode(ctx, reader, feed, header.OperationID, appstoretextstream.MaxBytes)
		if err != nil {
			_ = feed.CloseWithError(appstoretextstream.ErrFrame)
		} else {
			_ = feed.Close()
		}
		decoded <- err
	}()
	reply := TextStreamReply{Format: TextStreamFormat, OperationID: header.OperationID, Status: "withheld"}
	if execute {
		outcome := s.textStream.Execute(ctx, header.Ticket, header.OperationID, header.File, input)
		reply.Status = "unknown"
		if outcome.Status == appstorecrypto.DeliveryWithheld {
			reply.Status = "withheld"
		}
		if outcome.Status == appstorecrypto.DeliveryReceived && ctx.Err() == nil {
			reply.Status = "received"
		}
	} else {
		prepared, err := s.textStream.Prepare(ctx, header.OperationID, header.File, input)
		if err == nil && ctx.Err() == nil && textStreamID(prepared.Ticket) && prepared.Bytes <= appstoretextstream.MaxBytes {
			reply.Status, reply.Ticket, reply.Bytes = "prepared", prepared.Ticket, prepared.Bytes
		}
	}
	input.CloseWithError(appstoretextstream.ErrFrame)
	request.Body.Close()
	decodeErr := <-decoded
	if decodeErr != nil || ctx.Err() != nil {
		if execute && reply.Status != "withheld" {
			reply.Status = "unknown"
		} else {
			reply.Status = "withheld"
		}
		reply.Ticket, reply.Bytes = "", 0
	}
	writeTextStreamReply(writer, reply)
}

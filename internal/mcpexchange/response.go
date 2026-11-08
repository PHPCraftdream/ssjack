package mcpexchange

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"strings"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"

	"github.com/PHPCraftdream/ssjack/internal/mcpflow"
	"github.com/PHPCraftdream/ssjack/internal/mcpjson"
)

// errTransportInterrupted marks a body/stream read that failed without
// producing complete protocol evidence (cancelled or broken transport). It
// never escapes Write: the exchange converts it to io.EOF under owned
// termination or to errExchange on a live connection.
var errTransportInterrupted = errors.New("exchange transport interrupted")

func parseMediaType(value string) (string, error) {
	mediaType, params, err := mime.ParseMediaType(value)
	if err != nil || mediaType == "" {
		return "", errExchange
	}
	for key, param := range params {
		if !strings.EqualFold(key, "charset") || !strings.EqualFold(param, "utf-8") {
			return "", errExchange
		}
	}
	return strings.ToLower(mediaType), nil
}

func decodeJSONResponse(source io.Reader, expected []byte) (*jsonrpc.Response, error) {
	body, err := io.ReadAll(io.LimitReader(source, maxResponse+1))
	if len(body) > maxResponse {
		clear(body)
		return nil, errExchange // definite oversize evidence, regardless of read errors
	}
	if err != nil {
		complete := json.Valid(body) // decided before any clearing: never validate zeroed evidence
		clear(body)
		if mcpflow.DefiniteResponse(err) || complete {
			return nil, errExchange // marked size evidence or complete syntactic evidence survives an unclean end; never success
		}
		return nil, errTransportInterrupted // truncated stream: interrupted read
	}
	if len(body) == 0 {
		clear(body)
		return nil, errExchange
	}
	defer clear(body)
	return decodeResponse(body, expected)
}

func decodeResponse(body, expected []byte) (*jsonrpc.Response, error) {
	var wire struct {
		ID json.RawMessage `json:"id"`
	}
	if !utf8.Valid(body) || json.Unmarshal(body, &wire) != nil || len(wire.ID) == 0 || !sameID(wire.ID, expected) {
		return nil, errExchange
	}
	if _, err := mcpjson.Decode(body, maxResponse, 32, 8192); err != nil {
		return nil, errExchange
	}
	message, err := jsonrpc.DecodeMessage(body)
	response, ok := message.(*jsonrpc.Response)
	if err != nil || !ok || response == nil || !response.ID.IsValid() {
		return nil, errExchange
	}
	var strict struct {
		JSONRPC string          `json:"jsonrpc"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
		Method  json.RawMessage `json:"method"`
		Params  json.RawMessage `json:"params"`
	}
	if json.Unmarshal(body, &strict) != nil || strict.JSONRPC != "2.0" || len(strict.Method) != 0 || len(strict.Params) != 0 || len(strict.Error) != 0 && len(strict.Result) != 0 || len(strict.Error) == 0 && len(strict.Result) == 0 {
		return nil, errExchange
	}
	return response, nil
}

func sameID(actual, expected []byte) bool {
	var actualString, expectedString string
	if json.Unmarshal(actual, &actualString) == nil {
		return json.Unmarshal(expected, &expectedString) == nil && actualString == expectedString
	}
	// Numeric identifiers are emitted canonically by the pinned SDK. Comparing
	// their tokens avoids float conversion and preserves large integer IDs.
	return bytes.Equal(actual, expected)
}

// decodeSSEResponse classification: after any read error Scanner re-splits its
// buffered bytes with atEOF=true, so a buffered unterminated line is delivered
// even when owned cancellation closed the body mid-read (flow's closed
// conversion returns unmarked ErrExchange); field/limit validation of that
// delivered line is definite errExchange. A parked stream with nothing
// buffered stays clean interruption, pinned by the owned-cancel SSE body test
// in internal/mcpruntimetest/exchange_shutdown_body_test.go.
func decodeSSEResponse(source io.Reader, expected []byte) (*jsonrpc.Response, error) {
	scanner := bufio.NewScanner(io.LimitReader(source, maxResponse+1))
	scanner.Buffer(make([]byte, 4096), maxResponse)
	total := 0
	event := ""
	data := make([]byte, 0, 1024)
	defer func() { clear(data) }()
	for scanner.Scan() {
		line := scanner.Bytes()
		total += len(line) + 1
		if total > maxResponse {
			return nil, errExchange
		}
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if !utf8.Valid(line) {
			return nil, errExchange
		}
		if len(line) == 0 {
			if event == "" && len(data) == 0 {
				continue
			}
			if event != "message" || len(data) == 0 {
				return nil, errExchange
			}
			return decodeResponse(data, expected)
		}
		if line[0] == ':' {
			continue
		}
		field, value, found := bytes.Cut(line, []byte{':'})
		if !found {
			field, value = line, nil
		}
		if len(value) > 0 && value[0] == ' ' {
			value = value[1:]
		}
		switch string(field) {
		case "event":
			if event != "" || string(value) != "message" {
				return nil, errExchange
			}
			event = "message"
		case "data":
			if len(data) != 0 {
				data = append(data, '\n')
			}
			if len(value) > maxResponse-len(data) {
				return nil, errExchange
			}
			data = append(data, value...)
		default:
			return nil, errExchange
		}
	}
	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) || mcpflow.DefiniteResponse(err) {
			return nil, errExchange // definite token-limit or size evidence
		}
		return nil, errTransportInterrupted
	}
	return nil, errExchange // clean stream end without a message
}

func expectedID(encoded []byte) ([]byte, error) {
	var wire struct {
		ID json.RawMessage `json:"id"`
	}
	if json.Unmarshal(encoded, &wire) != nil || len(wire.ID) == 0 || bytes.Equal(wire.ID, []byte("null")) {
		return nil, errExchange
	}
	return append([]byte(nil), wire.ID...), nil
}

func consumeEmpty(body io.Reader) error {
	data, err := io.ReadAll(io.LimitReader(body, 1))
	if len(data) != 0 || mcpflow.DefiniteResponse(err) {
		clear(data)
		return errExchange // definite nonempty or limit evidence, even with a read error
	}
	if err != nil {
		return errTransportInterrupted
	}
	return nil
}

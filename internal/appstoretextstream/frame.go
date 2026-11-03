package appstoretextstream

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
)

const (
	ChunkSize    = 32 * 1024
	MaxBytes     = 64 * 1024 * 1024
	MaxFrames    = 4096
	MaxWireFrame = 48 * 1024
	MaxWireBytes = 96 * 1024 * 1024
)

var ErrFrame = errors.New("invalid or incomplete private text stream")

type frame struct {
	Type        string `json:"type"`
	OperationID string `json:"operation_id"`
	Sequence    uint32 `json:"sequence"`
	Data        string `json:"data,omitempty"`
	Bytes       uint64 `json:"bytes,omitempty"`
	Frames      uint32 `json:"frames,omitempty"`
}

func validOperation(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for _, c := range []byte(id) {
		if !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}

func decodeFrame(encoded []byte) (frame, error) {
	var result frame
	if len(encoded) == 0 || len(encoded) > MaxWireFrame {
		return result, ErrFrame
	}
	canonical, err := canonicaljson.Canonicalize(encoded)
	if err != nil {
		return result, ErrFrame
	}
	defer clear(canonical)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &fields); err != nil {
		return result, ErrFrame
	}
	if err := json.Unmarshal(canonical, &result); err != nil || !validOperation(result.OperationID) {
		return frame{}, ErrFrame
	}
	var required []string
	switch result.Type {
	case "data":
		required = []string{"type", "operation_id", "sequence", "data"}
	case "complete":
		required = []string{"type", "operation_id", "sequence", "bytes", "frames"}
	default:
		return frame{}, ErrFrame
	}
	if len(fields) != len(required) {
		return frame{}, ErrFrame
	}
	for _, key := range required {
		if _, ok := fields[key]; !ok || bytes.Equal(fields[key], []byte("null")) {
			return frame{}, ErrFrame
		}
	}
	return result, nil
}

func encodeFrame(value frame) ([]byte, error) {
	var data any
	switch value.Type {
	case "data":
		data = struct {
			Type        string `json:"type"`
			OperationID string `json:"operation_id"`
			Sequence    uint32 `json:"sequence"`
			Data        string `json:"data"`
		}{value.Type, value.OperationID, value.Sequence, value.Data}
	case "complete":
		data = struct {
			Type        string `json:"type"`
			OperationID string `json:"operation_id"`
			Sequence    uint32 `json:"sequence"`
			Bytes       uint64 `json:"bytes"`
			Frames      uint32 `json:"frames"`
		}{value.Type, value.OperationID, value.Sequence, value.Bytes, value.Frames}
	default:
		return nil, ErrFrame
	}
	encoded, err := json.Marshal(data)
	if err != nil || len(encoded) > MaxWireFrame {
		return nil, ErrFrame
	}
	return append(encoded, '\n'), nil
}

func decodeData(encoded string) ([]byte, error) {
	if len(encoded) == 0 || len(encoded) > base64.StdEncoding.EncodedLen(ChunkSize) {
		return nil, ErrFrame
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) == 0 || len(decoded) > ChunkSize || base64.StdEncoding.EncodeToString(decoded) != encoded {
		clear(decoded)
		return nil, ErrFrame
	}
	return decoded, nil
}

func writeAll(writer io.Writer, data []byte) error {
	written, err := writer.Write(data)
	if err != nil {
		return err
	}
	if written != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

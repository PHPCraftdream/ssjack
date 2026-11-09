package mcpjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

type customMarshaler struct{}

func (customMarshaler) MarshalJSON() ([]byte, error) { return []byte(`"unsafe"`), nil }

func TestDecodePrecisionDuplicatesAndBudgets(t *testing.T) {
	value, err := Decode([]byte(`{"n":9007199254740993}`), 128, 32, 4)
	if err != nil || value.(map[string]any)["n"] != json.Number("9007199254740993") {
		t.Fatalf("integer precision lost: %#v, %v", value, err)
	}
	if _, err := Decode([]byte(`{"n":1,"n":2}`), 128, 32, 10); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate object member accepted: %v", err)
	}
	if _, err := Decode([]byte(`[[[0]]]`), 64, 2, 32); !errors.Is(err, ErrLimit) {
		t.Fatalf("excessive depth accepted: %v", err)
	}
	if _, err := Decode([]byte(`[0,1,2]`), 64, 32, 3); !errors.Is(err, ErrLimit) {
		t.Fatalf("excessive node count accepted: %v", err)
	}
}

func TestDecodeRejectsOversizedInput(t *testing.T) {
	if _, err := Decode([]byte(`{"long":"value"}`), 8, 32, 32); !errors.Is(err, ErrLimit) {
		t.Fatalf("oversized input accepted: %v", err)
	}
}

func TestNormalizeTypedRawMessageAndRejectsBinaryAndMarshalers(t *testing.T) {
	value := struct {
		Payload json.RawMessage `json:"payload"`
	}{Payload: json.RawMessage(`{"n":9007199254740993}`)}
	normalized, err := Normalize(value, 128)
	if err != nil || normalized.(map[string]any)["payload"].(map[string]any)["n"] != json.Number("9007199254740993") {
		t.Fatalf("typed RawMessage normalization failed: %#v, %v", normalized, err)
	}
	if _, err := Normalize([]byte("secret"), 128); !errors.Is(err, ErrInvalid) {
		t.Fatalf("byte slice interpreted as binary JSON: %v", err)
	}
	if _, err := Normalize(customMarshaler{}, 128); !errors.Is(err, ErrInvalid) {
		t.Fatalf("custom marshaler was accepted: %v", err)
	}
}

func TestNormalizeRejectsAmbiguousStructAndAcceptsNilRawMessage(t *testing.T) {
	value := struct {
		First  string `json:"same"`
		Second string `json:"same"`
	}{First: "one", Second: "two"}
	if _, err := Normalize(value, 128); !errors.Is(err, ErrInvalid) {
		t.Fatalf("ambiguous struct fields were normalized: %v", err)
	}
	var empty *json.RawMessage
	if normalized, err := Normalize(empty, 128); err != nil || normalized != nil {
		t.Fatalf("nil RawMessage pointer panicked or changed: %#v, %v", normalized, err)
	}
}

func TestMarshalLimitsEscapedOutputAndNormalizesNumbers(t *testing.T) {
	value := map[string]any{"n": json.Number("9007199254740993")}
	data, err := Marshal(value, 128)
	if err != nil || !bytes.Contains(data, []byte("9007199254740993")) {
		t.Fatalf("number encoding lost precision: %s, %v", data, err)
	}
	if _, err := Marshal(string(bytes.Repeat([]byte{1}, 16)), 32); !errors.Is(err, ErrLimit) {
		t.Fatalf("escaped output was not bounded: %v", err)
	}
	deep := any("leaf")
	for i := 0; i < 34; i++ {
		deep = []any{deep}
	}
	if _, err := Normalize(deep, 128); !errors.Is(err, ErrLimit) {
		t.Fatalf("over-depth input accepted: %v", err)
	}
}

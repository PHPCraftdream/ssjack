package mcpbridge

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

func maskGuard(t *testing.T) *outputguard.Snapshot {
	t.Helper()
	guard, err := outputguard.New([][]byte{[]byte(secretLiteral)})
	if err != nil {
		t.Fatal(err)
	}
	return guard
}

func TestOpenValidationRefuses(t *testing.T) {
	guard := maskGuard(t)
	closeLaunch := func(context.Context) error { return nil }
	live := context.Background()
	canceled, cancel := context.WithCancel(live)
	cancel()
	manyHandles := make([]UpstreamHandle, 17)
	manyBindings := make([]mcpdirectory.Binding, 17)
	zeroBinding := []mcpdirectory.Binding{{ServerID: "s", AccountID: "a"}}
	cases := map[string]func() (*Runtime, error){
		"nil parent": func() (*Runtime, error) {
			return Open(nil, []UpstreamHandle{&testHandle{}}, guard, closeLaunch, []mcpdirectory.Binding{{ServerID: "s", AccountID: "a", ServerRevision: 1, AccountRevision: 1}})
		},
		"canceled parent": func() (*Runtime, error) {
			return Open(canceled, []UpstreamHandle{&testHandle{}}, guard, closeLaunch, []mcpdirectory.Binding{{ServerID: "s", AccountID: "a", ServerRevision: 1, AccountRevision: 1}})
		},
		"nil guard": func() (*Runtime, error) {
			return Open(live, []UpstreamHandle{&testHandle{}}, nil, closeLaunch, []mcpdirectory.Binding{{ServerID: "s", AccountID: "a", ServerRevision: 1, AccountRevision: 1}})
		},
		"nil close": func() (*Runtime, error) {
			return Open(live, []UpstreamHandle{&testHandle{}}, guard, nil, []mcpdirectory.Binding{{ServerID: "s", AccountID: "a", ServerRevision: 1, AccountRevision: 1}})
		},
		"length mismatch": func() (*Runtime, error) {
			return Open(live, nil, guard, closeLaunch, []mcpdirectory.Binding{{ServerID: "s", AccountID: "a", ServerRevision: 1, AccountRevision: 1}})
		},
		"empty":    func() (*Runtime, error) { return Open(live, nil, guard, closeLaunch, nil) },
		"too many": func() (*Runtime, error) { return Open(live, manyHandles, guard, closeLaunch, manyBindings) },
		"nil handle": func() (*Runtime, error) {
			return Open(live, []UpstreamHandle{nil}, guard, closeLaunch, []mcpdirectory.Binding{{ServerID: "s", AccountID: "a", ServerRevision: 1, AccountRevision: 1}})
		},
		"zero binding": func() (*Runtime, error) {
			return Open(live, []UpstreamHandle{&testHandle{}}, guard, closeLaunch, zeroBinding)
		},
	}
	for name, open := range cases {
		if runtime, err := open(); runtime != nil || !errors.Is(err, ErrBridge) {
			t.Fatalf("%s: expected ErrBridge, got %+v, %v", name, runtime, err)
		}
	}
}

func TestMaskValueWalksStringsAndPreservesControlFields(t *testing.T) {
	guard := maskGuard(t)
	value := map[string]any{
		"secret": secretLiteral,
		"nested": []any{secretLiteral, 3, true, nil, map[string]any{"deep": secretLiteral}},
		"count":  12,
	}
	budget := MaxMaskNodes
	masked, err := maskValue(guard, value, &budget)
	if err != nil {
		t.Fatal(err)
	}
	maskedMap := masked.(map[string]any)
	if maskedMap["secret"] != outputguard.Marker || maskedMap["count"] != 12 {
		t.Fatalf("unexpected masking: %+v", maskedMap)
	}
	nested := maskedMap["nested"].([]any)
	if nested[0] != outputguard.Marker || nested[1] != 3 || nested[2] != true || nested[3] != nil {
		t.Fatalf("non-string leaves were changed: %+v", nested)
	}
	if nested[4].(map[string]any)["deep"] != outputguard.Marker {
		t.Fatalf("deep string was not masked: %+v", nested[4])
	}
	// Inputs are never mutated.
	if value["secret"] != secretLiteral {
		t.Fatal("input value was mutated")
	}
	tiny := 0
	if _, err := maskValue(guard, map[string]any{"a": "b"}, &tiny); err == nil {
		t.Fatal("exhausted budget did not error")
	}
}

func TestMaskResultCoversContentKindsAndBounds(t *testing.T) {
	guard := maskGuard(t)
	result := &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: "text " + secretLiteral},
			&mcp.ImageContent{},
		},
		StructuredContent: map[string]any{"secret": secretLiteral, "n": 7},
		IsError:           true,
	}
	data, err := maskResult(guard, result)
	if err != nil {
		t.Fatal(err)
	}
	encoded := string(data)
	if !strings.Contains(encoded, outputguard.Marker) || strings.Contains(encoded, secretLiteral) {
		t.Fatalf("secret leaked through maskResult: %s", encoded)
	}
	if !strings.Contains(encoded, omittedContent) {
		t.Fatalf("non-text content was not replaced: %s", encoded)
	}
	if !strings.Contains(encoded, `"n":7`) || !strings.Contains(encoded, `"isError":true`) {
		t.Fatalf("structured value or IsError was not preserved: %s", encoded)
	}
	oversized := &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: strings.Repeat("x", 70<<10)}}}
	if _, err := maskResult(guard, oversized); !errors.Is(err, errResultSize) {
		t.Fatalf("expected errResultSize, got %v", err)
	}
}

func TestMaskValueRefusesKnownKeysAndBoundsDepthAndLeaves(t *testing.T) {
	guard := maskGuard(t)
	budget := MaxMaskNodes
	if _, err := maskValue(guard, map[string]any{secretLiteral: "safe"}, &budget); !errors.Is(err, errResultSize) {
		t.Fatal("known literal key was renamed or leaked")
	}
	deep := any("leaf")
	for i := 0; i < maxGuardDepth+2; i++ {
		deep = []any{deep}
	}
	budget = MaxMaskNodes
	if _, err := maskValue(guard, deep, &budget); err == nil {
		t.Fatal("excessive recursion depth accepted")
	}
	budget = 1
	if _, err := maskValue(guard, []any{1, true, nil}, &budget); err == nil {
		t.Fatal("non-string leaf budget was not counted")
	}
}

func TestStructuredRawMessageAndNilContentAreSafe(t *testing.T) {
	guard := maskGuard(t)
	var nilText *mcp.TextContent
	data, err := maskResult(guard, &mcp.CallToolResult{Content: []mcp.Content{nil, nilText}, StructuredContent: json.RawMessage(`{"n":123456789012345678901234567890,"safe":true}`)})
	if err != nil || !strings.Contains(string(data), "123456789012345678901234567890") {
		t.Fatalf("raw structured content lost precision: %s, %v", data, err)
	}
	if strings.Count(string(data), omittedContent) != 2 {
		t.Fatalf("nil text content was not replaced: %s", data)
	}
	if _, err := maskResult(guard, &mcp.CallToolResult{StructuredContent: json.RawMessage(`{"a":1,"a":2}`)}); err == nil {
		t.Fatal("duplicate structured keys accepted")
	}
}

func TestJSONNormalizationPreservesNumbersAndBoundsTypedRawMessage(t *testing.T) {
	decoded, err := decodeJSONNoDuplicates([]byte(`{"n":9007199254740993}`), 128, maxGuardDepth, MaxMaskNodes)
	if err != nil || decoded.(map[string]any)["n"] != json.Number("9007199254740993") {
		t.Fatalf("large integer was not preserved: %#v, %v", decoded, err)
	}
	if _, err := decodeJSONNoDuplicates([]byte(`{"n":1,"n":2}`), 128, maxGuardDepth, MaxMaskNodes); !errors.Is(err, errArguments) {
		t.Fatalf("duplicate-key error was not translated: %v", err)
	}
	deep := any("leaf")
	for i := 0; i < maxGuardDepth+2; i++ {
		deep = []any{deep}
	}
	if _, err := normalizeJSON(deep, MaxResultBytes); !errors.Is(err, errResultSize) {
		t.Fatalf("over-depth typed value was accepted: %v", err)
	}
	typed := struct {
		Payload json.RawMessage `json:"payload"`
	}{Payload: json.RawMessage(`{"n":9007199254740993}`)}
	normalized, err := normalizeJSON(typed, 128)
	if err != nil || normalized.(map[string]any)["payload"].(map[string]any)["n"] != json.Number("9007199254740993") {
		t.Fatalf("typed RawMessage was not safely normalized: %#v, %v", normalized, err)
	}
}

func TestSchemaRefusesSecretsInAnyStringToPreserveControlSemantics(t *testing.T) {
	guard := maskGuard(t)
	for _, schema := range []map[string]any{
		{"type": secretLiteral},
		{"enum": []any{secretLiteral}},
		{"properties": map[string]any{secretLiteral: map[string]any{"type": "string"}}},
		{"required": []any{secretLiteral}},
		{"const": map[string]any{"description": secretLiteral}},
		{"enum": []any{map[string]any{"description": secretLiteral}}},
	} {
		if _, err := maskSchema(guard, schema); err == nil {
			t.Fatalf("schema string secret accepted: %#v", schema)
		}
	}
}

func TestMaskSchemaPreservesOrdinaryShapeAndRefusesSecretDescription(t *testing.T) {
	guard := maskGuard(t)
	schema := map[string]any{
		"type":       "object",
		"properties": map[string]any{"q": map[string]any{"type": "string", "description": "ordinary help text"}},
	}
	masked, err := maskSchema(guard, schema)
	if err != nil {
		t.Fatal(err)
	}
	if masked["type"] != "object" {
		t.Fatalf("top-level type was lost: %+v", masked)
	}
	property := masked["properties"].(map[string]any)["q"].(map[string]any)
	if property["type"] != "string" || property["description"] != "ordinary help text" {
		t.Fatalf("schema shape or prose changed: %+v", property)
	}
	secretDescription := map[string]any{"properties": map[string]any{"q": map[string]any{"description": "about " + secretLiteral}}}
	if _, err := maskSchema(guard, secretDescription); err == nil {
		t.Fatal("secret schema description was rewritten instead of refusing the schema")
	}
	tiny := map[string]any{"blob": strings.Repeat("y", MaxSchemaBytes+1)}
	if _, err := maskSchema(guard, tiny); err == nil {
		t.Fatal("oversized schema was accepted")
	}
}

func TestMaskResultBoundsEscapedOutput(t *testing.T) {
	guard := maskGuard(t)
	control := strings.Repeat("\x01", 12<<10)
	if _, err := maskResult(guard, &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: control}}}); !errors.Is(err, errResultSize) {
		t.Fatalf("escape-expanded output exceeded its bound without refusal: %v", err)
	}
}

// awaitSignal joins one owned worker or gate with the shared one-second budget.
func awaitSignal[T any](t *testing.T, signal <-chan T, message string) T {
	t.Helper()
	select {
	case value := <-signal:
		return value
	case <-time.After(time.Second):
		t.Fatal(message)
	}
	var zero T
	return zero
}

// describeAsync launches one describe operation worker that closes exited on
// return, used by runtime lifecycle tests.
func describeAsync(t *testing.T, r *Runtime, op context.Context, exited chan struct{}, result chan wire.Reply) {
	t.Helper()
	data, err := wire.Encode(ordinalInput{})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(exited)
		reply, _ := r.Handle(op, wire.Request{Operation: OpDescribe, Data: data})
		result <- reply
	}()
}

// joinExited bounded-asserts one worker exit; cleanup-safe because it uses
// t.Error instead of t.Fatal, so every joined worker is reported.
func joinExited(t *testing.T, exited <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Error(message)
	}
}

// launchGatedClose runs the single owned shutdown worker: it waits for the
// startClose gate, closes the runtime bounded, reports the result, and only
// then releases its exit signal.
func launchGatedClose(t *testing.T, r *Runtime, startClose <-chan struct{}, closed chan<- error, closeExited chan<- struct{}) {
	t.Helper()
	go func() {
		defer close(closeExited)
		<-startClose
		closed <- closeBounded(t, r, time.Second)
	}()
}

// gateClose returns a cleanup-safe func that closes one test gate exactly once.
func gateClose(ch chan struct{}) func() {
	var once sync.Once
	return func() { once.Do(func() { close(ch) }) }
}

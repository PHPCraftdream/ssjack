package mcpbridge

import (
	"bytes"
	"reflect"

	"github.com/PHPCraftdream/ssjack/internal/mcpjson"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	omittedContent     = "[remote MCP content omitted]"
	maxGuardDepth      = 32
	maxGuardInputBytes = 256 << 10
)

type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, errResultSize
	}
	return b.Buffer.Write(p)
}

func maskString(snapshot *outputguard.Snapshot, value string, budget *int) (string, error) {
	if budget == nil || *budget <= 0 {
		return "", errResultSize
	}
	*budget--
	return maskStringValue(snapshot, value)
}

func maskStringValue(snapshot *outputguard.Snapshot, value string) (string, error) {
	if len(value) > maxGuardInputBytes {
		return "", errResultSize
	}
	var sink limitedBuffer
	sink.limit = MaxResultBytes
	writer, err := outputguard.NewWriter(snapshot, &sink)
	if err != nil {
		return "", errResultSize
	}
	if _, err = writer.Write([]byte(value)); err != nil {
		return "", errResultSize
	}
	if err = writer.Close(); err != nil {
		return "", errResultSize
	}
	return sink.String(), nil
}

func isNil(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func:
		return rv.IsNil()
	}
	return false
}

func normalizeJSON(value any, limit int) (any, error) {
	normalized, err := mcpjson.Normalize(value, limit)
	if err != nil {
		return nil, errResultSize
	}
	return normalized, nil
}

func decodeJSONNoDuplicates(data []byte, limit, depthLimit, nodeLimit int) (any, error) {
	value, err := mcpjson.Decode(data, limit, depthLimit, nodeLimit)
	if err != nil {
		return nil, errArguments
	}
	return value, nil
}

func maskValue(snapshot *outputguard.Snapshot, value any, budget *int) (any, error) {
	return maskWalk(snapshot, value, budget, 0)
}

func maskWalk(snapshot *outputguard.Snapshot, value any, budget *int, depth int) (any, error) {
	if depth > maxGuardDepth || consumeGuardNodes(budget, 1) != nil {
		return nil, errResultSize
	}
	switch v := value.(type) {
	case map[string]any:
		if len(v) > *budget/2 {
			return nil, errResultSize
		}
		out := make(map[string]any, len(v))
		for key, item := range v {
			if consumeGuardNodes(budget, 1) != nil {
				return nil, errResultSize
			}
			maskedKey, err := guarded(snapshot, key)
			if err != nil || maskedKey != key {
				return nil, errResultSize
			}
			child, err := maskWalk(snapshot, item, budget, depth+1)
			if err != nil {
				return nil, err
			}
			out[key] = child
		}
		return out, nil
	case []any:
		if len(v) > *budget {
			return nil, errResultSize
		}
		out := make([]any, len(v))
		for i, item := range v {
			child, err := maskWalk(snapshot, item, budget, depth+1)
			if err != nil {
				return nil, err
			}
			out[i] = child
		}
		return out, nil
	case string:
		return maskStringValue(snapshot, v)
	default:
		return value, nil
	}
}

func guarded(snapshot *outputguard.Snapshot, value string) (string, error) {
	budget := 1
	return maskString(snapshot, value, &budget)
}

func maskSchema(snapshot *outputguard.Snapshot, schema map[string]any) (map[string]any, error) {
	budget := MaxMaskNodes
	walked, err := schemaWalk(snapshot, schema, &budget, 0)
	if err != nil {
		return nil, errInventory
	}
	result, ok := walked.(map[string]any)
	if !ok {
		return nil, errInventory
	}
	if _, err := marshalBounded(result, MaxSchemaBytes); err != nil {
		return nil, errInventory
	}
	return result, nil
}

func schemaWalk(snapshot *outputguard.Snapshot, value any, budget *int, depth int) (any, error) {
	if depth > maxGuardDepth || consumeGuardNodes(budget, 1) != nil {
		return nil, errInventory
	}
	switch v := value.(type) {
	case map[string]any:
		if len(v) > *budget/2 {
			return nil, errInventory
		}
		out := make(map[string]any, len(v))
		for key, item := range v {
			if consumeGuardNodes(budget, 1) != nil {
				return nil, errInventory
			}
			maskedKey, err := guarded(snapshot, key)
			if err != nil || maskedKey != key {
				return nil, errInventory
			}
			child, err := schemaWalk(snapshot, item, budget, depth+1)
			if err != nil {
				return nil, err
			}
			out[key] = child
		}
		return out, nil
	case []any:
		if len(v) > *budget {
			return nil, errInventory
		}
		out := make([]any, len(v))
		for i, item := range v {
			child, err := schemaWalk(snapshot, item, budget, depth+1)
			if err != nil {
				return nil, err
			}
			out[i] = child
		}
		return out, nil
	case string:
		masked, err := guarded(snapshot, v)
		if err != nil || masked != v {
			return nil, errInventory
		}
		return v, nil
	default:
		return v, nil
	}
}

func maskResult(snapshot *outputguard.Snapshot, result *mcp.CallToolResult) ([]byte, error) {
	if result == nil || len(result.Content) > MaxMaskNodes/4 {
		return nil, errResultSize
	}
	budget := MaxMaskNodes
	if err := consumeGuardNodes(&budget, 1); err != nil {
		return nil, errResultSize
	}
	contents := make([]any, 0, len(result.Content))
	var structured any
	inputBytes := 0
	for _, item := range result.Content {
		if consumeGuardNodes(&budget, 4) != nil {
			return nil, errResultSize
		}
		if isNil(item) {
			if err := consumeGuardNodes(&budget, 1); err != nil {
				return nil, errResultSize
			}
			contents = append(contents, map[string]any{"type": "text", "text": omittedContent})
			continue
		}
		if text, ok := item.(*mcp.TextContent); ok && text != nil {
			if len(text.Text) > maxGuardInputBytes-inputBytes {
				return nil, errResultSize
			}
			inputBytes += len(text.Text)
			value, err := maskString(snapshot, text.Text, &budget)
			if err != nil {
				return nil, errResultSize
			}
			contents = append(contents, map[string]any{"type": "text", "text": value})
			continue
		}
		if err := consumeGuardNodes(&budget, 1); err != nil {
			return nil, errResultSize
		}
		contents = append(contents, map[string]any{"type": "text", "text": omittedContent})
	}
	if !isNil(result.StructuredContent) {
		normalized, err := normalizeJSON(result.StructuredContent, MaxResultBytes)
		if err != nil {
			return nil, errResultSize
		}
		walked, err := maskValue(snapshot, normalized, &budget)
		if err != nil {
			return nil, errResultSize
		}
		structured = walked
	}
	out := map[string]any{"content": contents}
	if consumeGuardNodes(&budget, 2) != nil {
		return nil, errResultSize
	}
	if result.IsError {
		if consumeGuardNodes(&budget, 2) != nil {
			return nil, errResultSize
		}
		out["isError"] = true
	}
	if structured != nil {
		if consumeGuardNodes(&budget, 1) != nil {
			return nil, errResultSize
		}
		out["structuredContent"] = structured
	}
	return marshalBounded(out, MaxResultBytes)
}

func consumeGuardNodes(budget *int, count int) error {
	if budget == nil || count < 0 || *budget < count {
		return errResultSize
	}
	*budget -= count
	return nil
}

func marshalBounded(value any, limit int) ([]byte, error) {
	encoded, err := mcpjson.Marshal(value, limit)
	if err != nil {
		return nil, errResultSize
	}
	return encoded, nil
}

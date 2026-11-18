package mcpbridge

import (
	"context"
	"encoding/json"
	"regexp"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var toolNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,48}$`)

func (r *Runtime) slotAt(ordinal int) (*slot, bool) {
	if ordinal < 0 || ordinal >= len(r.slots) {
		return nil, false
	}
	return r.slots[ordinal], true
}

// CloseBinding retires one borrowed binding; Runtime.Close retains the launch owner until every binding joins.
func (r *Runtime) CloseBinding(ctx context.Context, ordinal int) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrBridge
	}
	s, ok := r.slotAt(ordinal)
	if !ok {
		return ErrBridge
	}
	r.failBinding(s)
	s.mu.Lock()
	started := s.initStarted
	s.mu.Unlock()
	if !started {
		return nil
	}
	if !waitSignal(ctx, s.closeDone) {
		return ErrBridge
	}
	s.mu.Lock()
	closeErr := s.closeErr
	s.mu.Unlock()
	if closeErr != nil {
		return ErrBridge
	}
	return nil
}

func cloneValue(value any, depth int) (any, error) {
	if depth > 32 {
		return nil, errInventory
	}
	switch v := value.(type) {
	case map[string]any:
		copyMap := make(map[string]any, len(v))
		for key, item := range v {
			cloned, err := cloneValue(item, depth+1)
			if err != nil {
				return nil, err
			}
			copyMap[key] = cloned
		}
		return copyMap, nil
	case []any:
		copySlice := make([]any, len(v))
		for i, item := range v {
			cloned, err := cloneValue(item, depth+1)
			if err != nil {
				return nil, err
			}
			copySlice[i] = cloned
		}
		return copySlice, nil
	default:
		return value, nil
	}
}

func (r *Runtime) describe(ctx context.Context, ordinal int) (InventoryOutput, error) {
	opCtx, stop := context.WithTimeout(ctx, opBudget)
	defer stop()
	if r.ctx.Err() != nil {
		return InventoryOutput{}, errShutdown
	}
	s, ok := r.slotAt(ordinal)
	if !ok {
		return InventoryOutput{}, errUnavailable
	}
	s.mu.Lock()
	ready, failed, cached := s.inventoryReady, s.failed, s.tools
	s.mu.Unlock()
	if failed {
		return InventoryOutput{}, errInventory
	}
	if ready {
		return cloneInventory(ordinal, cached)
	}
	if err := r.ensureSession(opCtx, s); err != nil {
		return InventoryOutput{}, errInventory
	}
	if !r.acquireIO(opCtx, s) {
		return InventoryOutput{}, errInventory
	}
	defer releaseIO(s)
	s.mu.Lock()
	if s.inventoryReady {
		cached = s.tools
		s.mu.Unlock()
		return cloneInventory(ordinal, cached)
	}
	session := s.session
	s.mu.Unlock()
	if session == nil {
		return InventoryOutput{}, errInventory
	}
	listing, err := session.ListTools(opCtx, nil)
	if err != nil {
		r.failBinding(s)
		return InventoryOutput{}, errInventory
	}
	if listing == nil || listing.NextCursor != "" || len(listing.Tools) == 0 || len(listing.Tools) > MaxInventoryTools {
		r.failBinding(s)
		return InventoryOutput{}, errInventory
	}
	budget := MaxMaskNodes
	namespace := bindingNamespace(s.binding)
	tools := make([]InventoryTool, 0, len(listing.Tools))
	names := make([]string, 0, len(listing.Tools))
	seen := make(map[string]struct{}, len(listing.Tools))
	for _, tool := range listing.Tools {
		if tool == nil || len(tool.Name) > MaxUpstreamToolName || !toolNamePattern.MatchString(tool.Name) || len(tool.Description) > MaxToolDescription {
			r.failBinding(s)
			return InventoryOutput{}, errInventory
		}
		if maskedName, nameErr := guarded(r.guard, tool.Name); nameErr != nil || maskedName != tool.Name {
			r.failBinding(s)
			return InventoryOutput{}, errInventory
		}
		if _, exists := seen[tool.Name]; exists {
			r.failBinding(s)
			return InventoryOutput{}, errInventory
		}
		seen[tool.Name] = struct{}{}
		maskedDescription, maskErr := maskString(r.guard, tool.Description, &budget)
		if maskErr != nil {
			r.failBinding(s)
			return InventoryOutput{}, errInventory
		}
		schema, decodeErr := normalizeJSON(tool.InputSchema, MaxSchemaBytes)
		if decodeErr != nil {
			r.failBinding(s)
			return InventoryOutput{}, errInventory
		}
		schemaMap, ok := schema.(map[string]any)
		if !ok || schemaMap["type"] != "object" {
			r.failBinding(s)
			return InventoryOutput{}, errInventory
		}
		maskedSchema, schemaErr := maskSchema(r.guard, schemaMap)
		if schemaErr != nil {
			r.failBinding(s)
			return InventoryOutput{}, errInventory
		}
		name := namespace + tool.Name
		if len(name) > 64 {
			r.failBinding(s)
			return InventoryOutput{}, errInventory
		}
		tools = append(tools, InventoryTool{Name: name, Description: maskedDescription, Schema: maskedSchema})
		names = append(names, tool.Name)
	}
	out := InventoryOutput{Ordinal: ordinal, Tools: tools}
	if _, err = marshalBounded(out, MaxInventoryBytes); err != nil {
		r.failBinding(s)
		return InventoryOutput{}, errInventory
	}
	s.mu.Lock()
	if s.failed || r.ctx.Err() != nil || opCtx.Err() != nil {
		s.mu.Unlock()
		return InventoryOutput{}, errInventory
	}
	s.tools = tools
	s.upstreamNames = names
	s.inventoryReady = true
	s.mu.Unlock()
	return cloneInventory(ordinal, tools)
}

func cloneInventory(ordinal int, tools []InventoryTool) (InventoryOutput, error) {
	copyTools := make([]InventoryTool, len(tools))
	for i, tool := range tools {
		schema, err := cloneValue(tool.Schema, 0)
		if err != nil {
			return InventoryOutput{}, errInventory
		}
		copyTools[i] = InventoryTool{Name: tool.Name, Description: tool.Description, Schema: schema.(map[string]any)}
	}
	return InventoryOutput{Ordinal: ordinal, Tools: copyTools}, nil
}

func (r *Runtime) call(ctx context.Context, input CallInput) (CallOutput, error) {
	opCtx, stop := context.WithTimeout(ctx, opBudget)
	defer stop()
	if r.ctx.Err() != nil {
		return CallOutput{}, errShutdown
	}
	s, ok := r.slotAt(input.Ordinal)
	if !ok {
		return CallOutput{}, errUnavailable
	}
	s.mu.Lock()
	if s.failed || !s.inventoryReady {
		s.mu.Unlock()
		return CallOutput{}, errInventory
	}
	session := s.session
	tools := s.tools
	names := s.upstreamNames
	s.mu.Unlock()
	if session == nil {
		return CallOutput{}, errInventory
	}
	index := -1
	for i, tool := range tools {
		if tool.Name == input.Tool {
			index = i
			break
		}
	}
	if index < 0 {
		return CallOutput{}, errUnknownTool
	}
	if input.Arguments != "" && len(input.Arguments) > MaxArgumentsBytes {
		return CallOutput{}, errArguments
	}
	var args any = map[string]any{}
	if input.Arguments != "" {
		decoded, err := decodeJSONNoDuplicates([]byte(input.Arguments), MaxArgumentsBytes, 32, MaxMaskNodes)
		if err != nil {
			return CallOutput{}, errArguments
		}
		if _, ok := decoded.(map[string]any); !ok {
			return CallOutput{}, errArguments
		}
		args = decoded
	}
	argBytes, err := json.Marshal(args)
	if err != nil || len(argBytes) > MaxUpstreamArguments {
		return CallOutput{}, errArguments
	}
	body, err := json.Marshal(struct {
		JSONRPC string             `json:"jsonrpc"`
		ID      int                `json:"id"`
		Method  string             `json:"method"`
		Params  mcp.CallToolParams `json:"params"`
	}{"2.0", 1, "tools/call", mcp.CallToolParams{Name: names[index], Arguments: args}})
	if err != nil || len(body) > 64<<10 {
		return CallOutput{}, errArguments
	}
	if !r.acquireIO(opCtx, s) {
		return CallOutput{}, errCallFailed
	}
	defer releaseIO(s)
	if opCtx.Err() != nil || r.ctx.Err() != nil {
		return CallOutput{}, errCallFailed
	}
	result, err := session.CallTool(opCtx, &mcp.CallToolParams{Name: names[index], Arguments: args})
	if err != nil {
		r.failBinding(s)
		return CallOutput{}, errCallFailed
	}
	masked, err := maskResult(r.guard, result)
	if err != nil {
		return CallOutput{}, errResultSize
	}
	if opCtx.Err() != nil || r.ctx.Err() != nil {
		return CallOutput{}, errCallFailed
	}
	return CallOutput{Result: string(masked)}, nil
}

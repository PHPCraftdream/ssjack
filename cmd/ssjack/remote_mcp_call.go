package main

import (
	"bytes"
	"context"
	"encoding/json"

	mcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/mcpchannel"
)

func remoteMCPTool(registration *remoteMCPRegistration, client *mcpchannel.Client, name string) mcp.ToolHandler {
	return func(ctx context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !registration.beginCall() {
			return remoteMCPFailure(), nil
		}
		defer registration.endCall()
		if request == nil || request.Params == nil {
			return remoteMCPFailure(), nil
		}
		raw := request.Params.Arguments
		if len(raw) == 0 {
			raw = []byte("{}")
		}
		if len(raw) > mcpchannel.MaxClientInputBytes {
			return remoteMCPFailure(), nil
		}
		callCtx, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(registration.ctx, cancel)
		defer func() { stop(); cancel() }()
		result, err := client.Call(callCtx, name, raw)
		if err != nil {
			return remoteMCPFailure(), nil
		}
		var output mcp.CallToolResult
		var structured struct {
			StructuredContent json.RawMessage `json:"structuredContent"`
		}
		if err := json.Unmarshal(result, &output); err != nil || json.Unmarshal(result, &structured) != nil {
			return remoteMCPFailure(), nil
		}
		if len(structured.StructuredContent) != 0 && !bytes.Equal(bytes.TrimSpace(structured.StructuredContent), []byte("null")) {
			output.StructuredContent = append(json.RawMessage(nil), structured.StructuredContent...)
		}
		if output.Content == nil && output.StructuredContent == nil {
			return remoteMCPFailure(), nil
		}
		return &output, nil
	}
}

func remoteMCPFailure() *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "remote MCP tool call failed"}}}
}

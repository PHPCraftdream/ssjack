package mcpbridge

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	modernProtocolVersion = "2026-07-28"
	discoverMethod        = "server/discover"
)

func upstreamSendingMiddleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		if method == "initialize" {
			if params, ok := req.GetParams().(*mcp.InitializeParams); ok {
				params.ProtocolVersion = upstreamProtocolVersion
			}
		}
		result, err := next(ctx, method, req)
		if err != nil {
			return result, err
		}
		if method == "tools/call" {
			if callResult, ok := result.(*mcp.CallToolResult); ok && callResult.NeedsInput() {
				return nil, errCallFailed
			}
		}
		return result, nil
	}
}

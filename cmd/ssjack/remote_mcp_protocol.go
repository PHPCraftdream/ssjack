package main

import (
	"context"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	mcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	maxRemoteMCPSubscriptionsListenHandlers = 1
	remoteMCPSubscriptionsListenBudget      = time.Minute
)

func configureMCPStdioServer(server *mcp.Server) {
	var mu sync.Mutex
	active := 0

	server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method != "subscriptions/listen" {
				return next(ctx, method, req)
			}

			mu.Lock()
			if active >= maxRemoteMCPSubscriptionsListenHandlers {
				mu.Unlock()
				return nil, &jsonrpc.Error{
					Code:    jsonrpc.CodeInvalidParams,
					Message: "subscriptions/listen already active",
				}
			}
			active++
			mu.Unlock()

			defer func() {
				mu.Lock()
				active--
				mu.Unlock()
			}()

			boundedCtx, cancel := context.WithTimeout(ctx, remoteMCPSubscriptionsListenBudget)
			defer cancel()
			return next(boundedCtx, method, req)
		}
	})
}

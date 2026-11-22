package remotemcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/PHPCraftdream/ssjack/internal/bridge"
	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/hooks"
	"github.com/PHPCraftdream/ssjack/internal/lifelog"
	"github.com/PHPCraftdream/ssjack/internal/mcpchannel"
	"github.com/PHPCraftdream/ssjack/internal/mcpstart"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	mcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"io"
	"os"
	"strconv"
	"sync"
)

func runHook(args []string) (int, error) {
	if len(args) != 1 {
		return 1, errors.New("usage: ssjack hook pre|post|failure")
	}
	input, err := io.ReadAll(io.LimitReader(os.Stdin, hooks.MaxInput+1))
	if err != nil {
		return 1, errors.New("failed to read hook event")
	}
	output, err := hooks.Run(args[0], input)
	if err != nil {
		return 1, err
	}
	if _, err := fmt.Fprintln(os.Stdout, string(output)); err != nil {
		return 1, err
	}
	return 0, nil
}

func runMCP(ctx context.Context) (int, error) {
	// Read before the bootstrap environment is consumed; the log holds no secret.
	life := lifelog.New(os.Getenv(lifelog.Env), "mcp", os.Getenv(broker.EnvSession))
	life.Event("start", "ppid", strconv.Itoa(os.Getppid()))
	code, stage, err := serveMCP(ctx, life)
	life.Event("exit", "code", strconv.Itoa(code), "stage", stage, "context", lifelog.Cause(ctx.Err()))
	return code, err
}

// serveMCP also names the stage it stopped at, for the lifecycle log only.
func serveMCP(ctx context.Context, life *lifelog.Log) (int, string, error) {
	bootstrap, descriptors, err := mcpstart.ReadEnvironment()
	if err != nil {
		return 1, "bootstrap-environment", err
	}
	defer func() { bootstrap.Token = "" }()
	client, err := broker.ConnectBootstrap(ctx, bootstrap)
	bootstrap.Token = ""
	if err != nil {
		stage := "attach-parameters"
		switch {
		case errors.Is(err, broker.ErrDial):
			stage = "attach-dial"
		case errors.Is(err, broker.ErrAuth):
			stage = "attach-send"
		case errors.Is(err, broker.ErrRejected):
			stage = "attach-rejected"
		}
		return 1, stage, errors.New("MCP session attachment failed")
	}
	defer client.Close()
	client.SetTrace(life.Event)
	life.Event("attached")
	descriptor, err := broker.Describe(ctx, client)
	if err != nil {
		return 1, "describe", errors.New("keeper descriptor unavailable or invalid; refusing MCP startup")
	}
	server, err := bridge.NewRegistryForDescriptor(client, descriptor)
	if err != nil {
		return 1, "registry", errors.New("keeper descriptor unavailable or invalid; refusing MCP startup")
	}
	connCtx, cancel := context.WithCancel(ctx)
	configureMCPStdioServer(server, connCtx)
	registration := startRemoteMCPRegistration(connCtx, descriptors, server)
	life.Event("serving")
	runErr := server.Run(connCtx, newMCPStdioTransport(os.Stdin, os.Stdout))
	life.Event("stdio-end", "cause", stdioCause(runErr))
	cancel()
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), remoteMCPRegistrationBudget)
	cleanupErr := registration.Close(cleanupCtx)
	cleanupCancel()
	if cleanupErr != nil {
		return 1, "cleanup", errors.New("MCP bridge cleanup did not complete")
	}
	if runErr != nil {
		return 1, "stdio", errors.New("MCP bridge session failed")
	}
	return 0, "stdio-closed", nil
}

// stdioCause names the bridge's own stdio refusals, which the generic classes
// would all record as other.
func stdioCause(err error) string {
	switch {
	case errors.Is(err, errMCPStdioBatchUnsupported):
		return "unsupported-batch"
	case errors.Is(err, errMCPStdioMessageLimit), errors.Is(err, errMCPStdioMessageCountLimit):
		return "stdio-limit"
	case errors.Is(err, errMCPStdioInvalidMessage):
		return "invalid-message"
	case errors.Is(err, errMCPStdioUnsupportedMethod):
		return "unsupported-message"
	case errors.Is(err, errMCPStdioConcurrentRead):
		return "concurrent-read"
	case errors.Is(err, errMCPStdioWriteTimeout):
		return "stdio-write-timeout"
	}
	return lifelog.Cause(err)
}

const (
	maxRemoteMCPSubscriptionsListenHandlers = 1
	// remoteMCPToolListCacheTTLMs bounds how long a client may reuse a
	// tools/list result; a registry change notifies subscribed clients at
	// once, so it only bounds the staleness a client that subscribed to
	// nothing can observe.
	remoteMCPToolListCacheTTLMs = 5000
	// remoteMCPToolListCacheScope is private: the list describes the owner's
	// configured targets, applications and channels, not a shared resource.
	remoteMCPToolListCacheScope = "private"
)

// configureMCPStdioServer gives the served registry its listen and list-cache
// policy. shutdown is the bridge's own lifetime, the context handed to
// Server.Run: ending it must never wait on a parked listen. At most one
// subscriptions/listen is admitted, and it holds its slot for as long as its
// request context lives. The SDK cancels a parked listen on session close only
// after it has recorded the request ID, and it releases the request for
// asynchronous handling before that record, so a close starting in between
// would wait on the handler indefinitely; the shutdown context therefore
// cancels every admitted listen as well. The SDK still acknowledges only the
// requested notification types it advertises and completes a listen that
// accepted none.
func configureMCPStdioServer(server *mcp.Server, shutdown context.Context) {
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

			listenCtx, ceaseListen := context.WithCancel(ctx)
			stopShutdown := context.AfterFunc(shutdown, ceaseListen)
			defer func() {
				stopShutdown()
				ceaseListen()
				mu.Lock()
				active--
				mu.Unlock()
			}()

			return next(listenCtx, method, req)
		}
	})

	server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			result, err := next(ctx, method, req)
			if err != nil || method != "tools/list" {
				return result, err
			}
			if listing, ok := result.(*mcp.ListToolsResult); ok && listing != nil {
				listing.Cacheable = mcp.Cacheable{TTLMs: remoteMCPToolListCacheTTLMs, CacheScope: remoteMCPToolListCacheScope}
			}
			return result, nil
		}
	})
}

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

func Run(ctx context.Context) (int, error) { return runMCP(ctx) }

func RunHook(args []string) (int, error) { return runHook(args) }

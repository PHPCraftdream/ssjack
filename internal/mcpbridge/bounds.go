// Package mcpbridge supervises one confirmed remote MCP launch inside the
// startup process, exposing only three bounded keeper operations to the child
// bridge and holding no credential knowledge of its own.
package mcpbridge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
)

// Keeper operations the child bridge process may request. Nothing else is
// handled, so the model-facing surface is closed by construction.
const (
	OpBindings = "mcp_remote_bindings"
	OpDescribe = "mcp_remote_describe"
	OpCall     = "mcp_remote_call"
)

const (
	MaxInventoryTools    = 64
	MaxUpstreamToolName  = 48
	MaxToolDescription   = 4096
	MaxSchemaBytes       = 16 << 10
	MaxInventoryBytes    = 192 << 10
	MaxMaskNodes         = 8192
	MaxArgumentsBytes    = 48 << 10
	MaxUpstreamArguments = 56 << 10
	MaxResultBytes       = 64 << 10
	RuntimeLease         = 10 * time.Minute
	MaxActiveOperations  = 4
	MaxRuntimeMessages   = 4096
	OpBudget             = 20 * time.Second
	ConnectWait          = 18 * time.Second
	DisconnectBudget     = time.Minute
)

var (
	errUnavailable = errors.New("remote MCP connection is not available")
	errShutdown    = errors.New("remote MCP bridge is shutting down")
	errInventory   = errors.New("remote MCP inventory is unavailable")
	errUnknownTool = errors.New("unknown remote MCP tool for this connection")
	errArguments   = errors.New("remote MCP tool arguments are invalid or too large")
	errCallFailed  = errors.New("remote MCP tool call failed")
	errResultSize  = errors.New("remote MCP result is too large to deliver")
	ErrBridge      = errors.New("remote MCP bridge cleanup did not complete")
)

var (
	opBudget    = OpBudget
	connectWait = ConnectWait
)

type BindingsOutput struct {
	Ordinals []int `json:"ordinals"`
}
type InventoryTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Schema      map[string]any `json:"schema"`
}
type InventoryOutput struct {
	Ordinal int             `json:"ordinal"`
	Tools   []InventoryTool `json:"tools"`
}
type InventoryEnvelope struct {
	Inventory string `json:"inventory"`
}
type CallInput struct {
	Ordinal   int    `json:"ordinal"`
	Tool      string `json:"tool"`
	Arguments string `json:"arguments,omitempty"`
}
type CallOutput struct {
	Result string `json:"result"`
}

type slot struct {
	binding        mcpdirectory.Binding
	handle         UpstreamHandle
	ctx            context.Context
	cancel         context.CancelFunc
	mu             sync.Mutex
	failed         bool
	initStarted    bool
	initDone       chan struct{}
	initErr        error
	session        *mcp.ClientSession
	conn           mcp.Connection
	tools          []InventoryTool
	upstreamNames  []string
	inventoryReady bool
	ioGate         chan struct{}
	closeOnce      sync.Once
	closeDone      chan struct{}
	closeStarted   chan struct{}
	closeErr       error
}

func bindingNamespace(binding mcpdirectory.Binding) string {
	identity := fmt.Sprintf("%d:%s|%d:%s|%d|%d", len(binding.ServerID), binding.ServerID, len(binding.AccountID), binding.AccountID, binding.ServerRevision, binding.AccountRevision)
	digest := sha256.Sum256([]byte(identity))
	return "mcp" + hex.EncodeToString(digest[:6]) + "_"
}

// lateCaptureClose publishes a connection captured by the initializing client
// and closes it immediately when slot shutdown already began, unblocking a
// wedged Client.Connect. The close error is retained under the slot mutex.
func (s *slot) lateCaptureClose(conn mcp.Connection) {
	if conn == nil {
		return
	}
	s.mu.Lock()
	s.conn = conn
	lateClose := false
	select {
	case <-s.closeStarted:
		lateClose = true
	default:
	}
	s.mu.Unlock()
	if !lateClose {
		return
	}
	if closeErr := conn.Close(); closeErr != nil {
		s.mu.Lock()
		s.closeErr = errors.Join(s.closeErr, closeErr)
		s.mu.Unlock()
	}
}

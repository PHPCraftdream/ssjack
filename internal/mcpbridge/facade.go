// Package mcpbridge supervises one confirmed remote MCP launch inside the
// startup process, exposing only three bounded keeper operations to the child
// bridge and holding no credential knowledge of its own.
package mcpbridge

import (
	"context"

	supervisor "github.com/PHPCraftdream/ssjack/internal/mcpbridge/internal/supervisor"
	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
)

// Keeper operations the child bridge process may request.
const (
	OpBindings = supervisor.OpBindings
	OpDescribe = supervisor.OpDescribe
	OpCall     = supervisor.OpCall
)

const (
	MaxInventoryTools    = supervisor.MaxInventoryTools
	MaxUpstreamToolName  = supervisor.MaxUpstreamToolName
	MaxToolDescription   = supervisor.MaxToolDescription
	MaxSchemaBytes       = supervisor.MaxSchemaBytes
	MaxInventoryBytes    = supervisor.MaxInventoryBytes
	MaxMaskNodes         = supervisor.MaxMaskNodes
	MaxArgumentsBytes    = supervisor.MaxArgumentsBytes
	MaxUpstreamArguments = supervisor.MaxUpstreamArguments
	MaxResultBytes       = supervisor.MaxResultBytes
	RuntimeLease         = supervisor.RuntimeLease
	MaxActiveOperations  = supervisor.MaxActiveOperations
	MaxRuntimeMessages   = supervisor.MaxRuntimeMessages
	OpBudget             = supervisor.OpBudget
	ConnectWait          = supervisor.ConnectWait
	DisconnectBudget     = supervisor.DisconnectBudget
)

var ErrBridge = supervisor.ErrBridge

type (
	UpstreamHandle    = supervisor.UpstreamHandle
	LaunchUpstream    = supervisor.LaunchUpstream
	Runtime           = supervisor.Runtime
	BindingsOutput    = supervisor.BindingsOutput
	InventoryTool     = supervisor.InventoryTool
	InventoryOutput   = supervisor.InventoryOutput
	InventoryEnvelope = supervisor.InventoryEnvelope
	CallInput         = supervisor.CallInput
	CallOutput        = supervisor.CallOutput
)

// Open validates and owns immutable copies of the launch-minted capability set.
func Open(parent context.Context, handles []UpstreamHandle, guard *outputguard.Snapshot, closeLaunch func(context.Context) error, bindings []mcpdirectory.Binding) (*Runtime, error) {
	return supervisor.Open(parent, handles, guard, closeLaunch, bindings)
}

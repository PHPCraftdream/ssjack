package bridge

import (
	"io"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	confirm "github.com/PHPCraftdream/ssjack/internal/bridge/internal/confirm"
	tooltext "github.com/PHPCraftdream/ssjack/internal/bridge/internal/tooltext"
	"github.com/PHPCraftdream/ssjack/internal/broker"
)

// ReadOutput is the output of one read as ParseResult recovers it from the
// result text; see tooltext.ReadOutput.
type ReadOutput = tooltext.ReadOutput

// NewDeclarativeServer builds the empty declarative registry.
func NewDeclarativeServer() *mcp.Server {
	return tooltext.NewDeclarativeServer()
}

// NewServer builds the full registry of the remote, application and transfer
// tools.
func NewServer(client *broker.Client) *mcp.Server {
	return tooltext.NewServer(client)
}

// NewFullServer is the full registry of the remote, application and transfer
// tools.
func NewFullServer(client *broker.Client) *mcp.Server {
	return tooltext.NewFullServer(client)
}

// NewRegistryForDescriptor selects the registry a broker descriptor asks for.
func NewRegistryForDescriptor(client *broker.Client, descriptor broker.Descriptor) (*mcp.Server, error) {
	return tooltext.NewRegistryForDescriptor(client, descriptor)
}

// ConfirmManager is the optional manager used for interactive tool approval.
type ConfirmManager = confirm.Manager

// NewConfirmManager builds the elicitation manager wired to the keeper.
func NewConfirmManager(client *broker.Client, now func() time.Time, random io.Reader) *ConfirmManager {
	return tooltext.NewConfirmManager(client, now, random)
}

// NewRegistryForDescriptorWithConfirm selects the registry and optional approval manager.
func NewRegistryForDescriptorWithConfirm(client *broker.Client, descriptor broker.Descriptor, confirmMgr *ConfirmManager) (*mcp.Server, error) {
	return tooltext.NewRegistryForDescriptorWithConfirm(client, descriptor, confirmMgr)
}

// ParseResult is the reference reader of the text contract: it fills out from
// the text of a tool result; see tooltext.ParseResult.
func ParseResult(text string, out any) error {
	return tooltext.ParseResult(text, out)
}

// ResultText returns the text of a tool result of this package: exactly one
// text content block and no structured content.
func ResultText(result *mcp.CallToolResult) (string, error) {
	return tooltext.ResultText(result)
}

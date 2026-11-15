package main

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

// methodNotFoundWire is decoded per refusal so the SDK encoder keeps the
// standard JSON-RPC code; the SDK does not export its error type.
var methodNotFoundWire = []byte(`{"jsonrpc":"2.0","id":0,"error":{"code":-32601,"message":"method not found"}}`)

// refuseUnsupported keeps the SDK surface to supportedMCPMethod without ending
// the session: a call outside it is answered with method-not-found and a
// notification outside it is dropped, as JSON-RPC requires. Clients probe with
// such calls (Claude Code sends server/discover before initialize) and treat a
// closed stdio as a dead server, which a single-use bridge cannot survive. An
// inbound response stays fatal: the bridge sends the client no requests.
func (c *mcpStdioConnection) refuseUnsupported(ctx context.Context, messages []jsonrpc.Message) ([]jsonrpc.Message, error) {
	admitted := make([]jsonrpc.Message, 0, len(messages))
	for _, message := range messages {
		request, ok := message.(*jsonrpc.Request)
		if !ok {
			return nil, errMCPStdioUnsupportedMethod
		}
		if supportedMCPMethod(request.Method) {
			admitted = append(admitted, request)
			continue
		}
		if !request.ID.IsValid() {
			continue
		}
		refusal, err := methodNotFound(request.ID)
		if err != nil {
			return nil, err
		}
		if err := c.Write(ctx, refusal); err != nil {
			return nil, err
		}
	}
	return admitted, nil
}

func methodNotFound(id jsonrpc.ID) (*jsonrpc.Response, error) {
	message, err := jsonrpc.DecodeMessage(methodNotFoundWire)
	if err != nil {
		return nil, err
	}
	response, ok := message.(*jsonrpc.Response)
	if !ok {
		return nil, errMCPStdioInvalidMessage
	}
	response.ID = id
	return response, nil
}

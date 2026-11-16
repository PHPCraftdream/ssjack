package main

import (
	"context"
	"encoding/json"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

// methodNotFoundWire is decoded to create a method-not-found response.
var methodNotFoundWire = []byte(`{"jsonrpc":"2.0","id":0,"error":{"code":-32601,"message":"method not found"}}`)

const mcpProtocolVersionMetaKey = "io.modelcontextprotocol/protocolVersion"

// refuseUnsupported keeps the SDK surface to supportedMCPMethod without ending
// the session: unsupported calls are answered and notifications are dropped.
// Per-request protocol metadata is checked before the method surface so the SDK
// cannot silently negotiate or accept a version this transport does not serve.
// An inbound response stays fatal: the bridge sends the client no requests.
func (c *mcpStdioConnection) refuseUnsupported(ctx context.Context, messages []jsonrpc.Message) ([]jsonrpc.Message, error) {
	admitted := make([]jsonrpc.Message, 0, len(messages))
	for _, message := range messages {
		request, ok := message.(*jsonrpc.Request)
		if !ok {
			return nil, errMCPStdioUnsupportedMethod
		}

		version, present, valid := requestMCPProtocolVersion(request.Params)
		if present && !valid {
			if !request.ID.IsValid() {
				continue
			}
			if err := c.writeRequestError(ctx, request.ID, jsonrpc.CodeInvalidParams, "Invalid params", nil); err != nil {
				return nil, err
			}
			continue
		}
		if present && !supportedMCPProtocol(version) {
			if !request.ID.IsValid() {
				continue
			}
			data, err := json.Marshal(struct {
				Supported []string `json:"supported"`
				Requested string   `json:"requested"`
			}{Supported: supportedMCPProtocols(), Requested: version})
			if err != nil {
				return nil, err
			}
			if err := c.writeRequestError(ctx, request.ID, -32022, "Unsupported protocol version", data); err != nil {
				return nil, err
			}
			continue
		}

		if request.Method == "subscriptions/listen" && (!present || version < mcpProtocol20260728) {
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
			continue
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

// requestMCPProtocolVersion extracts only the protocol version from _meta.
// Malformed parameter envelopes are left for the SDK to validate; a present
// protocolVersion value that is not a JSON string is reported as invalid params.
func requestMCPProtocolVersion(params json.RawMessage) (version string, present, valid bool) {
	var object map[string]json.RawMessage
	if json.Unmarshal(params, &object) != nil || object == nil {
		return "", false, true
	}
	metaRaw, ok := object["_meta"]
	if !ok {
		return "", false, true
	}
	var meta map[string]json.RawMessage
	if json.Unmarshal(metaRaw, &meta) != nil || meta == nil {
		return "", false, true
	}
	versionRaw, ok := meta[mcpProtocolVersionMetaKey]
	if !ok {
		return "", false, true
	}
	var decoded any
	if json.Unmarshal(versionRaw, &decoded) != nil {
		return "", true, false
	}
	version, ok = decoded.(string)
	if !ok {
		return "", true, false
	}
	return version, true, true
}

func (c *mcpStdioConnection) writeRequestError(ctx context.Context, id jsonrpc.ID, code int64, message string, data json.RawMessage) error {
	return c.Write(ctx, &jsonrpc.Response{
		ID:    id,
		Error: &jsonrpc.Error{Code: code, Message: message, Data: data},
	})
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

package declarativeschemas

import (
	"encoding/json"
	"errors"

	"github.com/PHPCraftdream/ssjack/internal/domaindigest"
)

type Tool struct {
	Name         string
	SchemaID     string
	SchemaDigest string
	InputSchema  string
	OutputSchema string
}

var ErrUnknownTool = errors.New("unknown declarative tool")

func Catalog() ([]Tool, error) {
	planInput := resourceInput()
	planInput["desired"] = dynamic()
	planInput["request_id"] = stringNode(22)

	specs := []struct {
		name   string
		input  node
		output node
	}{
		{"driver_list", object(node{}), object(node{
			"drivers": array(driver(), 0, 128),
		})},
		{"resource_status", object(resourceInput()), object(node{
			"state":       enumeration("present", "absent", "unknown"),
			"revision":    nullable(stringNode(128)),
			"observed_at": stringNode(24),
			"projection":  dynamic(),
		})},
		{"resource_plan", object(planInput), object(node{
			"plan_id":    stringNode(22),
			"digest":     stringNode(64),
			"expires_at": stringNode(24),
			"effects": array(object(node{
				"class":       stringNode(64),
				"summary_id":  stringNode(64),
				"destructive": boolean(),
			}), 0, 256),
			"precondition": nullable(stringNode(128)),
		})},
		{"plan_apply", object(node{
			"plan_id":    stringNode(22),
			"request_id": stringNode(22),
		}), object(node{
			"operation_id": stringNode(22),
			"state":        state(),
		})},
		{"operation_read", object(node{
			"operation_id": stringNode(22),
		}), object(node{
			"operation_id": stringNode(22),
			"state":        state(),
			"phase":        enumeration("queued", "observing", "planning", "applying", "verifying", "reconciling", "cancelling", "complete"),
			"progress":     nullable(integer(0, 100)),
			"revisions":    revisions(),
			"result":       nullable(safeResult()),
			"error":        nullable(errorNode()),
			"updated_at":   stringNode(24),
		})},
		{"operation_cancel", object(node{
			"operation_id": stringNode(22),
			"request_id":   stringNode(22),
		}), object(node{
			"operation_id": stringNode(22),
			"state":        state(),
			"cancellation": enumeration("confirmed", "unsupported", "pending"),
		})},
	}

	tools := make([]Tool, 0, len(specs))
	for _, spec := range specs {
		input, err := document(spec.input)
		if err != nil {
			return nil, err
		}
		output, err := document(spec.output)
		if err != nil {
			return nil, err
		}
		pair, err := json.Marshal(struct {
			Input  json.RawMessage `json:"input"`
			Output json.RawMessage `json:"output"`
		}{json.RawMessage(input), json.RawMessage(output)})
		if err != nil {
			return nil, err
		}
		digest, err := domaindigest.Sum(domaindigest.ToolSchema, pair)
		if err != nil {
			return nil, err
		}
		tools = append(tools, Tool{
			Name:         spec.name,
			SchemaID:     "ssjack.tool." + spec.name + ".v1",
			SchemaDigest: digest,
			InputSchema:  input,
			OutputSchema: output,
		})
	}
	return tools, nil
}

func Lookup(name string) (Tool, error) {
	switch name {
	case "driver_list", "resource_status", "resource_plan", "plan_apply", "operation_read", "operation_cancel":
	default:
		return Tool{}, ErrUnknownTool
	}
	tools, err := Catalog()
	if err != nil {
		return Tool{}, err
	}
	for _, tool := range tools {
		if tool.Name == name {
			return tool, nil
		}
	}
	return Tool{}, ErrUnknownTool
}

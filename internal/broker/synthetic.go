package broker

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/PHPCraftdream/ssjack/internal/declarativeslice"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

func DispatchSynthetic(session *declarativeslice.Session) (Handler, error) {
	if session == nil {
		return nil, errors.New("synthetic session required")
	}
	if _, err := session.Describe(); err != nil {
		return nil, errors.New("invalid synthetic session")
	}
	return func(ctx context.Context, req wire.Request) wire.Reply {
		if req.Operation == "session.describe" {
			var input DescribeRequest
			if wire.DecodeStrict(req.Data, &input, "discovery") != nil || input.Discovery != DiscoveryRequest {
				return wire.Reply{Error: "unsupported descriptor request"}
			}
			protocol := SyntheticProtocol
			if session.IsDelivery() {
				protocol = DeliveryProtocol
			}
			d := Descriptor{Protocol: protocol, Mode: ModeDeclarative, Complete: false, Tools: []string{"resource_plan", "plan_apply"}}
			return Result(d, nil)
		}
		switch req.Operation {
		case "resource_plan":
			var in declarativeslice.PlanInput
			if wire.DecodeStrict(req.Data, &in, "target", "driver_id", "kind", "schema_id", "resource_id", "desired", "request_id") != nil {
				return wire.Reply{Error: "invalid synthetic plan request"}
			}
			out, err := session.Plan(ctx, mustJSON(in))
			return Result(out, err)
		case "plan_apply":
			var in declarativeslice.ApplyInput
			if wire.DecodeStrict(req.Data, &in, "plan_id", "request_id") != nil {
				return wire.Reply{Error: "invalid synthetic apply request"}
			}
			out, err := session.Apply(ctx, mustJSON(in))
			return Result(out, err)
		default:
			return wire.Reply{Error: "operation unavailable in this session mode"}
		}
	}, nil
}
func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

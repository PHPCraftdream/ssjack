package broker

import (
	"context"
	"errors"

	"github.com/PHPCraftdream/ssjack/internal/wire"
	"github.com/ktav-lang/golang/pure"
)

type Mode string

const (
	ModeFull         Mode = "full"
	ModeDeclarative  Mode = "declarative"
	PartialProtocol       = "ssjack-declarative-partial-0"
	FullProtocol          = "ssjack-full-1"
	DiscoveryRequest      = "ssjack-session-discovery"
)

type Descriptor struct {
	Protocol string   `json:"protocol"`
	Mode     Mode     `json:"mode"`
	Complete bool     `json:"complete"`
	Tools    []string `json:"tools"`
}

type DescribeRequest struct {
	Discovery string `json:"discovery"`
}

func ValidateDescriptor(d Descriptor) error {
	fullTools := []string{"remote_targets", "remote_exec", "remote_read", "remote_cancel", "app_list", "app_exec", "app_read", "app_cancel"}
	if d.Mode == ModeFull && d.Protocol == FullProtocol && d.Complete && equalTools(d.Tools, fullTools) {
		return nil
	}
	if d.Mode == ModeDeclarative && d.Protocol == PartialProtocol && !d.Complete && len(d.Tools) == 0 {
		return nil
	}
	return errors.New("invalid keeper session descriptor")
}

func equalTools(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Dispatch fixes mode when the keeper is constructed; it is not request-selected.
func Dispatch(mode Mode, full Handler) Handler {
	if mode != ModeFull && mode != ModeDeclarative {
		panic("invalid immutable keeper mode")
	}
	if mode == ModeFull && full == nil {
		panic("full keeper requires a handler")
	}
	return func(ctx context.Context, request wire.Request) wire.Reply {
		if request.Operation == "session.describe" {
			protocol := FullProtocol
			tools := []string{"remote_targets", "remote_exec", "remote_read", "remote_cancel", "app_list", "app_exec", "app_read", "app_cancel"}
			complete := true
			if mode == ModeDeclarative {
				protocol, tools, complete = PartialProtocol, []string{}, false
			}
			var input DescribeRequest
			if wire.DecodeStrict(request.Data, &input, "discovery") != nil || input.Discovery != DiscoveryRequest {
				return wire.Reply{Error: "unsupported descriptor request"}
			}
			return Result(Descriptor{Protocol: protocol, Mode: mode, Complete: complete, Tools: tools}, nil)
		}
		if mode == ModeDeclarative {
			return DeclarativeDenyAll(ctx, request)
		}
		return full(ctx, request)
	}
}

func Describe(ctx context.Context, client *Client) (Descriptor, error) {
	var descriptor Descriptor
	input := DescribeRequest{Discovery: DiscoveryRequest}
	data, err := client.CallRaw(ctx, "session.describe", input)
	if err != nil {
		return Descriptor{}, err
	}
	parsed, err := pure.Loads(data)
	if err != nil {
		return Descriptor{}, err
	}
	fields, ok := parsed.(map[string]any)
	if !ok || len(fields) != 4 {
		return Descriptor{}, errors.New("invalid keeper session descriptor")
	}
	for key, want := range map[string]string{"protocol": "string", "mode": "string", "complete": "bool", "tools": "array"} {
		value, exists := fields[key]
		if !exists {
			return Descriptor{}, errors.New("invalid keeper session descriptor")
		}
		typeOK := false
		switch want {
		case "string":
			_, typeOK = value.(string)
		case "bool":
			_, typeOK = value.(bool)
		case "array":
			_, typeOK = value.([]any)
		}
		if !typeOK {
			return Descriptor{}, errors.New("invalid keeper session descriptor")
		}
	}
	for _, value := range fields["tools"].([]any) {
		if _, ok := value.(string); !ok {
			return Descriptor{}, errors.New("invalid keeper session descriptor")
		}
	}
	if err := wire.DecodeStrict(data, &descriptor, "protocol", "mode", "complete", "tools"); err != nil {
		return Descriptor{}, err
	}
	if err := ValidateDescriptor(descriptor); err != nil {
		return Descriptor{}, err
	}
	return descriptor, nil
}

func DeclarativeDenyAll(_ context.Context, _ wire.Request) wire.Reply {
	return wire.Reply{Error: "operation unavailable in this session mode"}
}

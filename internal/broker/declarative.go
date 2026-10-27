package broker

import (
	"context"
	"encoding/base64"
	"errors"
	"regexp"

	"github.com/PHPCraftdream/ssjack/internal/enrollment"
	"github.com/PHPCraftdream/ssjack/internal/wire"
	"github.com/ktav-lang/golang/pure"
)

type Mode string

const (
	ModeFull           Mode = "full"
	ModeDeclarative    Mode = "declarative"
	PartialProtocol         = "ssjack-declarative-partial-0"
	EnrollmentProtocol      = "ssjack-enrollment-partial-1"
	FullProtocol            = "ssjack-full-1"
	DiscoveryRequest        = "ssjack-session-discovery"
)

type Descriptor struct {
	Protocol       string   `json:"protocol"`
	Mode           Mode     `json:"mode"`
	Complete       bool     `json:"complete"`
	Tools          []string `json:"tools"`
	EnrollmentID   string   `json:"enrollment_id,omitempty"`
	DriverID       string   `json:"driver_id,omitempty"`
	DriverProtocol int      `json:"driver_protocol,omitempty"`
	PolicyRevision string   `json:"policy_revision,omitempty"`
	PolicyDigest   string   `json:"policy_digest,omitempty"`
}
type DescribeRequest struct {
	Discovery string `json:"discovery"`
}

var enrollmentIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
var driverIDPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)

func validEnrollmentFields(id, driver string, protocol int) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(id)
	return err == nil && len(decoded) == 16 && base64.RawURLEncoding.EncodeToString(decoded) == id && enrollmentIDPattern.MatchString(id) && driverIDPattern.MatchString(driver) && protocol == 1
}

var policyRevisionPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var policyDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func ValidateDescriptor(d Descriptor) error {
	fullTools := []string{"remote_targets", "remote_exec", "remote_read", "remote_cancel", "app_list", "app_exec", "app_read", "app_cancel"}
	policyFieldsEmpty := d.PolicyRevision == "" && d.PolicyDigest == ""
	if d.Mode == ModeDeclarative && d.Protocol == PolicyProtocol && !d.Complete && len(d.Tools) == 0 && validEnrollmentFields(d.EnrollmentID, d.DriverID, d.DriverProtocol) && policyRevisionPattern.MatchString(d.PolicyRevision) && policyDigestPattern.MatchString(d.PolicyDigest) {
		return nil
	}
	if d.Mode == ModeFull && d.Protocol == FullProtocol && d.Complete && equalTools(d.Tools, fullTools) && d.EnrollmentID == "" && d.DriverID == "" && d.DriverProtocol == 0 && policyFieldsEmpty {
		return nil
	}
	if d.Mode == ModeDeclarative && d.Protocol == PartialProtocol && !d.Complete && len(d.Tools) == 0 && d.EnrollmentID == "" && d.DriverID == "" && d.DriverProtocol == 0 && policyFieldsEmpty {
		return nil
	}
	if d.Mode == ModeDeclarative && d.Protocol == EnrollmentProtocol && !d.Complete && len(d.Tools) == 0 && validEnrollmentFields(d.EnrollmentID, d.DriverID, d.DriverProtocol) && policyFieldsEmpty {
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

func DispatchPolicy(metadata *enrollment.Metadata, policy enrollment.Policy) (Handler, error) {
	if metadata == nil || policy.EnrollmentID() != metadata.EnrollmentID() || policy.DriverID() != metadata.DriverID() || policy.DriverProtocol() != metadata.DriverProtocol() {
		return nil, errors.New("policy snapshot identity mismatch")
	}
	base, err := DispatchEnrollment(metadata)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, request wire.Request) wire.Reply {
		if request.Operation != "session.describe" {
			return DeclarativeDenyAll(ctx, request)
		}
		reply := base(ctx, request)
		if !reply.OK {
			return reply
		}
		var descriptor Descriptor
		if err := wire.DecodeStrict(reply.Data, &descriptor, "protocol", "mode", "complete", "tools", "enrollment_id", "driver_id", "driver_protocol"); err != nil {
			return wire.Reply{Error: "invalid keeper session descriptor"}
		}
		descriptor.Protocol = PolicyProtocol
		descriptor.PolicyRevision = policy.Revision()
		descriptor.PolicyDigest = policy.Digest()
		return Result(descriptor, nil)
	}, nil
}

const PolicyProtocol = "ssjack-policy-deny-only-1"

func DispatchEnrollment(metadata *enrollment.Metadata) (Handler, error) {
	if metadata == nil || !validEnrollmentFields(metadata.EnrollmentID(), metadata.DriverID(), metadata.DriverProtocol()) {
		return nil, errors.New("invalid enrollment metadata")
	}
	id, driver, protocol := metadata.EnrollmentID(), metadata.DriverID(), metadata.DriverProtocol()
	return func(_ context.Context, request wire.Request) wire.Reply {
		if request.Operation != "session.describe" {
			return wire.Reply{Error: "operation unavailable in this session mode"}
		}
		var input DescribeRequest
		if wire.DecodeStrict(request.Data, &input, "discovery") != nil || input.Discovery != DiscoveryRequest {
			return wire.Reply{Error: "unsupported descriptor request"}
		}
		return Result(Descriptor{Protocol: EnrollmentProtocol, Mode: ModeDeclarative, Complete: false, Tools: []string{}, EnrollmentID: id, DriverID: driver, DriverProtocol: protocol}, nil)
	}, nil
}

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
	data, err := client.CallRaw(ctx, "session.describe", DescribeRequest{Discovery: DiscoveryRequest})
	if err != nil {
		return Descriptor{}, err
	}
	parsed, err := pure.Loads(data)
	if err != nil {
		return Descriptor{}, err
	}
	fields, ok := parsed.(map[string]any)
	if !ok {
		return Descriptor{}, errors.New("invalid keeper session descriptor")
	}
	base := []string{"protocol", "mode", "complete", "tools"}
	keys := append([]string{}, base...)
	protocol, ok := fields["protocol"].(string)
	if !ok {
		return Descriptor{}, errors.New("invalid keeper session descriptor")
	}
	if protocol == EnrollmentProtocol || protocol == PolicyProtocol {
		keys = append(keys, "enrollment_id", "driver_id", "driver_protocol")
		if protocol == PolicyProtocol {
			keys = append(keys, "policy_revision", "policy_digest")
		}
	}
	if len(fields) != len(keys) {
		return Descriptor{}, errors.New("invalid keeper session descriptor")
	}
	for _, key := range keys {
		if _, ok := fields[key]; !ok {
			return Descriptor{}, errors.New("invalid keeper session descriptor")
		}
	}
	for key, want := range map[string]string{"protocol": "string", "mode": "string", "complete": "bool", "tools": "array"} {
		v := fields[key]
		good := false
		switch want {
		case "string":
			_, good = v.(string)
		case "bool":
			_, good = v.(bool)
		case "array":
			_, good = v.([]any)
		}
		if !good {
			return Descriptor{}, errors.New("invalid keeper session descriptor")
		}
	}
	if protocol == PolicyProtocol {
		if _, ok := fields["policy_revision"].(string); !ok {
			return Descriptor{}, errors.New("invalid keeper session descriptor")
		}
		if _, ok := fields["policy_digest"].(string); !ok {
			return Descriptor{}, errors.New("invalid keeper session descriptor")
		}
	}
	if protocol == EnrollmentProtocol || protocol == PolicyProtocol {
		if _, ok := fields["enrollment_id"].(string); !ok {
			return Descriptor{}, errors.New("invalid keeper session descriptor")
		}
		if _, ok := fields["driver_id"].(string); !ok {
			return Descriptor{}, errors.New("invalid keeper session descriptor")
		}
		if _, ok := fields["driver_protocol"].(int64); !ok {
			return Descriptor{}, errors.New("invalid keeper session descriptor")
		}
	}
	for _, v := range fields["tools"].([]any) {
		if _, ok := v.(string); !ok {
			return Descriptor{}, errors.New("invalid keeper session descriptor")
		}
	}
	var d Descriptor
	if err := wire.DecodeStrict(data, &d, keys...); err != nil {
		return Descriptor{}, err
	}
	if err := ValidateDescriptor(d); err != nil {
		return Descriptor{}, err
	}
	return d, nil
}

func DeclarativeDenyAll(_ context.Context, _ wire.Request) wire.Reply {
	return wire.Reply{Error: "operation unavailable in this session mode"}
}

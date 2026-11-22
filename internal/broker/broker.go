package broker

import (
	"context"
	"time"

	brokercore "github.com/PHPCraftdream/ssjack/internal/broker/internal/brokercore"
	"github.com/PHPCraftdream/ssjack/internal/declarativeslice"
	"github.com/PHPCraftdream/ssjack/internal/enrollment"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

type (
	Handler         = brokercore.Handler
	Trace           = brokercore.Trace
	Server          = brokercore.Server
	Client          = brokercore.Client
	Bootstrap       = brokercore.Bootstrap
	Mode            = brokercore.Mode
	Descriptor      = brokercore.Descriptor
	DescribeRequest = brokercore.DescribeRequest
)

const (
	EnvToken    = brokercore.EnvToken
	EnvSession  = brokercore.EnvSession
	EnvEndpoint = brokercore.EnvEndpoint
	EnvPin      = brokercore.EnvPin
	EnvFile     = brokercore.EnvFile

	ModeFull        = brokercore.ModeFull
	ModeDeclarative = brokercore.ModeDeclarative

	PartialProtocol    = brokercore.PartialProtocol
	EnrollmentProtocol = brokercore.EnrollmentProtocol
	FullProtocol       = brokercore.FullProtocol
	PolicyProtocol     = brokercore.PolicyProtocol
	SnapshotProtocol   = brokercore.SnapshotProtocol
	SyntheticProtocol  = brokercore.SyntheticProtocol
	DeliveryProtocol   = brokercore.DeliveryProtocol
	DiscoveryRequest   = brokercore.DiscoveryRequest
)

var (
	ErrDial          = brokercore.ErrDial
	ErrAuth          = brokercore.ErrAuth
	ErrRejected      = brokercore.ErrRejected
	ErrSessionClosed = brokercore.ErrSessionClosed
)

func ConnectBootstrap(ctx context.Context, bootstrap Bootstrap) (*Client, error) {
	return brokercore.ConnectBootstrap(ctx, bootstrap)
}

func Listen(parent context.Context, session, token string, ttl time.Duration, handler Handler) (*Server, error) {
	return brokercore.Listen(parent, session, token, ttl, handler)
}

// ListenTraced is Listen with lifecycle events reported to trace.
func ListenTraced(parent context.Context, session, token string, ttl time.Duration, handler Handler, trace Trace) (*Server, error) {
	return brokercore.ListenTraced(parent, session, token, ttl, handler, trace)
}

func Connect(ctx context.Context, endpoint, pin string, auth wire.Auth) (*Client, error) {
	return brokercore.Connect(ctx, endpoint, pin, auth)
}

func Result(value any, err error) wire.Reply { return brokercore.Result(value, err) }

func ValidateDescriptor(d Descriptor) error { return brokercore.ValidateDescriptor(d) }

func DispatchIdentity(metadata *enrollment.Metadata, policy enrollment.Policy, snapshot enrollment.Snapshot) (Handler, error) {
	return brokercore.DispatchIdentity(metadata, policy, snapshot)
}

func DispatchPolicy(metadata *enrollment.Metadata, policy enrollment.Policy) (Handler, error) {
	return brokercore.DispatchPolicy(metadata, policy)
}

func DispatchEnrollment(metadata *enrollment.Metadata) (Handler, error) {
	return brokercore.DispatchEnrollment(metadata)
}

func Dispatch(mode Mode, full Handler) Handler { return brokercore.Dispatch(mode, full) }

func Describe(ctx context.Context, client *Client) (Descriptor, error) {
	return brokercore.Describe(ctx, client)
}

func DeclarativeDenyAll(ctx context.Context, request wire.Request) wire.Reply {
	return brokercore.DeclarativeDenyAll(ctx, request)
}

func DispatchSynthetic(session *declarativeslice.Session) (Handler, error) {
	return brokercore.DispatchSynthetic(session)
}

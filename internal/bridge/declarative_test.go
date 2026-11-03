package bridge

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/enrollment"
	"github.com/PHPCraftdream/ssjack/internal/wire"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func listSelected(ctx context.Context, server *mcp.Server) ([]*mcp.Tool, error) {
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		return nil, err
	}
	defer serverSession.Close()
	peer, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "dev"}, nil).Connect(ctx, clientTransport, nil)
	if err != nil {
		return nil, err
	}
	defer peer.Close()
	tools, err := peer.ListTools(ctx, nil)
	if err != nil {
		return nil, err
	}
	return tools.Tools, nil
}

func TestEnrollmentDescriptorSelectsEmptyRegistry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	id := "AAAAAAAAAAAAAAAAAAAAAA"
	metadata, err := enrollment.Parse([]byte(`{"format":"ssjack-enrollment-metadata-v1","enrollment_id":"` + id + `","driver_id":"driver.test","driver_protocol":1}`))
	if err != nil {
		t.Fatal(err)
	}
	h, err := broker.DispatchEnrollment(&metadata)
	if err != nil {
		t.Fatal(err)
	}
	auth := wire.Auth{Version: 2, Session: strings.Repeat("3", 64), Token: strings.Repeat("4", 64)}
	keeper, err := broker.Listen(ctx, auth.Session, auth.Token, time.Minute, h)
	if err != nil {
		t.Fatal(err)
	}
	defer keeper.Close()
	client, err := broker.Connect(ctx, keeper.Endpoint(), keeper.Pin(), auth)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	d, err := broker.Describe(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistryForDescriptor(client, d)
	if err != nil {
		t.Fatal(err)
	}
	tools, err := listSelected(ctx, registry)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 0 || d.Protocol != broker.EnrollmentProtocol {
		t.Fatalf("descriptor=%+v tools=%d", d, len(tools))
	}
}

func TestAuthenticatedDiscoverySelectsRegistry(t *testing.T) {
	for _, mode := range []broker.Mode{broker.ModeFull, broker.ModeDeclarative} {
		t.Run(string(mode), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			auth := wire.Auth{Version: 2, Session: strings.Repeat("e", 64), Token: strings.Repeat("f", 64)}
			handler := broker.Dispatch(mode, func(context.Context, wire.Request) wire.Reply { return wire.Reply{Error: "legacy fallback"} })
			keeper, err := broker.Listen(ctx, auth.Session, auth.Token, time.Minute, handler)
			if err != nil {
				t.Fatal(err)
			}
			defer keeper.Close()
			client, err := broker.Connect(ctx, keeper.Endpoint(), keeper.Pin(), auth)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			descriptor, err := broker.Describe(ctx, client)
			if err != nil {
				t.Fatal(err)
			}
			registry, err := NewRegistryForDescriptor(client, descriptor)
			if err != nil {
				t.Fatal(err)
			}
			tools, err := listSelected(ctx, registry)
			if err != nil {
				t.Fatal(err)
			}
			want := 8
			if mode == broker.ModeDeclarative {
				want = 0
			}
			if len(tools) != want {
				t.Fatalf("mode %s exposed %d tools, want %d", mode, len(tools), want)
			}
			if mode == broker.ModeDeclarative {
				for _, operation := range []string{"targets", "app_start", "plan_apply", "secret.read", "session.describe.with-mode-switch"} {
					var out map[string]any
					if err := client.Call(ctx, operation, map[string]any{}, &out); err == nil {
						t.Fatalf("operation %q was not denied", operation)
					}
				}
			}
		})
	}
}

func TestFullModeSwitchAttemptKeepsDeclarativeRegistry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	auth := wire.Auth{Version: 2, Session: strings.Repeat("7", 64), Token: strings.Repeat("6", 64)}
	var callbackCalls int
	handler := broker.Dispatch(broker.ModeDeclarative, func(context.Context, wire.Request) wire.Reply { callbackCalls++; return wire.Reply{OK: true} })
	keeper, err := broker.Listen(ctx, auth.Session, auth.Token, time.Minute, handler)
	if err != nil {
		t.Fatal(err)
	}
	defer keeper.Close()
	client, err := broker.Connect(ctx, keeper.Endpoint(), keeper.Pin(), auth)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	before, err := broker.Describe(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if before.Mode != broker.ModeDeclarative || before.Complete || len(before.Tools) != 0 {
		t.Fatalf("initial descriptor is not partial: %+v", before)
	}
	var output map[string]any
	if err := client.Call(ctx, "session.describe", map[string]any{"discovery": broker.DiscoveryRequest, "mode": "full"}, &output); err == nil {
		t.Fatal("accepted full-mode switch attempt")
	}
	if err := client.Call(ctx, "start", map[string]any{"target": "example", "command": "true"}, &output); err == nil {
		t.Fatal("declarative session accepted forged start")
	}
	after, err := broker.Describe(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if after.Protocol != before.Protocol || after.Mode != broker.ModeDeclarative || after.Complete || len(after.Tools) != 0 {
		t.Fatalf("descriptor changed or became full: before=%+v after=%+v", before, after)
	}
	registry, err := NewRegistryForDescriptor(client, after)
	if err != nil {
		t.Fatal(err)
	}
	tools, err := listSelected(ctx, registry)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 0 {
		t.Fatalf("declarative registry exposed %d tools after rejected mode switch", len(tools))
	}
	if callbackCalls != 0 {
		t.Fatalf("registry enumeration invoked sentinel callback %d times", callbackCalls)
	}
}

func TestRegistrySelectionRejectsMissingOrMalformedDescriptor(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reply wire.Reply
	}{
		{name: "missing", reply: wire.Reply{Error: "unknown operation"}},
		{name: "malformed", reply: broker.Result(map[string]any{"protocol": broker.PartialProtocol, "mode": broker.ModeDeclarative, "complete": false, "tools": []string{"plan_apply"}, "extra": true}, nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			auth := wire.Auth{Version: 2, Session: strings.Repeat("9", 64), Token: strings.Repeat("8", 64)}
			keeper, err := broker.Listen(ctx, auth.Session, auth.Token, time.Minute, func(_ context.Context, req wire.Request) wire.Reply {
				if req.Operation == "session.describe" {
					return tc.reply
				}
				return wire.Reply{Error: "denied"}
			})
			if err != nil {
				t.Fatal(err)
			}
			defer keeper.Close()
			client, err := broker.Connect(ctx, keeper.Endpoint(), keeper.Pin(), auth)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if _, err := broker.Describe(ctx, client); err == nil {
				t.Fatal("accepted invalid broker descriptor")
			}
		})
	}
}

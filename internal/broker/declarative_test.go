package broker

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/wire"
)

func TestDeclarativeAuthenticatedBoundaryDeniesForgedCalls(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	auth := wire.Auth{Version: 2, Session: strings.Repeat("a", 64), Token: strings.Repeat("b", 64)}
	called := false
	handler := Dispatch(ModeDeclarative, func(context.Context, wire.Request) wire.Reply {
		called = true
		return wire.Reply{OK: true}
	})
	keeper, err := Listen(ctx, auth.Session, auth.Token, time.Minute, handler)
	if err != nil {
		t.Fatal(err)
	}
	defer keeper.Close()
	client, err := Connect(ctx, keeper.Endpoint(), keeper.Pin(), auth)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var d Descriptor
	if err := client.Call(ctx, "session.describe", map[string]any{"discovery": DiscoveryRequest, "extra": true}, &d); err == nil {
		t.Fatal("accepted unknown discovery field")
	}
	if err := client.Call(ctx, "session.describe", map[string]any{"discovery": DiscoveryRequest, "mode": "declarative"}, &d); err == nil {
		t.Fatal("accepted descriptor request containing mode selector")
	}
	d, err = Describe(ctx, client)
	if err != nil || d.Mode != ModeDeclarative || d.Complete || len(d.Tools) != 0 {
		t.Fatalf("descriptor: %+v %v", d, err)
	}
	for _, operation := range []string{"targets", "start", "app_start", "plan_apply", "admin.secret"} {
		var result map[string]any
		if err := client.Call(ctx, operation, map[string]any{"confirm": true}, &result); err == nil {
			t.Fatalf("forged operation %q accepted", operation)
		}
	}
	if called {
		t.Fatal("declarative route invoked full handler")
	}
}

func TestDescriptorRawTypeValidationAuthenticated(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	auth := wire.Auth{Version: 2, Session: strings.Repeat("e", 64), Token: strings.Repeat("f", 64)}
	validMap := map[string]any{"protocol": PartialProtocol, "mode": ModeDeclarative, "complete": false, "tools": []string{}}
	valid, err := wire.Encode(validMap)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{}
	for field, badValues := range map[string][]any{"protocol": {nil, 17}, "mode": {nil, 17}, "complete": {nil, "false"}, "tools": {nil, "none"}} {
		for _, bad := range badValues {
			candidate := map[string]any{}
			for k, v := range validMap {
				candidate[k] = v
			}
			candidate[field] = bad
			raw, err := wire.Encode(candidate)
			if err != nil {
				t.Fatal(err)
			}
			label := field + " null"
			if bad != nil {
				label = field + " wrong type " + fmt.Sprint(bad)
			}
			cases[label] = raw
		}
	}
	for name, mutate := range map[string]func(map[string]any){
		"missing protocol": func(m map[string]any) { delete(m, "protocol") },
		"missing mode":     func(m map[string]any) { delete(m, "mode") },
		"missing complete": func(m map[string]any) { delete(m, "complete") },
		"missing tools":    func(m map[string]any) { delete(m, "tools") },
		"extra field":      func(m map[string]any) { m["extra"] = true },
	} {
		candidate := map[string]any{}
		for k, v := range validMap {
			candidate[k] = v
		}
		mutate(candidate)
		raw, err := wire.Encode(candidate)
		if err != nil {
			t.Fatal(err)
		}
		cases[name] = raw
	}
	badArray, err := wire.Encode(map[string]any{"protocol": PartialProtocol, "mode": ModeDeclarative, "complete": false, "tools": []any{nil}})
	if err != nil {
		t.Fatal(err)
	}
	cases["invalid array element"] = badArray
	cases["duplicate mode"] = valid + "\nmode: declarative\n"
	baselineKeeper, err := Listen(ctx, auth.Session, auth.Token, time.Minute, func(_ context.Context, _ wire.Request) wire.Reply { return wire.Reply{OK: true, Data: valid} })
	if err != nil {
		t.Fatal(err)
	}
	baselineClient, err := Connect(ctx, baselineKeeper.Endpoint(), baselineKeeper.Pin(), auth)
	if err != nil {
		baselineKeeper.Close()
		t.Fatal(err)
	}
	if _, err := Describe(ctx, baselineClient); err != nil {
		baselineClient.Close()
		baselineKeeper.Close()
		t.Fatalf("valid baseline descriptor rejected: %v", err)
	}
	baselineClient.Close()
	baselineKeeper.Close()
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			keeper, err := Listen(ctx, auth.Session, auth.Token, time.Minute, func(_ context.Context, _ wire.Request) wire.Reply { return wire.Reply{OK: true, Data: raw} })
			if err != nil {
				t.Fatal(err)
			}
			defer keeper.Close()
			client, err := Connect(ctx, keeper.Endpoint(), keeper.Pin(), auth)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if _, err := Describe(ctx, client); err == nil {
				t.Fatal("accepted malformed descriptor")
			}
		})
	}
}

func TestFullCompatibilityAndInvalidDescriptor(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	auth := wire.Auth{Version: 2, Session: strings.Repeat("c", 64), Token: strings.Repeat("d", 64)}
	called := false
	handler := Dispatch(ModeFull, func(context.Context, wire.Request) wire.Reply {
		called = true
		return Result(map[string]string{"ok": "yes"}, nil)
	})
	keeper, err := Listen(ctx, auth.Session, auth.Token, time.Minute, handler)
	if err != nil {
		t.Fatal(err)
	}
	defer keeper.Close()
	client, err := Connect(ctx, keeper.Endpoint(), keeper.Pin(), auth)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	d, err := Describe(ctx, client)
	if err != nil || d.Mode != ModeFull || !d.Complete || len(d.Tools) != 8 {
		t.Fatalf("full descriptor: %+v %v", d, err)
	}
	var response map[string]string
	if err := client.Call(ctx, "legacy-op", struct{}{}, &response); err != nil || response["ok"] != "yes" || !called {
		t.Fatal("full compatibility path failed")
	}
	called = false
	if err := client.Call(ctx, "session.describe", map[string]any{"discovery": DiscoveryRequest, "mode": "declarative"}, &response); err == nil {
		t.Fatal("accepted mode switch attempt")
	}
	d, err = Describe(ctx, client)
	if err != nil || d.Mode != ModeFull || !d.Complete || len(d.Tools) != 8 {
		t.Fatalf("mode changed after rejected attempt: %+v %v", d, err)
	}
	if called {
		t.Fatal("mode-switch attempt invoked full callback")
	}
}

func TestDescriptorRejectsUnexpectedToolsAndProtocol(t *testing.T) {
	if ValidateDescriptor(Descriptor{Protocol: PartialProtocol, Mode: ModeDeclarative, Complete: false, Tools: []string{"plan_apply"}}) == nil {
		t.Fatal("accepted unexpected declarative tools")
	}
	if ValidateDescriptor(Descriptor{Protocol: "1", Mode: ModeDeclarative, Complete: false}) == nil {
		t.Fatal("accepted ambiguous protocol")
	}
}

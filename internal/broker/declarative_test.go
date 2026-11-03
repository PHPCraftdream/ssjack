package broker

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/enrollment"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

func TestEnrollmentDescriptorAuthenticatedSnapshotAndDeny(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	id := "AAAAAAAAAAAAAAAAAAAAAA"
	m, err := enrollment.Parse([]byte(`{"format":"ssjack-enrollment-metadata-v1","enrollment_id":"` + id + `","driver_id":"driver-a","driver_protocol":1}`))
	if err != nil {
		t.Fatal(err)
	}
	h, err := DispatchEnrollment(&m)
	if err != nil {
		t.Fatal(err)
	}
	mutated, err := enrollment.Parse([]byte(`{"format":"ssjack-enrollment-metadata-v1","enrollment_id":"` + id + `","driver_id":"driver-b","driver_protocol":1}`))
	if err != nil {
		t.Fatal(err)
	}
	m = mutated
	auth := wire.Auth{Version: 2, Session: strings.Repeat("1", 64), Token: strings.Repeat("2", 64)}
	keeper, err := Listen(ctx, auth.Session, auth.Token, time.Minute, h)
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
	if err != nil {
		t.Fatal(err)
	}
	if d.Protocol != EnrollmentProtocol || d.DriverID != "driver-a" || d.EnrollmentID != id || d.DriverProtocol != 1 || len(d.Tools) != 0 {
		t.Fatalf("descriptor: %+v", d)
	}
	for _, op := range []string{"targets", "start", "app_start", "driver.execute"} {
		var out map[string]any
		if err := client.Call(ctx, op, map[string]any{}, &out); err == nil {
			t.Fatalf("accepted %s", op)
		}
	}
}

func TestEnrollmentSourceFileMutationDoesNotChangeSnapshot(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "freebsd" && runtime.GOOS != "openbsd" && runtime.GOOS != "netbsd" && runtime.GOOS != "dragonfly" && runtime.GOOS != "solaris" {
		t.Skip("secure enrollment file loading is unsupported on this platform")
	}
	id := base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	original := []byte(`{"format":"ssjack-enrollment-metadata-v1","enrollment_id":"` + id + `","driver_id":"before","driver_protocol":1}`)
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "metadata.json")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	metadata, err := enrollment.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := DispatchEnrollment(&metadata)
	if err != nil {
		t.Fatal(err)
	}
	changed := []byte(`{"format":"ssjack-enrollment-metadata-v1","enrollment_id":"` + id + `","driver_id":"after","driver_protocol":1}`)
	if err := os.WriteFile(path, changed, 0600); err != nil {
		t.Fatalf("unexpected source metadata mutation failure: %v", err)
	}
	request, _ := wire.Encode(DescribeRequest{Discovery: DiscoveryRequest})
	reply := h(context.Background(), wire.Request{Operation: "session.describe", Data: request})
	var got Descriptor
	if err := wire.DecodeStrict(reply.Data, &got, "protocol", "mode", "complete", "tools", "enrollment_id", "driver_id", "driver_protocol"); err != nil {
		t.Fatal(err)
	}
	if got.DriverID != "before" {
		t.Fatalf("source mutation changed snapshot: %+v", got)
	}
}

func TestEnrollmentDescriptorRejectsMalformedFields(t *testing.T) {
	valid := Descriptor{Protocol: EnrollmentProtocol, Mode: ModeDeclarative, Complete: false, Tools: []string{}, EnrollmentID: "AAAAAAAAAAAAAAAAAAAAAA", DriverID: "driver-a", DriverProtocol: 1}
	if err := ValidateDescriptor(valid); err != nil {
		t.Fatalf("valid enrollment descriptor rejected: %v", err)
	}
	cases := map[string]func(*Descriptor){
		"enrollment id":   func(d *Descriptor) { d.EnrollmentID = "invalid" },
		"driver id":       func(d *Descriptor) { d.DriverID = "Invalid" },
		"driver protocol": func(d *Descriptor) { d.DriverProtocol = 2 },
		"mode":            func(d *Descriptor) { d.Mode = ModeFull },
		"complete":        func(d *Descriptor) { d.Complete = true },
		"tools":           func(d *Descriptor) { d.Tools = []string{"remote_exec"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			d := valid
			mutate(&d)
			if ValidateDescriptor(d) == nil {
				t.Fatalf("accepted malformed descriptor: %+v", d)
			}
		})
	}
}

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
	enrollmentMap := map[string]any{"protocol": EnrollmentProtocol, "mode": ModeDeclarative, "complete": false, "tools": []string{}, "enrollment_id": "AAAAAAAAAAAAAAAAAAAAAA", "driver_id": "driver-a", "driver_protocol": 1}
	enrollmentRaw, err := wire.Encode(enrollmentMap)
	if err != nil {
		t.Fatal(err)
	}
	for field, badValues := range map[string][]any{"enrollment_id": {nil, 17}, "driver_id": {nil, 17}, "driver_protocol": {nil, "1"}} {
		for _, bad := range badValues {
			candidate := map[string]any{}
			for k, v := range enrollmentMap {
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
	cases["duplicate enrollment id"] = enrollmentRaw + "\nenrollment_id: AAAAAAAAAAAAAAAAAAAAAA\n"
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

func TestDescriptorRejectsUnexpectedToolsAndProtocol(t *testing.T) {
	if ValidateDescriptor(Descriptor{Protocol: PartialProtocol, Mode: ModeDeclarative, Complete: false, Tools: []string{"plan_apply"}}) == nil {
		t.Fatal("accepted unexpected declarative tools")
	}
	if ValidateDescriptor(Descriptor{Protocol: "1", Mode: ModeDeclarative, Complete: false}) == nil {
		t.Fatal("accepted ambiguous protocol")
	}
}

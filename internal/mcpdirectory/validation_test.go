package mcpdirectory

import (
	"reflect"
	"testing"

	"github.com/ktav-lang/golang/pure"
)

func TestPrivateDirectoryCanonicalRoundTripAndUnknownFieldRefusal(t *testing.T) {
	d, _, account := fixture(t)
	binding, err := d.CurrentBinding(account)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Remember("deploy", []Binding{binding}); err != nil {
		t.Fatal(err)
	}
	encoded, err := pure.EmitCanonical(d.Record())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := pure.LoadsStrict(encoded)
	if err != nil || ValidateFields(raw) != nil {
		t.Fatal("canonical MCP fields were rejected")
	}
	var decoded Directory
	if err := pure.LoadsInto(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	defer decoded.Clear()
	if decoded.Validate() != nil || !reflect.DeepEqual(d, &decoded) {
		t.Fatal("private MCP records did not round trip")
	}
	for _, mutate := range []func(map[string]any){
		func(root map[string]any) { root["unknown"] = true },
		func(root map[string]any) {
			for _, s := range root["servers"].(map[string]any) {
				s.(map[string]any)["unknown"] = true
			}
		},
		func(root map[string]any) {
			for _, a := range root["accounts"].(map[string]any) {
				a.(map[string]any)["auth"].(map[string]any)["unknown"] = true
			}
		},
		func(root map[string]any) {
			for _, a := range root["accounts"].(map[string]any) {
				a.(map[string]any)["headers"].([]any)[0].(map[string]any)["unknown"] = true
			}
		},
		func(root map[string]any) {
			root["last"].(map[string]any)["deploy"].([]any)[0].(map[string]any)["unknown"] = true
		},
	} {
		candidate := d.Record()
		mutate(candidate)
		if ValidateFields(candidate) == nil {
			t.Fatal("unknown private MCP field was silently accepted")
		}
	}
}
func TestEndpointAndAuthenticationBoundaries(t *testing.T) {
	d, server, _ := fixture(t)
	for _, endpoint := range []string{"http://docs.invalid/mcp", "https://user:password@docs.invalid/mcp", "https://docs.invalid/mcp?token=synthetic", "https://docs.invalid/mcp#token", "https://docs.invalid:0/mcp", "https://docs.invalid/%0a", "https://docs.invalid/\r\n"} {
		before := d.Servers[server]
		if d.EditServer(server, "docs", endpoint, true) == nil || d.Servers[server] != before {
			t.Fatal("unsafe endpoint was accepted or failed edit changed state")
		}
	}
	for _, auth := range []Authentication{
		{Kind: "bearer", Secret: []byte("synthetic\r\ninjected")},
		{Kind: "bearer", Secret: []byte("token with spaces")},
		{Kind: "bearer", Username: "unexpected", Secret: []byte("synthetic")},
		{Kind: "basic", Username: "user:other", Secret: []byte("synthetic")},
		{Kind: "none", Secret: []byte("unexpected")},
		{Kind: "oauth", Secret: []byte("not-implemented")},
	} {
		before := len(d.Accounts)
		if _, err := d.AddAccount(Account{ServerID: server, Name: "unsafe", Enabled: true, Auth: auth}); err == nil || len(d.Accounts) != before {
			t.Fatal("invalid authentication was published")
		}
	}
	for _, name := range []string{"Authorization", "Proxy-Authorization", "Host", "Content-Length", "Cookie", "Mcp-Session-Id", "X-Forwarded-Host", "Origin", "X-Api-Key\r\nInjected", "x-api-key"} {
		if _, err := d.AddAccount(Account{ServerID: server, Name: "unsafe", Enabled: true, Auth: Authentication{Kind: "none"}, Headers: []Header{{Name: name, Value: []byte("synthetic")}}}); err == nil {
			t.Fatal("reserved or noncanonical header accepted")
		}
	}
}

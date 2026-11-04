package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/ktav-lang/golang/pure"

	"github.com/PHPCraftdream/ssjack/internal/ownerarchive"
	"github.com/PHPCraftdream/ssjack/internal/sshproxy"
)

func proxyFixture(t *testing.T) (*Vault, string, string) {
	t.Helper()
	v, server := directoryFixture(t)
	first := v.Servers[server].Accounts["main"]
	target := ownTarget(v.Targets[first])
	target.PrivateKey, target.Password, target.User = nil, []byte("synthetic SSH password"), "second"
	defer clear(target.Password)
	if err := v.SetAccount(server, "second", target); err != nil {
		t.Fatal(err)
	}
	return v, server, first
}

func TestServerProxyIsSharedOwnedAndInherited(t *testing.T) {
	v, server, first := proxyFixture(t)
	route := &sshproxy.Config{Type: sshproxy.SOCKS5, Address: "proxy.invalid:1080", Username: "operator", Password: []byte("synthetic proxy password")}
	if err := v.SetServerProxy(server, route); err != nil {
		t.Fatal(err)
	}
	route.Clear()
	for _, profile := range v.Servers[server].Accounts {
		if got := v.Targets[profile].Proxy; got == nil || string(got.Password) != "synthetic proxy password" {
			t.Fatal("server proxy borrowed caller credentials")
		}
	}
	target := ownTarget(v.Targets[first])
	defer target.Proxy.Clear()
	target.User, target.Proxy = "third", nil
	if err := v.SetAccount(server, "third", target); err != nil {
		t.Fatal(err)
	}
	third, _ := v.AccountProfile(server, "third")
	if !sshproxy.Equal(v.Targets[first].Proxy, v.Targets[third].Proxy) || v.Targets[first].Proxy == v.Targets[third].Proxy {
		t.Fatal("new SSH account did not inherit an independently owned server route")
	}
	target = ownTarget(v.Targets[first])
	defer target.Proxy.Clear()
	target.Proxy.Address = "other.invalid:1080"
	if err := v.SetAccount(server, "main", target); err == nil {
		t.Fatal("account edit changed a server-owned proxy")
	}
	original := v.Targets[first].Proxy
	if err := v.SetServerProxy(server, &sshproxy.Config{Type: "unknown", Address: "proxy.invalid:80"}); err == nil || original != v.Targets[first].Proxy {
		t.Fatal("invalid proxy edit partially changed the directory")
	}
	if err := v.SetServerProxy(server, nil); err != nil {
		t.Fatal(err)
	}
	for _, profile := range v.Servers[server].Accounts {
		if v.Targets[profile].Proxy != nil {
			t.Fatal("direct selection left a proxy on another account")
		}
	}
	if len(original.Password) != 0 {
		t.Fatal("replaced proxy retained owned password bytes")
	}
}

func TestProxyCodecRejectsUnknownFieldsAndLegacyPayloads(t *testing.T) {
	v, server, first := proxyFixture(t)
	if err := v.SetServerProxy(server, &sshproxy.Config{Type: sshproxy.HTTP, Address: "proxy.invalid:8080", Username: "operator", Password: []byte("synthetic proxy password")}); err != nil {
		t.Fatal(err)
	}
	encoded, err := marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	decoded, err := unmarshal(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer decoded.Close()
	if !sshproxy.Equal(v.Targets[first].Proxy, decoded.Targets[first].Proxy) {
		t.Fatal("proxy settings did not round trip")
	}
	for _, mode := range []string{"unknown", "missing-password", "null", "legacy", "different-account"} {
		raw, err := pure.LoadsStrict(string(encoded))
		if err != nil {
			t.Fatal(err)
		}
		root := raw.(map[string]any)
		target := root["targets"].(map[string]any)[first].(map[string]any)
		proxy := target["proxy"].(map[string]any)
		switch mode {
		case "unknown":
			proxy["unexpected"] = "field"
		case "missing-password":
			delete(proxy, "password")
		case "null":
			target["proxy"] = nil
		case "legacy":
			root = map[string]any{"version": 1, "targets": map[string]any{first: target}}
		case "different-account":
			proxy["address"] = "different.invalid:80"
		}
		broken, err := pure.EmitCanonical(root)
		if err != nil {
			t.Fatal(err)
		}
		if bad, err := unmarshal([]byte(broken)); err == nil {
			bad.Close()
			t.Fatalf("invalid proxy schema accepted: %s", mode)
		}
	}
}

func TestProxyMetadataExportImportAndCleanup(t *testing.T) {
	v, server, first := proxyFixture(t)
	const password = "synthetic proxy password"
	if err := v.SetServerProxy(server, &sshproxy.Config{Type: sshproxy.HTTP, Address: "proxy.invalid:8080", Username: "operator", Password: []byte(password)}); err != nil {
		t.Fatal(err)
	}
	s := newSession(v, func(context.Context, []byte) error { return nil }, func() {})
	defer s.Discard()
	metadata, err := s.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	public, err := json.Marshal(metadata)
	if err != nil || bytes.Contains(public, []byte(password)) || metadata.Servers[0].Proxy.Type != sshproxy.HTTP || !metadata.Servers[0].Proxy.Authenticated {
		t.Fatal("proxy metadata leaked authentication or lost routing")
	}
	plan, err := s.PrepareOwnerExport(ExportSelection{Servers: map[string][]string{server: {"main", "second"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Close()
	path := filepath.Join(t.TempDir(), "proxy-export.zip")
	if err := plan.WritePlaintext(context.Background(), path, "EXPORT PLAINTEXT"); err != nil {
		t.Fatal(err)
	}
	opened, err := ownerarchive.ReadFile(context.Background(), path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	imported, err := ParseOwnerImport(opened)
	if err != nil {
		t.Fatal(err)
	}
	defer imported.Close()
	preview, err := json.Marshal(imported.Preview())
	if err != nil || bytes.Contains(preview, []byte(password)) {
		t.Fatal("import preview exposed proxy authentication")
	}
	destination := importDestination(t, false, nil)
	if err := destination.ApplyOwnerImportDirectory(imported); err != nil {
		t.Fatal(err)
	}
	inspectSession(destination, func(got *Vault) {
		if !sshproxy.Equal(v.Targets[first].Proxy, got.Targets[first].Proxy) {
			t.Fatal("owner archive lost proxy settings or credentials")
		}
	})
	if err := destination.Apply(func(got *Vault) error {
		return got.SetServerProxy(server, &sshproxy.Config{Type: sshproxy.SOCKS5, Address: "changed.invalid:1080"})
	}); err != nil {
		t.Fatal(err)
	}
	if destination.VerifyOwnerImportDirectory(imported) != ErrImportChanged {
		t.Fatal("import recovery ignored a changed proxy route")
	}
	owned := v.Targets[first].Proxy.Password
	s.Discard()
	if !allZero(owned) {
		t.Fatal("database close retained proxy credentials")
	}
}

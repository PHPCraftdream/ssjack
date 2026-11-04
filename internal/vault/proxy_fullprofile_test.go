package vault

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/sshproxy"
)

func TestVaultProxyFullProfile(t *testing.T) {
	if os.Getenv("SSJACK_TEST_FULL_KDF") != "1" {
		t.Skip("production KDF runs only in dedicated GitHub CI")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	v, server, first := proxyFixture(t)
	route := &sshproxy.Config{Type: sshproxy.SOCKS5, Address: "proxy.invalid:1080", Username: "operator", Password: []byte("synthetic proxy password")}
	defer route.Clear()
	if err := v.SetServerProxy(server, route); err != nil {
		t.Fatal(err)
	}
	password := []byte("synthetic proxy database password")
	defer clear(password)
	path := filepath.Join(t.TempDir(), "proxied.ktav")
	if err := CreateWithRecords(ctx, path, v, password); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(path)
	if err != nil || bytes.Contains(encoded, route.Password) {
		t.Fatal("proxy credentials were not encrypted")
	}
	loaded, err := Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Close()
	if !sshproxy.Equal(route, loaded.Targets[first].Proxy) {
		t.Fatal("encrypted database lost proxy settings")
	}
	baseline := make(map[string]string)
	for _, profile := range loaded.Servers[server].Accounts {
		binding, err := loaded.ProxyCredentialIdentity(profile)
		if err != nil || len(binding) != 64 {
			t.Fatal("authenticated proxy binding unavailable")
		}
		baseline[profile] = binding
	}
	for _, mutate := range []func(*sshproxy.Config){
		func(c *sshproxy.Config) { c.Type = sshproxy.HTTP },
		func(c *sshproxy.Config) { c.Address = "changed.invalid:1080" },
		func(c *sshproxy.Config) { c.Username = "changed" },
		func(c *sshproxy.Config) { clear(c.Password); c.Password = []byte("changed synthetic proxy password") },
	} {
		changed := sshproxy.Clone(route)
		mutate(changed)
		if err := loaded.SetServerProxy(server, changed); err != nil {
			t.Fatal(err)
		}
		changed.Clear()
		for _, profile := range loaded.Servers[server].Accounts {
			binding, err := loaded.ProxyCredentialIdentity(profile)
			if err != nil || binding == baseline[profile] {
				t.Fatal("grant binding ignored a changed server route or proxy authentication")
			}
		}
	}
	if err := loaded.SetServerProxy(server, route); err != nil {
		t.Fatal(err)
	}
	if err := SaveUnlocked(ctx, path, loaded); err != nil {
		t.Fatal(err)
	}
	reopened, err := Load(path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	for _, profile := range reopened.Servers[server].Accounts {
		binding, err := reopened.ProxyCredentialIdentity(profile)
		if err != nil || binding != baseline[profile] {
			t.Fatal("normal encrypted save changed the route grant binding")
		}
		if len(reopened.Targets[profile].Password) != 0 {
			selected, err := reopened.PasswordCredentialIdentity(profile)
			if err != nil || selected != binding {
				t.Fatal("password grant binding omitted its proxy route")
			}
		}
	}
	if err := reopened.SetServerProxy(server, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.ProxyCredentialIdentity(first); err == nil {
		t.Fatal("direct credential was treated as a proxied grant")
	}
}

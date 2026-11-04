package sshproxy

import (
	"bytes"
	"strings"
	"testing"
)

func TestProxyConfigBoundsAndOwnedMetadata(t *testing.T) {
	for _, config := range []Config{
		{}, {Type: SOCKS5, Address: "127.0.0.1:1080"}, {Type: HTTP, Address: "[::1]:8080"},
		{Type: SOCKS5, Address: "proxy.invalid:1080", Username: "u", Password: []byte("p")},
		{Type: HTTP, Address: "proxy.invalid:8080", Username: "u", Password: bytes.Repeat([]byte("p"), 1024)},
	} {
		if err := config.Validate(); err != nil {
			t.Fatal("valid proxy configuration refused")
		}
	}
	for _, config := range []Config{
		{Address: "proxy.invalid:1080"}, {Type: "https", Address: "proxy.invalid:8080"},
		{Type: HTTP, Address: "http://proxy.invalid:8080"}, {Type: HTTP, Address: "u:p@proxy.invalid:8080"},
		{Type: SOCKS5, Address: "proxy.invalid:0"}, {Type: SOCKS5, Address: "proxy.invalid:65536"},
		{Type: SOCKS5, Address: "proxy.invalid:1080", Username: "u"},
		{Type: HTTP, Address: "proxy.invalid:8080", Password: []byte("p")},
		{Type: HTTP, Address: "proxy.invalid:8080", Username: "u:p", Password: []byte("p")},
		{Type: SOCKS5, Address: "proxy.invalid:1080", Username: "u", Password: bytes.Repeat([]byte("p"), 256)},
		{Type: HTTP, Address: "proxy.invalid:8080", Username: "u", Password: bytes.Repeat([]byte("p"), 1025)},
		{Type: HTTP, Address: "proxy.invalid:8080", Username: strings.Repeat("u", 256), Password: []byte("p")},
		{Type: HTTP, Address: "bad host:8080"}, {Type: HTTP, Address: "proxy.invalid:80\r\nInjected: true"},
	} {
		if config.Validate() == nil {
			t.Fatal("invalid proxy configuration accepted")
		}
	}
	source := &Config{Type: SOCKS5, Address: "proxy.invalid:1080", Username: "u", Password: []byte("synthetic proxy password")}
	owned := Clone(source)
	if !Equal(source, owned) || owned == source {
		t.Fatal("route clone changed or borrowed the source")
	}
	public := owned.Metadata()
	source.Clear()
	if string(owned.Password) != "synthetic proxy password" || public.Type != SOCKS5 || !public.Authenticated {
		t.Fatal("source cleanup changed independent route ownership")
	}
	data := owned.Password
	owned.Clear()
	if !bytes.Equal(data, make([]byte, len(data))) || Clone(nil) != nil || !Equal(nil, nil) || (*Config)(nil).Metadata() != (Metadata{}) {
		t.Fatal("proxy cleanup or nil behavior changed")
	}
}

package mcpflow

import (
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

func metadataWireName(value string) string {
	return "=?base64?" + base64.StdEncoding.EncodeToString([]byte(value)) + "?="
}

func metadataRequest(t *testing.T, method string, headers http.Header) *http.Request {
	t.Helper()
	r := request(t, method, "{}")
	if method != http.MethodPost {
		r = request(t, method, "")
	}
	for name, values := range headers {
		r.Header[name] = append([]string(nil), values...)
	}
	return r
}

func TestMetadataRequestHeadersAccepted(t *testing.T) {
	longMethod := strings.Repeat("a", metadataValueMaxBytes)
	longName := strings.Repeat("n", metadataNameMaxBytes)
	longEncodedName := metadataWireName(longName)
	cases := []struct {
		name    string
		headers http.Header
	}{
		{"server initialization", http.Header{"Mcp-Method": {"initialize"}}},
		{"server discovery", http.Header{"Mcp-Method": {"server/discover"}}},
		{"discovery tools list", http.Header{"Mcp-Method": {"tools/list"}}},
		{"discovery tools call", http.Header{"Mcp-Method": {"tools/call"}, "Mcp-Name": {"tool-name_1./-"}}},
		{"mixed-case valid header names", http.Header{"mCp-MeThOd": {"tools/call"}, "mCp-NaMe": {"Mixed_Name"}}},
		{"notification", http.Header{"Mcp-Method": {"notifications/cancelled"}}},
		{"name punctuation uri and spaces", http.Header{"Mcp-Name": {"name_1./- with spaces?"}}},
		{"resource uri with spaces", http.Header{"Mcp-Name": {"file:///resource path"}}},
		{"encoded non ascii", http.Header{"Mcp-Name": {metadataWireName("café/雪")}}},
		{"encoded edge spaces", http.Header{"Mcp-Name": {metadataWireName(" leading and trailing ")}}},
		{"encoded newline", http.Header{"Mcp-Name": {metadataWireName("line\nbreak")}}},
		{"encoded literal sentinel", http.Header{"Mcp-Name": {metadataWireName("=?base64?YQ==?=")}}},
		{"sentinel prefix without suffix is plain", http.Header{"Mcp-Name": {"=?base64? printable"}}},
		{"nonlowercase prefix is plain", http.Header{"Mcp-Name": {"=?BASE64? printable"}}},
		{"method maximum", http.Header{"Mcp-Method": {longMethod}}},
		{"plain name maximum", http.Header{"Mcp-Name": {longName}}},
		{"encoded wire maximum", http.Header{"Mcp-Name": {longEncodedName}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls, cleared atomic.Int32
			transport := flow(t, peer(func(r *http.Request) (*http.Response, error) {
				calls.Add(1)
				for name, values := range tc.headers {
					if got := r.Header[name]; len(got) != len(values) || len(got) != 1 || got[0] != values[0] {
						t.Errorf("metadata header changed before peer: %q", name)
					}
				}
				return reply(`{"ok":true}`), nil
			}), &cleared)
			response, err := transport.RoundTrip(metadataRequest(t, http.MethodPost, tc.headers))
			if err != nil {
				t.Fatalf("valid metadata refused: %v", err)
			}
			if _, err := io.ReadAll(response.Body); err != nil {
				t.Fatalf("response body read: %v", err)
			}
			if err := response.Body.Close(); err != nil || calls.Load() != 1 {
				t.Fatal("accepted request did not complete cleanly")
			}
		})
	}
}

func TestMetadataRequestHeadersRejected(t *testing.T) {
	invalidMethods := []struct {
		name  string
		value string
	}{
		{"empty", ""},
		{"too long", strings.Repeat("a", metadataValueMaxBytes+1)},
		{"colon", "tools:list"},
		{"question", "tools?list"},
		{"plus", "tools+list"},
		{"space", "tools list"},
		{"tab", "tools\tlist"},
		{"unicode", "tools/雪"},
		{"control", "tools\x01list"},
	}
	for i := 0; i <= 0x1f; i++ {
		invalidMethods = append(invalidMethods, struct {
			name  string
			value string
		}{name: "control byte", value: "tools" + string(rune(i)) + "list"})
	}
	invalidMethods = append(invalidMethods, struct {
		name  string
		value string
	}{"DEL", "tools\x7flist"})
	invalidNames := []struct {
		name  string
		value string
	}{
		{"empty", ""},
		{"too long", strings.Repeat("n", metadataNameMaxBytes+1)},
		{"leading space", " name"},
		{"trailing space", "name "},
		{"raw unicode", "café"},
		{"wire too long", "=?base64?" + strings.Repeat("A", 345) + "?="},
		{"decoded too long", metadataWireName(strings.Repeat("n", metadataNameMaxBytes+1))},
		{"malformed base64", "=?base64?%%%?="},
		{"missing padding", "=?base64?YQ?="},
		{"extra padding", "=?base64?YQ===?="},
		{"noncanonical trailing bits", "=?base64?YR==?="},
		{"invalid utf8", metadataWireName(string([]byte{0xff}))},
		{"empty decoded", "=?base64??="},
		{"overlapping prefix and suffix", "=?base64?="},
		{"encoded raw CRLF", "=?base64?YQ\r\n==?="},
	}
	for i := 0; i <= 0x1f; i++ {
		invalidNames = append(invalidNames, struct {
			name  string
			value string
		}{name: "raw control byte", value: "a" + string(rune(i)) + "b"})
	}
	invalidNames = append(invalidNames, struct {
		name  string
		value string
	}{"raw DEL", "a\x7fb"})

	cases := []struct {
		name    string
		method  string
		headers http.Header
	}{
		{"GET method metadata", http.MethodGet, http.Header{"Mcp-Method": {"tools/list"}}},
		{"DELETE method metadata", http.MethodDelete, http.Header{"Mcp-Method": {"notifications/cancelled"}}},
		{"GET name metadata", http.MethodGet, http.Header{"Mcp-Name": {"resource"}}},
		{"DELETE name metadata", http.MethodDelete, http.Header{"Mcp-Name": {"resource"}}},
		{"method multiple values", http.MethodPost, http.Header{"Mcp-Method": {"tools/list", "tools/call"}}},
		{"name multiple values", http.MethodPost, http.Header{"Mcp-Name": {"one", "two"}}},
		{"case folded duplicate method", http.MethodPost, http.Header{"Mcp-Method": {"tools/list"}, "mcp-method": {"tools/call"}}},
		{"case folded duplicate name", http.MethodPost, http.Header{"Mcp-Name": {"one"}, "mcp-name": {"two"}}},
	}
	for _, tc := range invalidMethods {
		cases = append(cases, struct {
			name    string
			method  string
			headers http.Header
		}{"method " + tc.name, http.MethodPost, http.Header{"Mcp-Method": {tc.value}}})
	}
	for _, tc := range invalidNames {
		cases = append(cases, struct {
			name    string
			method  string
			headers http.Header
		}{"name " + tc.name, http.MethodPost, http.Header{"Mcp-Name": {tc.value}}})
	}
	for _, header := range []string{"Authorization", "Cookie", "X-Anything", "Mcp-Param-value", "Last-Event-ID"} {
		cases = append(cases, struct {
			name    string
			method  string
			headers http.Header
		}{"unapproved " + header, http.MethodPost, http.Header{header: {"synthetic"}}})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls, cleared atomic.Int32
			transport := flow(t, peer(func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return reply(`{"unexpected":true}`), nil
			}), &cleared)
			response, err := transport.RoundTrip(metadataRequest(t, tc.method, tc.headers))
			if response != nil || err != ErrExchange || calls.Load() != 0 {
				t.Fatal("invalid metadata request was admitted to peer")
			}
		})
	}
}

func TestMetadataHeadersDoNotChangeHeaderlessMethods(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodGet, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			var calls, cleared atomic.Int32
			transport := flow(t, peer(func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return reply(`{"ok":true}`), nil
			}), &cleared)
			response, err := transport.RoundTrip(metadataRequest(t, method, nil))
			if err != nil {
				t.Fatalf("headerless method changed: %v", err)
			}
			if _, err := io.ReadAll(response.Body); err != nil {
				t.Fatalf("response body read: %v", err)
			}
			if err := response.Body.Close(); err != nil || calls.Load() != 1 {
				t.Fatal("headerless exchange did not complete cleanly")
			}
		})
	}
}

package mcphttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
)

func authAccount(t *testing.T, kind string, custom bool) mcpdirectory.Account {
	t.Helper()
	directory := mcpdirectory.New()
	t.Cleanup(directory.Clear)
	server, err := directory.AddServer("fixed", "https://mcp.example.org/mcp")
	if err != nil {
		t.Fatal(err)
	}
	account := mcpdirectory.Account{ServerID: server, Name: "account", Enabled: true, Auth: mcpdirectory.Authentication{Kind: kind}}
	if kind != "none" {
		account.Auth.Secret = []byte("synthetic-private-auth")
	}
	if kind == "basic" {
		account.Auth.Username = "owner"
	}
	if custom {
		account.Headers = []mcpdirectory.Header{{Name: "X-Api-Key", Value: []byte("synthetic-private-header")}}
	}
	id, err := directory.AddAccount(account)
	if err != nil {
		t.Fatal(err)
	}
	return directory.Accounts[id]
}

func authRequest(t *testing.T) (*endpointPolicy, *http.Request) {
	t.Helper()
	policy, err := newEndpointPolicy("https://mcp.example.org/mcp")
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, policy.endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	return policy, request
}

func assertAuthMasked(t *testing.T, snapshot *outputguard.Snapshot, value string) {
	t.Helper()
	var output bytes.Buffer
	writer, err := outputguard.NewWriter(snapshot, &output)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []byte(value) {
		if _, err := writer.Write([]byte{value}); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil || output.String() != outputguard.Marker {
		t.Fatal("private authentication snapshot lost a known literal")
	}
}

func TestAuthMaterialOwnsSupportedHeadersAndProtectsTransmittedBasicLiteral(t *testing.T) {
	for _, kind := range []string{"none", "bearer", "basic"} {
		for _, custom := range []bool{false, true} {
			t.Run(kind+map[bool]string{false: "", true: "-custom"}[custom], func(t *testing.T) {
				account := authAccount(t, kind, custom)
				material, err := newHeaderMaterial(account)
				if err != nil {
					t.Fatal(err)
				}
				defer material.close()
				account.Clear()
				policy, original := authRequest(t)
				prepared, err := material.request(policy, original)
				if err != nil || prepared == original || prepared.Header.Get("Content-Type") != "application/json" || len(original.Header) != 1 {
					t.Fatal("authentication borrowed the source request or lost protocol headers")
				}
				want := ""
				switch kind {
				case "bearer":
					want = "Bearer synthetic-private-auth"
				case "basic":
					want = "Basic " + base64.StdEncoding.EncodeToString([]byte("owner:synthetic-private-auth"))
				}
				if prepared.Header.Get("Authorization") != want || (custom && prepared.Header.Get("X-Api-Key") != "synthetic-private-header") {
					t.Fatal("private header construction lost owned credential bytes")
				}
				snapshot, err := material.outputGuard()
				if err != nil {
					t.Fatal(err)
				}
				if kind != "none" {
					assertAuthMasked(t, snapshot, "synthetic-private-auth")
					assertAuthMasked(t, snapshot, want)
					if kind == "basic" {
						assertAuthMasked(t, snapshot, strings.TrimPrefix(want, "Basic "))
					}
				}
				if custom {
					assertAuthMasked(t, snapshot, "synthetic-private-header")
				}
				prepared.Header.Set("Authorization", "changed")
				again, err := material.request(policy, original)
				if err != nil || again.Header.Get("Authorization") != want {
					t.Fatal("prepared request mutation changed retained authentication")
				}
			})
		}
	}
}

func TestAuthMaterialRefusesHeaderCollisionOrEndpointSubstitution(t *testing.T) {
	material, err := newHeaderMaterial(authAccount(t, "basic", true))
	if err != nil {
		t.Fatal(err)
	}
	defer material.close()
	for _, name := range []string{"Authorization", "authorization", "AUTHORIZATION", "Proxy-Authorization", "cookie", "X-Api-Key", "x-api-key"} {
		policy, request := authRequest(t)
		request.Header[name] = []string{"synthetic caller header"}
		if result, err := material.request(policy, request); result != nil || err != ErrTransport {
			t.Fatal("caller header replaced or duplicated private authentication")
		}
	}
	for _, change := range []func(*http.Request){
		func(r *http.Request) { r.URL.Host = "other.example.org" },
		func(r *http.Request) { r.URL.Path = "/other" },
		func(r *http.Request) { r.Host = "other.example.org" },
	} {
		policy, request := authRequest(t)
		change(request)
		if result, err := material.request(policy, request); result != nil || err != ErrTransport {
			t.Fatal("substituted request obtained private authentication")
		}
	}
}

func TestAuthMaterialCloseClearsOwnedBytesWithoutErasingCapturedProtection(t *testing.T) {
	material, err := newHeaderMaterial(authAccount(t, "bearer", true))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := material.outputGuard()
	if err != nil {
		t.Fatal(err)
	}
	var owned [][]byte
	for _, header := range material.headers {
		owned = append(owned, header.value)
	}
	material.close()
	material.close()
	for _, value := range owned {
		if !bytes.Equal(value, make([]byte, len(value))) {
			t.Fatal("private header bytes were not cleared")
		}
	}
	policy, request := authRequest(t)
	if result, err := material.request(policy, request); result != nil || err != ErrTransport {
		t.Fatal("closed authentication material was reused")
	}
	if result, err := material.outputGuard(); result != nil || err != ErrTransport {
		t.Fatal("closed material issued a fresh snapshot")
	}
	assertAuthMasked(t, snapshot, "Bearer synthetic-private-auth")
}

func TestZeroMaterialAndZeroPolicyCannotPrepareAuthenticatedRequests(t *testing.T) {
	policy, request := authRequest(t)
	if prepared, err := (&headerMaterial{}).request(policy, request); prepared != nil || err != ErrTransport {
		t.Fatal("zero material created an unguarded request")
	}
	request.URL.Scheme, request.URL.Host, request.URL.Path, request.Host = "", "", "", ""
	if (&endpointPolicy{}).requestAllowed(request) {
		t.Fatal("zero policy accepted an empty endpoint")
	}
}

func TestAuthMaterialReusesRecordValidationBeforeOwningHeaders(t *testing.T) {
	for _, change := range []func(*mcpdirectory.Account){
		func(a *mcpdirectory.Account) { a.Enabled = false },
		func(a *mcpdirectory.Account) { a.ServerID = "invalid" },
		func(a *mcpdirectory.Account) { a.Auth.Kind = "unsupported" },
		func(a *mcpdirectory.Account) { a.Auth.Secret = []byte("private\r\ndiagnostic") },
		func(a *mcpdirectory.Account) { a.Headers[0].Name = "Authorization" },
		func(a *mcpdirectory.Account) { a.Headers[0].Name = "x-api-key" },
		func(a *mcpdirectory.Account) { a.Headers[0].Value = []byte(strings.Repeat("x", 8193)) },
	} {
		account := authAccount(t, "bearer", true)
		change(&account)
		if material, err := newHeaderMaterial(account); material != nil || err != ErrTransport {
			t.Fatal("invalid or disabled record created private header material")
		}
	}
}

func TestPrivateUpstreamUsesVerifiedTLSAndOneShotNoRetrySDKTransport(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	account := authAccount(t, "basic", true)
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("owner:synthetic-private-auth"))
	server := mcp.NewServer(&mcp.Implementation{Name: "bounded-fixture", Version: "dev"}, nil)
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{JSONResponse: true})
	var authenticated atomic.Int32
	peer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.Header.Get("Authorization") != want || r.Header.Get("X-Api-Key") != "synthetic-private-header" {
			http.Error(w, "refused", http.StatusUnauthorized)
			return
		}
		authenticated.Add(1)
		handler.ServeHTTP(w, r)
	}))
	defer peer.Close()
	if upstream, err := NewUpstream(ctx, peer.URL, account); upstream != nil || err != ErrTransport {
		t.Fatal("public constructor admitted loopback")
	}
	parsed, err := url.Parse(peer.URL)
	if err != nil {
		t.Fatal(err)
	}
	base := peer.Client().Transport.(*http.Transport)
	if base.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("TLS fixture skipped verification")
	}
	// Only this private fixture substitutes a loopback policy and its test roots.
	policy := &endpointPolicy{endpoint: peer.URL, host: parsed.Hostname(), port: parsed.Port()}
	upstream, err := newUpstream(ctx, policy, account, base)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if upstream.Close(cleanup) != nil {
			t.Error("private upstream failed joined cleanup")
		}
	}()
	transport, err := upstream.Take()
	if err != nil || transport.MaxRetries >= 0 || transport.HTTPClient == nil || transport.HTTPClient.Jar != nil || transport.HTTPClient.CheckRedirect == nil {
		t.Fatal("SDK transport lost fixed ownership or no-retry policy")
	}
	if again, err := upstream.Take(); again != nil || err != ErrTransport {
		t.Fatal("upstream transport was issued twice")
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "private-fixture", Version: "dev"}, nil)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatal("bounded authenticated initialization failed")
	}
	defer session.Close()
	tools, err := session.ListTools(ctx, nil)
	if err != nil || len(tools.Tools) != 0 || authenticated.Load() < 2 {
		t.Fatal("authenticated SDK exchange failed")
	}
	snapshot, err := upstream.OutputGuard()
	if err != nil {
		t.Fatal(err)
	}
	assertAuthMasked(t, snapshot, want)
	if (&Upstream{}).Close(ctx) != ErrTransport {
		t.Fatal("zero upstream reported successful cleanup")
	}
}

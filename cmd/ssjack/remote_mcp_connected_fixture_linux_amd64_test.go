//go:build linux && amd64

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	mcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

type remoteMCPConnectedServer struct {
	server       *http.Server
	listener     net.Listener
	rootDER      []byte
	authorized   atomic.Int32
	rejected     atomic.Int32
	calls        atomic.Int32
	waitCalls    atomic.Int32
	waitStarted  chan struct{}
	waitDone     atomic.Int32
	waitFinish   chan struct{}
	waitStart    sync.Once
	waitEnd      sync.Once
	knownLiteral []byte
}

func newRemoteMCPConnectedServer(t *testing.T, knownLiteral []byte) (*remoteMCPConnectedServer, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("cannot prepare private TLS fixture")
	}
	now := time.Now()
	certificate := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "coordinator.invalid"}, DNSNames: []string{"coordinator.invalid"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, public, private)
	if err != nil {
		t.Fatal("cannot prepare private TLS certificate")
	}
	keypair := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("cannot listen for private TLS fixture")
	}
	fixture := &remoteMCPConnectedServer{listener: listener, rootDER: der, waitStarted: make(chan struct{}), waitFinish: make(chan struct{}), knownLiteral: append([]byte(nil), knownLiteral...)}
	server := mcp.NewServer(&mcp.Implementation{Name: "synthetic-connected-upstream", Version: "1"}, nil)
	server.AddTool(&mcp.Tool{Name: "echo", Description: "synthetic verified TLS echo", InputSchema: map[string]any{"type": "object"}}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		fixture.calls.Add(1)
		return fixture.result(false), nil
	})
	server.AddTool(&mcp.Tool{Name: "fail", Description: "synthetic guarded error result", InputSchema: map[string]any{"type": "object"}}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		fixture.calls.Add(1)
		var input struct {
			RPC bool `json:"rpc"`
		}
		if request != nil && request.Params != nil && json.Unmarshal(request.Params.Arguments, &input) == nil && input.RPC {
			return nil, errors.New("synthetic private RPC detail")
		}
		return fixture.result(true), nil
	})
	server.AddTool(&mcp.Tool{Name: "wait", Description: "synthetic cancellable call", InputSchema: map[string]any{"type": "object"}}, func(ctx context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		fixture.calls.Add(1)
		fixture.waitCalls.Add(1)
		fixture.waitStart.Do(func() { close(fixture.waitStarted) })
		defer fixture.waitEnd.Do(func() { close(fixture.waitFinish) })
		<-ctx.Done()
		fixture.waitDone.Add(1)
		return nil, ctx.Err()
	})
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{JSONResponse: true})
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("synthetic-mcp-owner:synthetic startup Basic credential"))
	fixture.server = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.URL.Path != "/mcp" || r.Header.Get("Authorization") != want || r.Header.Get("X-Api-Key") != "synthetic MCP custom header" {
			fixture.rejected.Add(1)
			http.Error(w, "fixture refused", http.StatusUnauthorized)
			return
		}
		fixture.authorized.Add(1)
		w.Header().Set("Cache-Control", "no-store")
		handler.ServeHTTP(w, r)
	})}
	go func() {
		_ = fixture.server.Serve(tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{keypair}, MinVersion: tls.VersionTLS12}))
	}()
	t.Cleanup(func() { _ = fixture.server.Close(); clear(fixture.knownLiteral) })
	metadata, err := json.Marshal(remoteMCPConnectedRoute{Address: listener.Addr().String(), RootDER: der})
	if err != nil {
		t.Fatal("cannot encode private route metadata")
	}
	encoded := base64.RawStdEncoding.EncodeToString(metadata)
	clear(metadata)
	return fixture, encoded
}

func (s *remoteMCPConnectedServer) result(isError bool) *mcp.CallToolResult {
	raw := "synthetic startup Basic credential"
	joined := "synthetic-mcp-owner:" + raw
	encoded := base64.StdEncoding.EncodeToString([]byte(joined))
	authorization := "Basic " + encoded
	text := raw + "|" + authorization + "|" + encoded + "|synthetic MCP custom header|synthetic-unselected-account-secret|" + string(s.knownLiteral)
	return &mcp.CallToolResult{IsError: isError, Content: []mcp.Content{&mcp.TextContent{Text: text}}, StructuredContent: map[string]any{"raw": raw, "authorization": authorization, "encoded": encoded, "custom": "synthetic MCP custom header", "known": "synthetic-unselected-account-secret", "owner": string(s.knownLiteral), "n": 7}}
}

func remoteMCPDeterministicSSHKeyPEM(private ed25519.PrivateKey, comment string) []byte {
	sshString := func(value []byte) []byte {
		out := make([]byte, 4+len(value))
		binary.BigEndian.PutUint32(out, uint32(len(value)))
		copy(out[4:], value)
		return out
	}
	algorithm := sshString([]byte("ssh-ed25519"))
	publicPart := append(append([]byte(nil), algorithm...), sshString(private[32:])...)
	check := make([]byte, 4)
	section := append([]byte(nil), check...)
	section = append(section, check...)
	section = append(section, algorithm...)
	section = append(section, sshString(private[32:])...)
	section = append(section, sshString(private)...)
	section = append(section, sshString([]byte(comment))...)
	for pad := byte(1); len(section)%8 != 0; pad++ {
		section = append(section, pad)
	}
	blob := append([]byte(nil), []byte("openssh-key-v1\x00")...)
	blob = append(blob, sshString([]byte("none"))...)
	blob = append(blob, sshString([]byte("none"))...)
	blob = append(blob, sshString(nil)...)
	blob = append(blob, 0, 0, 0, 1)
	blob = append(blob, sshString(publicPart)...)
	blob = append(blob, sshString(section)...)
	return pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: blob})
}

func remoteMCPConnectedScenario(scenario string) bool {
	return scenario == "connected-basic" || scenario == "connected-bypass" || scenario == "connected-active-cancel" || scenario == "connected-cancel" || scenario == "connected-empty"
}

func remoteMCPConnectedNamespace(binding mcpdirectory.Binding) string {
	identity := fmt.Sprintf("%d:%s|%d:%s|%d|%d", len(binding.ServerID), binding.ServerID, len(binding.AccountID), binding.AccountID, binding.ServerRevision, binding.AccountRevision)
	digest := sha256.Sum256([]byte(identity))
	return "mcp" + hex.EncodeToString(digest[:6]) + "_"
}

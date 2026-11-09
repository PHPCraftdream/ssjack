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
	shutdown     chan struct{}
	serveDone    chan struct{}
	workMu       sync.Mutex
	closing      bool
	active       int
	activeDone   chan struct{}
	shutdownOnce sync.Once
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
	fixture.initLifetime()
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("synthetic-mcp-owner:synthetic startup Basic credential"))
	fixture.server = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !fixture.beginWork() {
			http.Error(w, "fixture shutting down", http.StatusServiceUnavailable)
			return
		}
		defer fixture.endWork()
		if r.TLS == nil || r.URL.Path != "/mcp" || r.Header.Get("Authorization") != want || r.Header.Get("X-Api-Key") != "synthetic MCP custom header" {
			fixture.rejected.Add(1)
			http.Error(w, "fixture refused", http.StatusUnauthorized)
			return
		}
		fixture.authorized.Add(1)
		w.Header().Set("Cache-Control", "no-store")
		fixture.handlerForRequest(r.Context()).ServeHTTP(w, r)
	})}
	go func() {
		defer close(fixture.serveDone)
		_ = fixture.server.Serve(tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{keypair}, MinVersion: tls.VersionTLS12}))
	}()
	t.Cleanup(func() {
		fixture.closeAdmission()
		closeErr := fixture.server.Close()
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		fixture.workMu.Lock()
		activeDone := fixture.activeDone
		fixture.workMu.Unlock()
		joined := true
		select {
		case <-fixture.serveDone:
		case <-cleanupCtx.Done():
			joined = false
		}
		select {
		case <-activeDone:
		case <-cleanupCtx.Done():
			joined = false
		}
		if !joined {
			t.Error("connected fixture shutdown did not finish within 10 seconds")
			return
		}
		if closeErr != nil {
			t.Error("connected fixture HTTP server did not close")
			return
		}
		clear(fixture.knownLiteral)
	})
	metadata, err := json.Marshal(remoteMCPConnectedRoute{Address: listener.Addr().String(), RootDER: der})
	if err != nil {
		t.Fatal("cannot encode private route metadata")
	}
	encoded := base64.RawStdEncoding.EncodeToString(metadata)
	clear(metadata)
	return fixture, encoded
}

func (s *remoteMCPConnectedServer) initLifetime() {
	s.shutdown = make(chan struct{})
	s.serveDone = make(chan struct{})
	s.activeDone = make(chan struct{})
}

func (s *remoteMCPConnectedServer) beginWork() bool {
	s.workMu.Lock()
	defer s.workMu.Unlock()
	if s.closing {
		return false
	}
	s.active++
	return true
}

func (s *remoteMCPConnectedServer) endWork() {
	s.workMu.Lock()
	defer s.workMu.Unlock()
	s.active--
	if s.closing && s.active == 0 {
		close(s.activeDone)
	}
}

func (s *remoteMCPConnectedServer) stopWaitWorkers() {
	s.shutdownOnce.Do(func() { close(s.shutdown) })
}

func (s *remoteMCPConnectedServer) closeAdmission() {
	s.workMu.Lock()
	if !s.closing {
		s.closing = true
		if s.active == 0 {
			close(s.activeDone)
		}
	}
	s.workMu.Unlock()
	s.stopWaitWorkers()
}

func (s *remoteMCPConnectedServer) handlerForRequest(requestCtx context.Context) http.Handler {
	server := mcp.NewServer(&mcp.Implementation{Name: "synthetic-connected-upstream", Version: "1"}, nil)
	server.AddTool(&mcp.Tool{Name: "echo", Description: "synthetic verified TLS echo", InputSchema: map[string]any{"type": "object"}}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !s.beginWork() {
			return nil, context.Canceled
		}
		defer s.endWork()
		s.calls.Add(1)
		var input struct {
			Capability string `json:"capability"`
		}
		if request != nil && request.Params != nil {
			_ = json.Unmarshal(request.Params.Arguments, &input)
		}
		return s.result(false, input.Capability), nil
	})
	server.AddTool(&mcp.Tool{Name: "fail", Description: "synthetic guarded error result", InputSchema: map[string]any{"type": "object"}}, func(_ context.Context, request *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !s.beginWork() {
			return nil, context.Canceled
		}
		defer s.endWork()
		s.calls.Add(1)
		var input struct {
			RPC bool `json:"rpc"`
		}
		if request != nil && request.Params != nil && json.Unmarshal(request.Params.Arguments, &input) == nil && input.RPC {
			return nil, errors.New("synthetic private RPC detail")
		}
		return s.result(true), nil
	})
	server.AddTool(&mcp.Tool{Name: "wait", Description: "synthetic cancellable call", InputSchema: map[string]any{"type": "object"}}, func(ctx context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !s.beginWork() {
			return nil, context.Canceled
		}
		defer s.endWork()
		return s.wait(ctx, requestCtx)
	})
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
}

func (s *remoteMCPConnectedServer) wait(ctx, requestCtx context.Context) (*mcp.CallToolResult, error) {
	s.calls.Add(1)
	s.waitCalls.Add(1)
	s.waitStart.Do(func() { close(s.waitStarted) })
	defer s.waitEnd.Do(func() { close(s.waitFinish) })
	select {
	case <-ctx.Done():
		s.waitDone.Add(1)
		return nil, ctx.Err()
	case <-requestCtx.Done():
		s.waitDone.Add(1)
		return nil, requestCtx.Err()
	case <-s.shutdown:
		return nil, context.Canceled
	}
}

func (s *remoteMCPConnectedServer) result(isError bool, capability ...string) *mcp.CallToolResult {
	raw := "synthetic startup Basic credential"
	joined := "synthetic-mcp-owner:" + raw
	encoded := base64.StdEncoding.EncodeToString([]byte(joined))
	authorization := "Basic " + encoded
	text := raw + "|" + authorization + "|" + encoded + "|synthetic MCP custom header|synthetic-unselected-account-secret|" + string(s.knownLiteral)
	structured := map[string]any{"raw": raw, "authorization": authorization, "encoded": encoded, "custom": "synthetic MCP custom header", "known": "synthetic-unselected-account-secret", "owner": string(s.knownLiteral), "n": 7}
	if len(capability) != 0 && capability[0] != "" {
		text += "|" + capability[0]
		structured["capability"] = capability[0]
	}
	return &mcp.CallToolResult{IsError: isError, Content: []mcp.Content{&mcp.TextContent{Text: text}}, StructuredContent: structured}
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

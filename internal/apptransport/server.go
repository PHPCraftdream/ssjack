package apptransport

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/buildinfo"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

const (
	EnvEndpoint = "SSJACK_APP_ENDPOINT"
	EnvToken    = "SSJACK_APP_TOKEN"
	EnvPin      = "SSJACK_APP_CERTIFICATE_SHA256"
	Protocol    = 1
)

type Bootstrap struct {
	Endpoint string
	Token    string
	Pin      string
}

type InfoOutput struct {
	Protocol     int      `json:"protocol"`
	Profile      string   `json:"profile"`
	Commit       string   `json:"commit"`
	ChunkSize    int      `json:"chunk_size"`
	Capabilities []string `json:"capabilities"`
	Cancellation string   `json:"cancellation"`
}

type Server struct {
	bootstrap Bootstrap
	http      *http.Server
	streams   *streams
	cancel    context.CancelFunc
	done      chan struct{}
	once      sync.Once
}

func Listen(parent context.Context, profile string, runner remote.StreamRunner) (*Server, error) {
	if parent.Err() != nil || profile == "" || len(profile) > 64 || runner == nil {
		return nil, errors.New("invalid application transport scope")
	}
	config, pin, err := wire.ServerTLS()
	if err != nil {
		return nil, err
	}
	token, err := wire.RandomToken()
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	s := &Server{streams: newStreams(ctx, profile, runner), cancel: cancel, done: make(chan struct{})}
	s.bootstrap = Bootstrap{Endpoint: "https://" + listener.Addr().String() + "/mcp", Token: token, Pin: pin}
	api := s.mcpServer(profile)
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return api }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	expected := sha256.Sum256([]byte("Bearer " + token))
	host := listener.Addr().String()
	s.http = &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 * 1024,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			actual := sha256.Sum256([]byte(r.Header.Get("Authorization")))
			if r.Host != host || r.URL.Path != "/mcp" || r.URL.RawQuery != "" || r.Header.Get("Origin") != "" ||
				len(r.Header.Values("Authorization")) != 1 || subtle.ConstantTimeCompare(expected[:], actual[:]) != 1 {
				http.Error(w, "access denied", http.StatusForbidden)
				return
			}
			if r.Method != http.MethodPost {
				http.Error(w, "POST required", http.StatusMethodNotAllowed)
				return
			}
			if ctx.Err() != nil {
				http.Error(w, "application transport closed", http.StatusServiceUnavailable)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 256*1024)
			handler.ServeHTTP(w, r)
		}),
	}
	limited := &limitedListener{Listener: listener, slots: make(chan struct{}, 16)}
	go func() {
		_ = s.http.Serve(tls.NewListener(limited, config))
		s.Close()
	}()
	go func() {
		select {
		case <-parent.Done():
			s.Close()
		case <-s.done:
		}
	}()
	return s, nil
}

func (s *Server) Bootstrap() Bootstrap  { return s.bootstrap }
func (s *Server) Done() <-chan struct{} { return s.done }

func (s *Server) Close() {
	s.once.Do(func() {
		s.cancel()
		_ = s.http.Close()
		s.streams.close()
		close(s.done)
	})
}

func (s *Server) mcpServer(profile string) *mcp.Server {
	api := mcp.NewServer(&mcp.Implementation{Name: "ssjack-app-transport", Version: buildinfo.Version}, nil)
	mcp.AddTool(api, &mcp.Tool{Name: "transport_info", Description: "Read the scoped transport protocol and capabilities."},
		func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, InfoOutput, error) {
			return nil, InfoOutput{Protocol: Protocol, Profile: profile, Commit: buildinfo.Revision(), ChunkSize: ChunkSize,
				Capabilities: []string{"exec", "stdin", "binary", "backpressure", "cancel"}, Cancellation: "connection-only"}, nil
		})
	mcp.AddTool(api, &mcp.Tool{Name: "transport_start", Description: "Start a command on the one delegated SSH profile."},
		func(_ context.Context, _ *mcp.CallToolRequest, input StartInput) (*mcp.CallToolResult, StartOutput, error) {
			out, err := s.streams.start(input)
			return nil, out, err
		})
	mcp.AddTool(api, &mcp.Tool{Name: "transport_input", Description: "Queue one base64 stdin chunk or EOF. Retry only when accepted is false."},
		func(_ context.Context, _ *mcp.CallToolRequest, input InputInput) (*mcp.CallToolResult, InputOutput, error) {
			out, err := s.streams.write(input)
			return nil, out, err
		})
	mcp.AddTool(api, &mcp.Tool{Name: "transport_read", Description: "Consume one lossless base64 stdout/stderr chunk, a pending reply, or final status."},
		func(ctx context.Context, _ *mcp.CallToolRequest, input JobInput) (*mcp.CallToolResult, ReadOutput, error) {
			out, err := s.streams.read(ctx, input)
			return nil, out, err
		})
	mcp.AddTool(api, &mcp.Tool{Name: "transport_cancel", Description: "Close the command SSH connection. Detached remote processes may survive."},
		func(_ context.Context, _ *mcp.CallToolRequest, input JobInput) (*mcp.CallToolResult, CancelOutput, error) {
			out, err := s.streams.stop(input)
			return nil, out, err
		})
	return api
}

func Environment(base []string, bootstrap Bootstrap) []string {
	out := make([]string, 0, len(base)+3)
	for _, item := range base {
		name, _, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}
		if IsEnvironmentName(name) {
			continue
		}
		out = append(out, item)
	}
	return append(out, EnvEndpoint+"="+bootstrap.Endpoint, EnvToken+"="+bootstrap.Token, EnvPin+"="+bootstrap.Pin)
}

func IsEnvironmentName(name string) bool {
	for _, secret := range []string{EnvEndpoint, EnvToken, EnvPin, broker.EnvToken, broker.EnvSession, broker.EnvEndpoint, broker.EnvPin, broker.EnvFile} {
		if strings.EqualFold(name, secret) {
			return true
		}
	}
	return false
}

type limitedListener struct {
	net.Listener
	slots chan struct{}
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &limitedConn{Conn: conn, release: func() { <-l.slots }}, nil
		default:
			_ = conn.Close()
		}
	}
}

type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

package apptransport

import (
	"bytes"
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
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstoretextstream"
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

type TextHydrator interface {
	Hydrate(context.Context, string, string, []byte) appstorecrypto.DeliveryOutcome
}

type TextReverseCopier interface {
	ReverseCopy(context.Context, string, string) appstorecrypto.ReverseTextOutcome
}

type Server struct {
	bootstrap     Bootstrap
	textAdapter   TextHydrator
	reverse       TextReverseCopier
	textStream    TextStreamHydrator
	reverseStream TextStreamReverseCopier
	http          *http.Server
	streams       *streams
	cancel        context.CancelFunc
	done          chan struct{}
	once          sync.Once
}

func Listen(parent context.Context, profile string, runner remote.StreamRunner) (*Server, error) {
	return listen(parent, profile, runner, nil, nil, nil, nil)
}

func ListenWithTextAdapter(parent context.Context, profile string, runner remote.StreamRunner, adapter TextHydrator) (*Server, error) {
	if adapter == nil {
		return nil, errors.New("invalid text adapter")
	}
	return listen(parent, profile, runner, adapter, nil, nil, nil)
}

func ListenWithReverseTextAdapter(parent context.Context, profile string, runner remote.StreamRunner, adapter TextReverseCopier) (*Server, error) {
	if adapter == nil {
		return nil, errors.New("invalid reverse text adapter")
	}
	return listen(parent, profile, runner, nil, adapter, nil, nil)
}

func listen(parent context.Context, profile string, runner remote.StreamRunner, adapter TextHydrator, reverse TextReverseCopier, textStream TextStreamHydrator, reverseStream TextStreamReverseCopier) (*Server, error) {
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
	s := &Server{streams: newStreams(ctx, profile, runner), textAdapter: adapter, reverse: reverse, textStream: textStream, reverseStream: reverseStream, cancel: cancel, done: make(chan struct{})}
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
			allowedPath := r.URL.Path == "/mcp" || (r.URL.RawPath == "" && ((s.textStream != nil && textStreamPath(r.URL.Path)) || (s.reverseStream != nil && r.URL.Path == TextStreamReversePath)))
			if r.Host != host || !allowedPath || r.URL.RawQuery != "" || r.Header.Get("Origin") != "" ||
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
			if r.URL.Path == TextStreamReversePath {
				s.serveReverseTextStream(w, r, profile)
				return
			}
			if r.URL.Path != "/mcp" {
				s.serveTextStream(w, r, profile)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 256*1024)
			if s.reverse != nil {
				reverseAPI := s.mcpServerForRequest(profile, r.Context())
				reverseHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return reverseAPI }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
				serveBoundedReverseResponse(w, r, reverseHandler)
				return
			}
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
	return s.mcpServerForRequest(profile, nil)
}

func (s *Server) mcpServerForRequest(profile string, requestCtx context.Context) *mcp.Server {
	api := mcp.NewServer(&mcp.Implementation{Name: "ssjack-app-transport", Version: buildinfo.Version}, nil)
	mcp.AddTool(api, &mcp.Tool{Name: "transport_info", Description: "Read the scoped transport protocol and capabilities."},
		func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, InfoOutput, error) {
			var capabilities []string
			protocol, chunkSize := Protocol, ChunkSize
			if s.reverseStream != nil {
				protocol, chunkSize, capabilities = 2, appstoretextstream.ChunkSize, []string{"text_reverse_copy_stream_v2"}
			} else if s.textStream != nil {
				protocol, chunkSize, capabilities = 2, appstoretextstream.ChunkSize, []string{"text_hydrate_stream_v2"}
			} else if s.reverse != nil {
				capabilities = []string{"text_reverse_copy"}
			} else if s.textAdapter == nil {
				capabilities = []string{"exec", "stdin", "binary", "backpressure", "cancel"}
			} else {
				capabilities = []string{"text_hydrate"}
			}
			return nil, InfoOutput{Protocol: protocol, Profile: profile, Commit: buildinfo.Revision(), ChunkSize: chunkSize,
				Capabilities: capabilities, Cancellation: "connection-only"}, nil
		})
	if s.textAdapter == nil && s.reverse == nil && s.textStream == nil && s.reverseStream == nil {
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
	}
	if s.reverse != nil {
		mcp.AddTool(api, &mcp.Tool{Name: "text_reverse_copy", Description: "Read one approved source into a reference-only selected copy; never return raw source."},
			func(ctx context.Context, _ *mcp.CallToolRequest, input TextReverseCopyInput) (*mcp.CallToolResult, TextReverseCopyOutput, error) {
				if input.OperationID == "" || len(input.OperationID) > 128 || input.File == "" || len(input.File) > 4096 || input.Mode != "reverse-copy-v1" {
					return nil, TextReverseCopyOutput{}, errors.New("invalid reverse text request")
				}
				operationCtx, cleanup := reverseRequestContext(ctx, requestCtx)
				defer cleanup()
				outcome := s.reverse.ReverseCopy(operationCtx, input.OperationID, input.File)
				defer clear(outcome.Text)
				output := TextReverseCopyOutput{Status: "unknown"}
				if outcome.Status == appstorecrypto.DeliveryWithheld {
					output.Status = "withheld"
				} else if outcome.Status == appstorecrypto.DeliveryReceived && operationCtx.Err() == nil && len(outcome.Text) <= 1<<20 && utf8.Valid(outcome.Text) && bytes.IndexByte(outcome.Text, 0) < 0 {
					text := string(outcome.Text)
					output.Status = "received"
					output.Text = &text
				}
				return nil, output, nil
			})
	}
	if s.textAdapter != nil {
		mcp.AddTool(api, &mcp.Tool{Name: "text_hydrate", Description: "Hydrate one explicitly granted text input; only a bounded status is returned."},
			func(ctx context.Context, _ *mcp.CallToolRequest, input TextHydrateInput) (*mcp.CallToolResult, TextHydrateOutput, error) {
				if input.OperationID == "" || len(input.OperationID) > 128 || input.File == "" || len(input.File) > 4096 || input.Mode != "hydrate-v1" || len(input.Template) > 32<<10 {
					return nil, TextHydrateOutput{}, errors.New("invalid text hydration request")
				}
				outcome := s.textAdapter.Hydrate(ctx, input.OperationID, input.File, []byte(input.Template))
				status := "unknown"
				switch outcome.Status {
				case appstorecrypto.DeliveryReceived:
					status = "received"
				case appstorecrypto.DeliveryWithheld:
					status = "withheld"
				}
				return nil, TextHydrateOutput{Status: status}, nil
			})
	}
	return api
}

type TextReverseCopyInput struct {
	OperationID string `json:"operation_id"`
	File        string `json:"file"`
	Mode        string `json:"mode"`
}

type TextReverseCopyOutput struct {
	Status string  `json:"status"`
	Text   *string `json:"text,omitempty"`
}

type TextHydrateInput struct {
	OperationID string `json:"operation_id"`
	File        string `json:"file"`
	Template    string `json:"template"`
	Mode        string `json:"mode"`
}

type TextHydrateOutput struct {
	Status string `json:"status"`
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

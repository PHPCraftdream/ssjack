package mcpjack

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"

	jack "github.com/PHPCraftdream/mcp-jack"
	"github.com/PHPCraftdream/mcp-jack/client"
)

const maxResponseBytes = 256 << 10

// ErrorClass is a bounded adapter error category. Messages never include remote data.
type ErrorClass string

const (
	ErrInvalidConfig   ErrorClass = "invalid_config"
	ErrSigning         ErrorClass = "signing_failed"
	ErrRoute           ErrorClass = "route_failed"
	ErrOversize        ErrorClass = "unreadable_response"
	ErrUnverified      ErrorClass = "unverified_response"
	ErrUntrustedSigner ErrorClass = "unpinned_signer"
	ErrUnsigned401     ErrorClass = "unverified_unauthorized"
	ErrSignedRejection ErrorClass = "signed_rejection"
	ErrForbiddenTool   ErrorClass = "forbidden_tool"
	ErrCall            ErrorClass = "call_failed"
)

func (e ErrorClass) Error() string { return string(e) }

// Config creates an isolated signed mcp-jack client. The route is supplied and
// owned by the caller; the adapter never creates a transport or dialer.
type Config struct {
	Endpoint  string
	Audience  string
	ServerKey []byte
	Signer    client.Signer
	Route     http.RoundTripper
	Timeout   time.Duration
}

type Adapter struct {
	client  *client.Client
	timeout time.Duration
}

// New validates adapter-owned inputs; NewClient remains authoritative for URL policy.
func New(cfg Config) (*Adapter, error) {
	if isNil(cfg.Route) || isNil(cfg.Signer) || cfg.Audience == "" || len(cfg.ServerKey) != ed25519.PublicKeySize || cfg.Timeout <= 0 {
		return nil, ErrInvalidConfig
	}
	key := append([]byte(nil), cfg.ServerKey...)
	httpClient := &http.Client{Transport: &responseLimit{next: cfg.Route}}
	c, err := client.NewClient(client.Config{BaseURL: cfg.Endpoint, Aud: cfg.Audience, ServerKey: key, Signer: cfg.Signer, HTTP: httpClient, Era: client.EraLegacy})
	if err != nil {
		return nil, ErrInvalidConfig
	}
	return &Adapter{client: c, timeout: cfg.Timeout}, nil
}

func isNil(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return r.IsNil()
	}
	return false
}

type responseLimit struct{ next http.RoundTripper }

func (l *responseLimit) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := l.next.RoundTrip(req)
	if err != nil {
		return nil, errRouteFailure
	}
	if resp == nil || resp.Body == nil {
		return nil, errEmptyRouteResponse
	}
	resp.Body = &limitedBody{ReadCloser: resp.Body, remaining: maxResponseBytes + 1}
	return resp, nil
}

type limitedBody struct {
	io.ReadCloser
	remaining int
}

func (b *limitedBody) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		return 0, errResponseLimit
	}
	if len(p) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.ReadCloser.Read(p)
	b.remaining -= n
	if b.remaining == 0 {
		return n, errResponseLimit
	}
	if err != nil && err != io.EOF {
		return n, errRouteFailure
	}
	return n, err
}

var errResponseLimit = errors.New("response limit exceeded")
var errRouteFailure = errors.New("route failed")
var errEmptyRouteResponse = errors.New("route returned no response")

// Call makes one configured-era (legacy) signed operation; network or
// verification failures are categorized without preserving SDK error strings.
func (a *Adapter) Call(ctx context.Context, name string, arguments any, out any) error {
	if a == nil || a.client == nil || ctx == nil {
		return ErrInvalidConfig
	}
	if forbidden(name) {
		return ErrForbiddenTool
	}
	callCtx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	err := a.client.CallTool(callCtx, name, arguments, out)
	if err == nil {
		return nil
	}
	var httpErr *client.HTTPError
	if errors.As(err, &httpErr) {
		return ErrSignedRejection
	}
	var unauth *client.UnauthenticatedResponseError
	if errors.As(err, &unauth) {
		return ErrUnsigned401
	}
	if errors.Is(err, errResponseLimit) {
		return ErrOversize
	}
	if errors.Is(err, errRouteFailure) || errors.Is(err, errEmptyRouteResponse) {
		return ErrRoute
	}
	if errors.Is(err, ErrSigning) {
		return ErrSigning
	}
	var redirect *client.RedirectRefusedError
	if errors.As(err, &redirect) {
		return ErrRoute
	}
	var jackErr *jack.Error
	if errors.As(err, &jackErr) {
		switch jackErr.Code {
		case jack.CodeUnknownServerKey:
			return ErrUntrustedSigner
		case jack.CodeBadSignature, jack.CodeMissingAuth:
			return ErrUnverified
		default:
			return ErrUnverified
		}
	}
	return ErrCall
}

func forbidden(name string) bool {
	return strings.HasPrefix(name, "jack.")
}

// SeedSigner adapts vault-provided seed material to the SDK interface. It
// retains a private copy of key material and best-effort clears its owned
// private/public buffers on Close; the caller retains its seed, and other
// Go/runtime copies cannot be guaranteed erased.
type SeedSigner struct {
	private ed25519.PrivateKey
	public  []byte
	kid     string
}

func NewSeedSigner(seed []byte) (*SeedSigner, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, ErrInvalidConfig
	}
	private := ed25519.NewKeyFromSeed(seed)
	public := append([]byte(nil), private.Public().(ed25519.PublicKey)...)
	return &SeedSigner{private: private, public: public, kid: jack.KeyID(public)}, nil
}
func (s *SeedSigner) Sign(message []byte) ([]byte, error) {
	if s == nil || len(s.private) != ed25519.PrivateKeySize {
		return nil, ErrSigning
	}
	return ed25519.Sign(s.private, message), nil
}
func (s *SeedSigner) PublicKey() []byte {
	if s == nil {
		return nil
	}
	return append([]byte(nil), s.public...)
}
func (s *SeedSigner) KID() string {
	if s == nil {
		return ""
	}
	return s.kid
}
func (s *SeedSigner) Close() {
	if s != nil {
		zero(s.private)
		zero(s.public)
		s.private = nil
		s.public = nil
		s.kid = ""
	}
}
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

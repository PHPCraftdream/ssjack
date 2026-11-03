// Package appstoreanchorhttp serves fixed-scope anchor metadata, never application secrets.
package appstoreanchorhttp

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorcore"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorledger"
)

var ErrInvalid = errors.New("invalid anchor service configuration")
var ErrClosed = errors.New("anchor service closed")
var ErrBusy = errors.New("anchor service already started")
var ErrUnavailable = errors.New("anchor service unavailable")

type Binding struct {
	CredentialID [32]byte
	StoreID      [16]byte
	Role         appstoreanchorcore.Role
	Backend      *appstoreanchorledger.Backend
}
type Config struct {
	Authority   string
	Certificate tls.Certificate
	ClientCAs   *x509.CertPool
	SigningKey  ed25519.PrivateKey
	Bindings    []Binding
}
type route struct {
	grant   appstoreanchorcore.Grant
	backend *appstoreanchorledger.Backend
}
type operationKey struct {
	credential [32]byte
	store, id  [16]byte
}
type serverState struct {
	mu              sync.Mutex
	handlers        sync.WaitGroup
	closed, started bool
	done            chan struct{}
	authority       string
	tlsConfig       *tls.Config
	signer          ed25519.PrivateKey
	routes          map[[32]byte]map[[16]byte]route
	active          map[operationKey]appstoreanchorcore.Request
	slots           chan struct{}
	http            *http.Server
}
type Server struct{ state *serverState }

// New copies supplied credentials and roles; it opens no files or listeners and proves no enrollment.
func New(config Config) (*Server, error) {
	host, port, err := net.SplitHostPort(config.Authority)
	p, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || host == "" || len(host) > 253 || p < 1 || p > 65535 || strings.ContainsAny(host, "@/\\#?% \t\r\n") {
		return nil, ErrInvalid
	}
	for _, b := range []byte(host) {
		if b < 33 || b >= 127 {
			return nil, ErrInvalid
		}
	}
	if net.JoinHostPort(host, strconv.Itoa(p)) != config.Authority {
		return nil, ErrInvalid
	}
	if config.ClientCAs == nil || len(config.ClientCAs.Subjects()) == 0 || len(config.ClientCAs.Subjects()) > 64 || len(config.SigningKey) != ed25519.PrivateKeySize || len(config.Bindings) == 0 || len(config.Bindings) > 64 {
		return nil, ErrInvalid
	}
	signer := ed25519.NewKeyFromSeed(config.SigningKey[:32])
	if !bytes.Equal(signer, config.SigningKey) {
		clear(signer)
		return nil, ErrInvalid
	}
	certificate, err := ownCertificate(config.Certificate)
	if err != nil {
		clear(signer)
		return nil, ErrInvalid
	}
	s := &serverState{authority: config.Authority, signer: signer, done: make(chan struct{}), routes: make(map[[32]byte]map[[16]byte]route), active: make(map[operationKey]appstoreanchorcore.Request), slots: make(chan struct{}, 8)}
	backends := make(map[[16]byte]*appstoreanchorledger.Backend)
	for _, binding := range config.Bindings {
		grant, err := appstoreanchorcore.NewGrant(binding.StoreID, binding.CredentialID, binding.Role)
		if err != nil || binding.Backend == nil || binding.Backend.StoreID() != binding.StoreID {
			clear(signer)
			return nil, ErrInvalid
		}
		if existing, ok := backends[binding.StoreID]; ok && existing != binding.Backend {
			clear(signer)
			return nil, ErrInvalid
		}
		backends[binding.StoreID] = binding.Backend
		if s.routes[binding.CredentialID] == nil {
			s.routes[binding.CredentialID] = make(map[[16]byte]route)
		}
		if _, ok := s.routes[binding.CredentialID][binding.StoreID]; ok {
			clear(signer)
			return nil, ErrInvalid
		}
		s.routes[binding.CredentialID][binding.StoreID] = route{grant: grant, backend: binding.Backend}
	}
	s.tlsConfig = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: config.ClientCAs.Clone(), SessionTicketsDisabled: true, NextProtos: []string{"http/1.1"}}
	return &Server{state: s}, nil
}

func ownCertificate(input tls.Certificate) (tls.Certificate, error) {
	var result tls.Certificate
	if len(input.Certificate) == 0 || len(input.Certificate) > 8 || input.PrivateKey == nil {
		return result, ErrInvalid
	}
	value := reflect.ValueOf(input.PrivateKey)
	if (value.Kind() == reflect.Pointer || value.Kind() == reflect.Slice) && value.IsNil() {
		return result, ErrInvalid
	}
	if key, ok := input.PrivateKey.(ed25519.PrivateKey); ok && len(key) != ed25519.PrivateKeySize {
		return result, ErrInvalid
	}
	total := 0
	for _, der := range input.Certificate {
		total += len(der)
		if len(der) == 0 || len(der) > 16384 || total > 65536 {
			return tls.Certificate{}, ErrInvalid
		}
		result.Certificate = append(result.Certificate, append([]byte(nil), der...))
	}
	leaf, err := x509.ParseCertificate(result.Certificate[0])
	if err != nil {
		return tls.Certificate{}, ErrInvalid
	}
	private, err := x509.MarshalPKCS8PrivateKey(input.PrivateKey)
	if err != nil {
		return tls.Certificate{}, ErrInvalid
	}
	defer clear(private)
	if len(private) == 0 || len(private) > 32768 {
		return tls.Certificate{}, ErrInvalid
	}
	owned, err := x509.ParsePKCS8PrivateKey(private)
	if err != nil {
		return tls.Certificate{}, ErrInvalid
	}
	signer, ok := owned.(crypto.Signer)
	if !ok {
		return tls.Certificate{}, ErrInvalid
	}
	public, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return tls.Certificate{}, ErrInvalid
	}
	expected, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil || !bytes.Equal(public, expected) {
		return tls.Certificate{}, ErrInvalid
	}
	result.PrivateKey = owned
	return result, nil
}

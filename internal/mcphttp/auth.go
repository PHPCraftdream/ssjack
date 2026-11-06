package mcphttp

import (
	"encoding/base64"
	"net/http"
	"strings"
	"sync"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
)

type credentialHeader struct {
	name  string
	value []byte
}

type headerMaterial struct {
	mu      sync.Mutex
	headers []credentialHeader
	guard   *outputguard.Snapshot
	closed  bool
}

func newHeaderMaterial(account mcpdirectory.Account) (*headerMaterial, error) {
	if !account.Enabled || mcpdirectory.ValidateAccount(account) != nil {
		return nil, ErrTransport
	}
	material := &headerMaterial{}
	patterns := make([][]byte, 0, 7)
	if len(account.Auth.Secret) != 0 {
		patterns = append(patterns, account.Auth.Secret)
	}
	var authorization []byte
	switch account.Auth.Kind {
	case "bearer":
		authorization = append([]byte("Bearer "), account.Auth.Secret...)
	case "basic":
		joined := append([]byte(account.Auth.Username+":"), account.Auth.Secret...)
		authorization = base64.StdEncoding.AppendEncode([]byte("Basic "), joined)
		clear(joined)
	}
	if len(authorization) != 0 {
		material.headers = append(material.headers, credentialHeader{"Authorization", authorization})
		patterns = append(patterns, authorization)
		if account.Auth.Kind == "basic" {
			patterns = append(patterns, authorization[len("Basic "):])
		}
	}
	for _, header := range account.Headers {
		value := append([]byte(nil), header.Value...)
		material.headers = append(material.headers, credentialHeader{header.Name, value})
		patterns = append(patterns, value)
	}
	guard, err := outputguard.New(patterns)
	if err != nil {
		material.close()
		return nil, ErrTransport
	}
	material.guard = guard
	return material, nil
}

// request prepares private network input, never a model-visible header getter.
func (m *headerMaterial) request(policy *endpointPolicy, request *http.Request) (*http.Request, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.guard == nil || !policy.requestAllowed(request) {
		return nil, ErrTransport
	}
	for name := range request.Header {
		if strings.EqualFold(name, "Authorization") || strings.EqualFold(name, "Proxy-Authorization") || strings.EqualFold(name, "Cookie") {
			return nil, ErrTransport
		}
		for _, header := range m.headers {
			if strings.EqualFold(name, header.name) {
				return nil, ErrTransport
			}
		}
	}
	owned := request.Clone(request.Context())
	if owned.Header == nil {
		owned.Header = make(http.Header)
	}
	for _, header := range m.headers {
		owned.Header.Set(header.name, string(header.value))
	}
	return owned, nil
}

func (m *headerMaterial) outputGuard() (*outputguard.Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.guard == nil {
		return nil, ErrTransport
	}
	return m.guard, nil
}

func (m *headerMaterial) close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	m.closed = true
	for index := range m.headers {
		clear(m.headers[index].value)
		m.headers[index].value = nil
	}
	m.headers, m.guard = nil, nil
}

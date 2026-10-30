package appstoreanchorhttp

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorcore"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorledger"
)

func (s *serverState) serveHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	s.handlers.Add(1)
	s.mu.Unlock()
	defer s.handlers.Done()
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	r.Close = true
	w.Header().Set("Connection", "close")
	if r.ProtoMajor != 1 || r.Method != http.MethodPost || r.URL.Path != "/anchor" || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.Scheme != "" || r.URL.Host != "" || !strings.EqualFold(r.Host, s.authority) || r.Header.Get("Origin") != "" || r.Header.Get("Content-Encoding") != "" || r.Header.Get("Content-Type") != "application/octet-stream" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if r.TLS == nil || !r.TLS.HandshakeComplete || r.TLS.Version != tls.VersionTLS13 || r.TLS.DidResume || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	credential := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
	stores, ok := s.routes[credential]
	if !ok {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if r.ContentLength > 304 {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 305))
	defer clear(body)
	if err != nil || len(body) < 48 || len(body) > 304 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	selected, ok := stores[[16]byte(body[16:32])]
	if !ok {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	request, err := appstoreanchorcore.Parse(body, selected.grant.StoreID())
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	key := operationKey{credential: credential, store: request.StoreID(), id: request.RequestID()}
	s.mu.Lock()
	prior, occupied := s.active[key]
	closed := s.closed
	if !occupied && !closed {
		s.active[key] = request
	}
	s.mu.Unlock()
	if occupied || closed {
		result, _ := appstoreanchorcore.Unknown(request)
		if occupied && (request.Kind() == appstoreanchorcore.Read || !bytes.Equal(prior.Bytes(), request.Bytes())) {
			result, _ = appstoreanchorcore.Rejected(request)
		}
		s.reply(w, result)
		return
	}
	defer func() { s.mu.Lock(); delete(s.active, key); s.mu.Unlock() }()
	if r.Context().Err() != nil {
		return
	}
	result, err := selected.backend.Execute(request, selected.grant)
	if err != nil {
		if errors.Is(err, appstoreanchorledger.ErrConflict) || errors.Is(err, appstoreanchorledger.ErrCapacity) || errors.Is(err, appstoreanchorledger.ErrInvalid) {
			result, _ = appstoreanchorcore.Rejected(request)
		} else {
			result, _ = appstoreanchorcore.Unknown(request)
		}
	}
	s.reply(w, result)
}

func (s *serverState) reply(w http.ResponseWriter, result appstoreanchorcore.Result) {
	unsigned, err := result.Unsigned()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	var body [352]byte
	copy(body[:288], unsigned[:])
	copy(body[288:], ed25519.Sign(s.signer, unsigned[:]))
	controller := http.NewResponseController(w)
	if err := controller.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", "352")
	if n, err := w.Write(body[:]); err != nil || n != len(body) {
		return
	}
	_ = controller.Flush()
}

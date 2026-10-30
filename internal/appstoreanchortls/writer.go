package appstoreanchortls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorrequest"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorresult"
)

// Writer is a separate configured transport, not an extension of the read-only Client.
type Writer struct{ client *Client }

// NewWriter owns supplied credentials; the service must independently enforce the enrolled role.
func NewWriter(config Config) (*Writer, error) {
	client, err := New(config)
	if err != nil {
		return nil, err
	}
	return &Writer{client: client}, nil
}

// Submit sends immutable canonical bytes once. It never generates replacement IDs or retries.
func (w *Writer) Submit(ctx context.Context, request appstoreanchorrequest.Request) (appstoreanchorreply.Reply, appstoreanchorresult.MutationResult, error) {
	if w == nil || w.client == nil || w.client.state == nil {
		return appstoreanchorreply.Reply{}, 0, ErrClosed
	}
	s := w.client.state
	if !request.Valid() || (request.Operation() != 2 && request.Operation() != 3) || request.StoreID() != s.store {
		return appstoreanchorreply.Reply{}, 0, ErrInvalid
	}
	if ctx == nil {
		return appstoreanchorreply.Reply{}, 0, ErrUnavailable
	}
	deadline, ok := ctx.Deadline()
	if !ok || !deadline.After(time.Now()) {
		return appstoreanchorreply.Reply{}, 0, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return appstoreanchorreply.Reply{}, 0, err
	}
	if !s.mu.TryLock() {
		return appstoreanchorreply.Reply{}, 0, ErrBusy
	}
	defer s.mu.Unlock()
	if s.closed || len(s.privateDER) == 0 {
		return appstoreanchorreply.Reply{}, 0, ErrClosed
	}
	private, err := x509.ParsePKCS8PrivateKey(s.privateDER)
	if err != nil {
		return appstoreanchorreply.Reply{}, 0, ErrUnavailable
	}
	certificate := tls.Certificate{Certificate: s.chain, PrivateKey: private}
	reply, err := exchange(ctx, s, certificate, request, deadline)
	if err != nil {
		return appstoreanchorreply.Reply{}, appstoreanchorresult.ReadRequired, err
	}
	classification, err := appstoreanchorresult.CheckMutation(request, reply)
	if err != nil {
		return appstoreanchorreply.Reply{}, appstoreanchorresult.ReadRequired, ErrUnavailable
	}
	return reply, classification, nil
}

// Read makes a fresh authenticated observation; it does not retry or reconcile a mutation itself.
func (w *Writer) Read(ctx context.Context) (appstoreanchorreply.Reply, error) {
	if w == nil || w.client == nil {
		return appstoreanchorreply.Reply{}, ErrClosed
	}
	return w.client.Read(ctx)
}
func (w *Writer) Close() error {
	if w == nil || w.client == nil {
		return nil
	}
	return w.client.Close()
}

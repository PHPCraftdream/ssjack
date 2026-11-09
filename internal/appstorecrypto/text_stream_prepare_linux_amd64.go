//go:build linux && amd64

package appstorecrypto

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"hash"
	"io"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/appstoretextstream"
)

type textStreamTicket struct {
	id        string
	operation string
	file      string
	base      string
	mac       [sha256.Size]byte
	bytes     uint64
	expires   time.Time
}

func newStreamTemplateMAC(binding *textBinding, base string) (hash.Hash, error) {
	if binding == nil || !binding.initialized || !digestPattern.MatchString(base) {
		return nil, ErrDelivery
	}
	mac := hmac.New(sha256.New, binding.key[:])
	_, _ = mac.Write([]byte("ssjack/appstorecrypto/private-stream-template/v2\x00"))
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(base)))
	_, _ = mac.Write(size[:])
	_, _ = mac.Write([]byte(base))
	return mac, nil
}

func finishStreamTemplateMAC(mac hash.Hash, count uint64) [sha256.Size]byte {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], count)
	_, _ = mac.Write(size[:])
	var result [sha256.Size]byte
	copy(result[:], mac.Sum(nil))
	return result
}

func streamTemplateBinding(ctx context.Context, binding *textBinding, base string, input io.Reader, references []appstoreref.Ref) ([sha256.Size]byte, uint64, error) {
	if ctx == nil || input == nil {
		return [sha256.Size]byte{}, 0, ErrDelivery
	}
	mac, err := newStreamTemplateMAC(binding, base)
	if err != nil {
		return [sha256.Size]byte{}, 0, err
	}
	count, err := appstoretextstream.ValidateTemplate(ctx, io.TeeReader(input, mac), references, appstoretextstream.MaxBytes)
	if err != nil {
		return [sha256.Size]byte{}, 0, ErrDelivery
	}
	return finishStreamTemplateMAC(mac, count), count, nil
}

func (c *TextStreamAdapter) Prepare(ctx context.Context, operationID, file string, input io.Reader) (TextStreamPreparation, error) {
	if c == nil || c.adapter == nil || ctx == nil || input == nil || ctx.Err() != nil || !canonicalID(operationID) {
		return TextStreamPreparation{}, ErrDelivery
	}
	base := c.adapter
	if base.grant.Mode != "hydrate-stream-v2" || file != base.grant.File || !base.operationMu.TryLock() {
		return TextStreamPreparation{}, ErrDelivery
	}
	defer base.operationMu.Unlock()
	if base.used || c.prepared != nil || base.check(ctx) != nil {
		return TextStreamPreparation{}, ErrDelivery
	}
	expires, err := time.Parse(time.RFC3339, base.grant.ExpiresAt)
	if err != nil {
		return TextStreamPreparation{}, ErrDelivery
	}
	deadline := time.Now().Add(time.Minute)
	if expires.Before(deadline) {
		deadline = expires
	}
	opctx, cancel := context.WithDeadline(ctx, deadline)
	base.mu.Lock()
	if base.closed {
		base.mu.Unlock()
		cancel()
		return TextStreamPreparation{}, ErrDelivery
	}
	base.cancel = cancel
	base.mu.Unlock()
	defer func() { base.mu.Lock(); base.cancel = nil; base.mu.Unlock(); cancel() }()
	operation, err := textOperationDigest(operationID, file, base.grant)
	if err != nil {
		return TextStreamPreparation{}, ErrDelivery
	}
	references := make([]appstoreref.Ref, len(base.grant.References))
	for i, encoded := range base.grant.References {
		references[i], err = appstoreplaceholder.Parse([]byte(encoded))
		if err != nil {
			return TextStreamPreparation{}, ErrDelivery
		}
	}
	digest, count, err := streamTemplateBinding(opctx, &base.binding, operation, input, references)
	if err != nil || opctx.Err() != nil || base.check(opctx) != nil {
		clear(digest[:])
		return TextStreamPreparation{}, ErrDelivery
	}
	var nonce [16]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		clear(digest[:])
		return TextStreamPreparation{}, ErrDelivery
	}
	id := base64.RawURLEncoding.EncodeToString(nonce[:])
	clear(nonce[:])
	c.prepared = &textStreamTicket{id: id, operation: operationID, file: file, base: operation, mac: digest, bytes: count, expires: deadline}
	clear(digest[:])
	return TextStreamPreparation{Ticket: id, Bytes: count}, nil
}

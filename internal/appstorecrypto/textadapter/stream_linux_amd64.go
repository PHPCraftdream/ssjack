//go:build linux && amd64

package textadapter

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"hash"
	"io"
	"sync/atomic"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/delivery"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/snapshotstore"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/appstoretext"
	"github.com/PHPCraftdream/ssjack/internal/appstoretextstream"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
)

type TextStreamAdapter struct {
	adapter  *TextAdapter
	prepared *textStreamTicket
}

func NewTextStreamAdapter(ctx context.Context, installation *snapshotstore.Installation, grantID, profile, credentialDigest string, runner TextAdapterRunner) (*TextStreamAdapter, error) {
	base, err := newTextAdapter(ctx, installation, grantID, profile, credentialDigest, runner, "hydrate-stream-v2")
	if err != nil {
		return nil, err
	}
	return &TextStreamAdapter{adapter: base}, nil
}

func NewReverseTextStreamAdapter(ctx context.Context, installation *snapshotstore.Installation, grantID, profile, credentialDigest string, runner TextAdapterRunner) (*TextStreamAdapter, error) {
	base, err := newTextAdapter(ctx, installation, grantID, profile, credentialDigest, runner, "reverse-copy-stream-v2")
	if err != nil {
		return nil, err
	}
	return &TextStreamAdapter{adapter: base}, nil
}

func loadTextAdapterGrant(mode, id string, uid int, now time.Time) (declarativeauthority.TextAdapterGrant, error) {
	switch mode {
	case "hydrate-v1", "reverse-copy-v1":
		return declarativeauthority.LoadTextAdapter(id, uid, now)
	case "hydrate-stream-v2", "reverse-copy-stream-v2":
		return declarativeauthority.LoadTextStream(id, uid, now)
	default:
		return declarativeauthority.TextAdapterGrant{}, delivery.ErrDelivery
	}
}

func validTextAdapterMode(mode string) bool {
	switch mode {
	case "hydrate-v1", "reverse-copy-v1", "hydrate-stream-v2", "reverse-copy-stream-v2":
		return true
	default:
		return false
	}
}

func (c *TextStreamAdapter) MatchScope(profile, file string, references []string) error {
	return c.matchStreamScope("hydrate-stream-v2", profile, file, references)
}

func (c *TextStreamAdapter) MatchReverseScope(profile, file string, references []string) error {
	return c.matchStreamScope("reverse-copy-stream-v2", profile, file, references)
}

func (c *TextStreamAdapter) matchStreamScope(mode, profile, file string, references []string) error {
	if c == nil || c.adapter == nil || c.adapter.grant.Mode != mode || c.adapter.grant.Profile != profile || c.adapter.grant.File != file || len(references) != len(c.adapter.grant.References) || len(references) == 0 {
		return delivery.ErrDelivery
	}
	selected := make(map[string]bool, len(references))
	for _, ref := range c.adapter.grant.References {
		selected[ref] = true
	}
	for _, ref := range references {
		if !selected[ref] {
			return delivery.ErrDelivery
		}
		delete(selected, ref)
	}
	if len(selected) != 0 {
		return delivery.ErrDelivery
	}
	return nil
}

func (c *TextStreamAdapter) Close() error {
	if c == nil || c.adapter == nil {
		return nil
	}
	err := c.adapter.Close()
	c.adapter.operationMu.Lock()
	defer c.adapter.operationMu.Unlock()
	if c.prepared != nil {
		clear(c.prepared.mac[:])
		c.prepared = nil
	}
	return err
}

func (c *TextStreamAdapter) Execute(ctx context.Context, ticketID, operationID, file string, input io.ReadCloser) delivery.DeliveryOutcome {
	withheld := delivery.DeliveryOutcome{Status: delivery.DeliveryWithheld}
	if input != nil {
		defer input.Close()
	}
	if c == nil || c.adapter == nil || ctx == nil || input == nil || ctx.Err() != nil || !delivery.CanonicalID(operationID) || !delivery.CanonicalID(ticketID) {
		return withheld
	}
	base := c.adapter
	if base.grant.Mode != "hydrate-stream-v2" || file != base.grant.File || !base.operationMu.TryLock() {
		return withheld
	}
	defer base.operationMu.Unlock()
	prepared := c.prepared
	if prepared == nil || prepared.operation != operationID || prepared.file != file || subtle.ConstantTimeCompare([]byte(prepared.id), []byte(ticketID)) != 1 {
		return withheld
	}
	c.prepared = nil
	defer clear(prepared.mac[:])
	base.mu.Lock()
	if base.closed || base.used {
		base.mu.Unlock()
		return withheld
	}
	base.used = true
	base.mu.Unlock()
	if !prepared.expires.After(time.Now()) || base.check(ctx) != nil {
		return withheld
	}
	current, err := textOperationDigest(operationID, file, base.grant)
	if err != nil || current != prepared.base {
		return withheld
	}
	opctx, cancel := context.WithDeadline(ctx, prepared.expires)
	base.mu.Lock()
	if base.closed {
		base.mu.Unlock()
		cancel()
		return withheld
	}
	base.cancel = cancel
	base.mu.Unlock()
	defer func() { base.mu.Lock(); base.cancel = nil; base.mu.Unlock(); cancel() }()
	selection, err := base.captureTextStream(opctx)
	if err != nil {
		return withheld
	}
	defer selection.close()
	if selection.check(opctx) != nil {
		return withheld
	}
	outcome := runTextStream(opctx, base.runner, base.grant.Profile, base.grant.Command, input, selection.mappings, &base.binding, prepared, func() error { return base.check(opctx) })
	if outcome.Status == delivery.DeliveryReceived && selection.check(opctx) != nil {
		return delivery.DeliveryOutcome{Status: delivery.DeliveryUnknown}
	}
	return outcome
}

type streamCountReader struct {
	ctx   context.Context
	input io.Reader
	check func() error
	bytes uint64
}

func (r *streamCountReader) Read(output []byte) (int, error) {
	if r.ctx.Err() != nil || r.check() != nil {
		return 0, delivery.ErrDelivery
	}
	n, err := r.input.Read(output)
	if n < 0 || n > len(output) || uint64(n) > appstoretextstream.MaxBytes-r.bytes {
		return 0, delivery.ErrDelivery
	}
	r.bytes += uint64(n)
	return n, err
}

type streamEOFReader struct {
	input io.Reader
	eof   atomic.Bool
}

func (r *streamEOFReader) Read(output []byte) (int, error) {
	n, err := r.input.Read(output)
	if err == io.EOF {
		r.eof.Store(true)
	}
	return n, err
}

func runTextStream(ctx context.Context, runner TextAdapterRunner, profile, command string, input io.ReadCloser, mappings []appstoretext.Mapping, binding *delivery.TextBinding, ticket *textStreamTicket, check func() error) delivery.DeliveryOutcome {
	withheld := delivery.DeliveryOutcome{Status: delivery.DeliveryWithheld}
	if ctx == nil || runner == nil || input == nil || ticket == nil || check == nil || ctx.Err() != nil || check() != nil {
		return withheld
	}
	probe, err := appstoretext.Replace(nil, mappings, false)
	clear(probe)
	if err != nil {
		return withheld
	}
	mac, err := newStreamTemplateMAC(binding, ticket.base)
	if err != nil {
		return withheld
	}
	pipeline, cancel := context.WithCancel(ctx)
	defer cancel()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	stopWatch, watchDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-pipeline.Done():
			input.Close()
			writer.CloseWithError(delivery.ErrDelivery)
			reader.CloseWithError(delivery.ErrDelivery)
		case <-stopWatch:
		}
	}()
	transformed := make(chan error, 1)
	counted := &streamCountReader{ctx: pipeline, input: input, check: check}
	go func() {
		err := appstoretext.ReplaceStream(pipeline, io.TeeReader(counted, mac), writer, mappings, false, appstoretext.StreamLimits{Input: appstoretextstream.MaxBytes, Output: appstoretextstream.MaxBytes})
		if err == nil {
			actual := finishStreamTemplateMAC(mac, counted.bytes)
			if counted.bytes != ticket.bytes || subtle.ConstantTimeCompare(actual[:], ticket.mac[:]) != 1 {
				err = delivery.ErrDelivery
			}
			clear(actual[:])
		}
		if err != nil {
			_ = writer.CloseWithError(delivery.ErrDelivery)
		} else {
			_ = writer.Close()
		}
		transformed <- err
	}()
	consumed := &streamEOFReader{input: reader}
	exit, runErr := runner(pipeline, profile, command, consumed, io.Discard, io.Discard)
	if runErr != nil || exit != 0 || !consumed.eof.Load() || ctx.Err() != nil {
		cancel()
		input.Close()
		reader.CloseWithError(delivery.ErrDelivery)
		writer.CloseWithError(delivery.ErrDelivery)
	}
	transformErr := <-transformed
	close(stopWatch)
	<-watchDone
	if runErr != nil || exit != 0 || !consumed.eof.Load() || transformErr != nil || ctx.Err() != nil || check() != nil {
		return delivery.DeliveryOutcome{Status: delivery.DeliveryUnknown}
	}
	return delivery.DeliveryOutcome{Status: delivery.DeliveryReceived}
}

type textStreamTicket struct {
	id        string
	operation string
	file      string
	base      string
	mac       [sha256.Size]byte
	bytes     uint64
	expires   time.Time
}

func newStreamTemplateMAC(binding *delivery.TextBinding, base string) (hash.Hash, error) {
	if binding == nil || !binding.Initialized() || !delivery.DigestPattern.MatchString(base) {
		return nil, delivery.ErrDelivery
	}
	mac := binding.NewMAC()
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

func streamTemplateBinding(ctx context.Context, binding *delivery.TextBinding, base string, input io.Reader, references []appstoreref.Ref) ([sha256.Size]byte, uint64, error) {
	if ctx == nil || input == nil {
		return [sha256.Size]byte{}, 0, delivery.ErrDelivery
	}
	mac, err := newStreamTemplateMAC(binding, base)
	if err != nil {
		return [sha256.Size]byte{}, 0, err
	}
	count, err := appstoretextstream.ValidateTemplate(ctx, io.TeeReader(input, mac), references, appstoretextstream.MaxBytes)
	if err != nil {
		return [sha256.Size]byte{}, 0, delivery.ErrDelivery
	}
	return finishStreamTemplateMAC(mac, count), count, nil
}

func (c *TextStreamAdapter) Prepare(ctx context.Context, operationID, file string, input io.Reader) (TextStreamPreparation, error) {
	if c == nil || c.adapter == nil || ctx == nil || input == nil || ctx.Err() != nil || !delivery.CanonicalID(operationID) {
		return TextStreamPreparation{}, delivery.ErrDelivery
	}
	base := c.adapter
	if base.grant.Mode != "hydrate-stream-v2" || file != base.grant.File || !base.operationMu.TryLock() {
		return TextStreamPreparation{}, delivery.ErrDelivery
	}
	defer base.operationMu.Unlock()
	if base.used || c.prepared != nil || base.check(ctx) != nil {
		return TextStreamPreparation{}, delivery.ErrDelivery
	}
	expires, err := time.Parse(time.RFC3339, base.grant.ExpiresAt)
	if err != nil {
		return TextStreamPreparation{}, delivery.ErrDelivery
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
		return TextStreamPreparation{}, delivery.ErrDelivery
	}
	base.cancel = cancel
	base.mu.Unlock()
	defer func() { base.mu.Lock(); base.cancel = nil; base.mu.Unlock(); cancel() }()
	operation, err := textOperationDigest(operationID, file, base.grant)
	if err != nil {
		return TextStreamPreparation{}, delivery.ErrDelivery
	}
	references := make([]appstoreref.Ref, len(base.grant.References))
	for i, encoded := range base.grant.References {
		references[i], err = appstoreplaceholder.Parse([]byte(encoded))
		if err != nil {
			return TextStreamPreparation{}, delivery.ErrDelivery
		}
	}
	digest, count, err := streamTemplateBinding(opctx, &base.binding, operation, input, references)
	if err != nil || opctx.Err() != nil || base.check(opctx) != nil {
		clear(digest[:])
		return TextStreamPreparation{}, delivery.ErrDelivery
	}
	var nonce [16]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		clear(digest[:])
		return TextStreamPreparation{}, delivery.ErrDelivery
	}
	id := base64.RawURLEncoding.EncodeToString(nonce[:])
	clear(nonce[:])
	c.prepared = &textStreamTicket{id: id, operation: operationID, file: file, base: operation, mac: digest, bytes: count, expires: deadline}
	clear(digest[:])
	return TextStreamPreparation{Ticket: id, Bytes: count}, nil
}

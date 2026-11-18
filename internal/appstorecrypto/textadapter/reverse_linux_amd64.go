//go:build linux && amd64

package textadapter

import (
	"bytes"
	"context"
	"crypto/subtle"
	"io"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/delivery"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/masterkey"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/snapshotstore"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/appstoretext"
	"github.com/PHPCraftdream/ssjack/internal/appstoretextstream"
)

const reverseTextLimit = 1 << 20

type reverseCapture struct {
	mu       sync.Mutex
	data     []byte
	length   int
	overflow bool
	closed   bool
}

func (w *reverseCapture) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, io.ErrClosedPipe
	}
	if len(p) > len(w.data)-w.length {
		w.overflow = true
		return 0, io.ErrShortWrite
	}
	copy(w.data[w.length:], p)
	w.length += len(p)
	return len(p), nil
}

func (w *reverseCapture) seal() (int, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closed = true
	return w.length, w.overflow
}

func (c *TextAdapter) ReverseCopy(ctx context.Context, operationID, file string) ReverseTextOutcome {
	withheld := ReverseTextOutcome{Status: delivery.DeliveryWithheld}
	if c == nil || ctx == nil || ctx.Err() != nil || c.grant.Mode != "reverse-copy-v1" || !delivery.CanonicalID(operationID) || file != c.grant.File || c.isClosed() {
		return withheld
	}
	if !c.operationMu.TryLock() {
		return withheld
	}
	defer c.operationMu.Unlock()

	c.mu.Lock()
	if c.closed || c.used {
		c.mu.Unlock()
		return withheld
	}
	c.used = true
	grant := c.grant
	c.mu.Unlock()

	expires, err := time.Parse(time.RFC3339, grant.ExpiresAt)
	if err != nil {
		return withheld
	}
	deadline := time.Now().Add(time.Minute)
	if expires.Before(deadline) {
		deadline = expires
	}
	opctx, cancel := context.WithDeadline(ctx, deadline)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		cancel()
		return withheld
	}
	c.cancel = cancel
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.cancel = nil
		c.mu.Unlock()
		cancel()
	}()

	base, err := textOperationDigest(operationID, file, grant)
	if err != nil || c.check(opctx) != nil {
		return withheld
	}
	refs := make([]appstoreref.Ref, 0, len(grant.References))
	for _, raw := range grant.References {
		r, e := appstoreplaceholder.Parse([]byte(raw))
		if e != nil || !r.Valid() {
			return withheld
		}
		refs = append(refs, r)
	}
	if len(refs) == 0 || len(refs) > 16 {
		return withheld
	}
	tx, err := c.directory.Lock()
	if err != nil {
		return withheld
	}
	defer tx.Close()
	reply, err := c.anchor.Read(opctx)
	if err != nil {
		return withheld
	}
	state, present := reply.State()
	if !reply.SignatureValid() || reply.Outcome() != appstoreanchorreply.ReadState || !present || state.StoreID() != refs[0].StoreID() || state.CommittedSnapshotID() != refs[0].SnapshotID() || state.CommittedFileHash() != delivery.MustDigest(grant.EncodedHash) {
		return withheld
	}
	pointer, err := tx.ReadPointer()
	if err != nil {
		return withheld
	}
	var wanted [64]byte
	snapshot, encoded, transaction := state.CommittedSnapshotID(), state.CommittedFileHash(), state.CommittedTransactionID()
	copy(wanted[:16], snapshot[:])
	copy(wanted[16:48], encoded[:])
	copy(wanted[48:], transaction[:])
	if pointer != wanted || c.check(opctx) != nil {
		return withheld
	}
	spool, err := delivery.PinSnapshot(snapshotstore.MasterOf(c.installation), opctx, tx, masterkey.ExpectedSnapshot{StoreID: state.StoreID(), SnapshotID: snapshot, EncodedHash: encoded})
	if err != nil {
		return withheld
	}
	defer spool.Close()
	fresh, err := c.anchor.Read(opctx)
	if err != nil {
		return withheld
	}
	freshState, ok := fresh.State()
	freshPointer, pointerErr := tx.ReadPointer()
	if !fresh.SignatureValid() || fresh.Outcome() != appstoreanchorreply.ReadState || !ok || !freshState.Valid() || freshState.Hash() != state.Hash() || pointerErr != nil || freshPointer != wanted || c.check(opctx) != nil {
		return withheld
	}
	var aggregate uint64
	secrets := make([][]byte, 0, len(refs))
	defer func() {
		for _, secret := range secrets {
			clear(secret)
		}
	}()
	for _, reference := range refs {
		entry, e := appstoreref.FindMetadata(reference, spool.Catalog())
		if e != nil || entry.Length() > reverseTextLimit || aggregate+entry.Length() > reverseTextLimit {
			return withheld
		}
		secret := make([]byte, 0, int(entry.Length()))
		secrets = append(secrets, secret)
		got, e := delivery.StreamPinned(snapshotstore.MasterOf(c.installation), opctx, spool, entry, delivery.Buffer{Data: &secret}, func() error {
			return c.check(opctx)
		})
		secrets[len(secrets)-1] = secret
		if e != nil || got.Bytes != entry.Length() {
			return withheld
		}
		if !utf8.Valid(secret) || bytes.IndexByte(secret, 0) >= 0 {
			return withheld
		}
		aggregate += got.Bytes
	}
	mappings := make([]appstoretext.Mapping, len(refs))
	for i := range refs {
		mappings[i] = appstoretext.Mapping{Reference: refs[i], Value: secrets[i]}
	}
	if _, err = appstoretext.Replace(nil, mappings, true); err != nil {
		return withheld
	}
	if spool.Recheck(opctx) != nil || c.check(opctx) != nil {
		return withheld
	}
	fresh, err = c.anchor.Read(opctx)
	if err != nil {
		return withheld
	}
	freshState, ok = fresh.State()
	freshPointer, pointerErr = tx.ReadPointer()
	if !fresh.SignatureValid() || fresh.Outcome() != appstoreanchorreply.ReadState || !ok || freshState.Hash() != state.Hash() || pointerErr != nil || freshPointer != wanted || c.check(opctx) != nil {
		return withheld
	}
	capture := &reverseCapture{data: make([]byte, reverseTextLimit)}
	defer clear(capture.data)
	if c.check(opctx) != nil {
		return withheld
	}
	exit, runErr := c.runner(opctx, grant.Profile, grant.Command, bytes.NewReader(nil), capture, io.Discard)
	n, overflow := capture.seal()
	if runErr != nil || exit != 0 || overflow || opctx.Err() != nil {
		return ReverseTextOutcome{Status: delivery.DeliveryUnknown}
	}
	raw := capture.data[:n]
	defer clear(raw)
	if !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0 {
		return ReverseTextOutcome{Status: delivery.DeliveryUnknown}
	}
	bound := c.binding.Digest(base, raw, true)
	if !delivery.DigestPattern.MatchString(bound) {
		return ReverseTextOutcome{Status: delivery.DeliveryUnknown}
	}
	transformed, err := appstoretext.Replace(raw, mappings, true)
	if err != nil || len(transformed) > reverseTextLimit || !utf8.Valid(transformed) || bytes.IndexByte(transformed, 0) >= 0 {
		clear(transformed)
		return ReverseTextOutcome{Status: delivery.DeliveryUnknown}
	}
	if spool.Recheck(opctx) != nil || c.check(opctx) != nil {
		clear(transformed)
		return ReverseTextOutcome{Status: delivery.DeliveryUnknown}
	}
	fresh, err = c.anchor.Read(opctx)
	if err != nil {
		clear(transformed)
		return ReverseTextOutcome{Status: delivery.DeliveryUnknown}
	}
	freshState, ok = fresh.State()
	freshPointer, pointerErr = tx.ReadPointer()
	if !fresh.SignatureValid() || fresh.Outcome() != appstoreanchorreply.ReadState || !ok || freshState.Hash() != state.Hash() || pointerErr != nil || freshPointer != wanted || c.check(opctx) != nil {
		clear(transformed)
		return ReverseTextOutcome{Status: delivery.DeliveryUnknown}
	}
	if subtle.ConstantTimeCompare([]byte(c.binding.Digest(base, raw, true)), []byte(bound)) != 1 || c.check(opctx) != nil {
		clear(transformed)
		return ReverseTextOutcome{Status: delivery.DeliveryUnknown}
	}
	return ReverseTextOutcome{Status: delivery.DeliveryReceived, Text: transformed}
}

// ReverseCopyStream writes tentative reference-only bytes. The caller must not
// publish them unless the returned outcome is received. Closing output must
// unblock Write; ownership transfers to this call, including refusal paths.
func (c *TextStreamAdapter) ReverseCopyStream(ctx context.Context, operationID, file string, output io.WriteCloser) delivery.DeliveryOutcome {
	withheld := delivery.DeliveryOutcome{Status: delivery.DeliveryWithheld}
	if output != nil {
		defer output.Close()
	}
	if c == nil || c.adapter == nil || ctx == nil || output == nil || ctx.Err() != nil || !delivery.CanonicalID(operationID) {
		return withheld
	}
	base := c.adapter
	if base.grant.Mode != "reverse-copy-stream-v2" || file != base.grant.File || !base.operationMu.TryLock() {
		return withheld
	}
	defer base.operationMu.Unlock()
	base.mu.Lock()
	if base.closed || base.used {
		base.mu.Unlock()
		return withheld
	}
	base.used = true
	base.mu.Unlock()
	expires, err := time.Parse(time.RFC3339, base.grant.ExpiresAt)
	if err != nil {
		return withheld
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
	outcome := runReverseTextStream(opctx, base.runner, base.grant.Profile, base.grant.Command, output, selection.mappings, func() error { return base.check(opctx) })
	if outcome.Status == delivery.DeliveryReceived && selection.check(opctx) != nil {
		return delivery.DeliveryOutcome{Status: delivery.DeliveryUnknown}
	}
	return outcome
}

func runReverseTextStream(ctx context.Context, runner TextAdapterRunner, profile, command string, output io.WriteCloser, mappings []appstoretext.Mapping, check func() error) delivery.DeliveryOutcome {
	withheld := delivery.DeliveryOutcome{Status: delivery.DeliveryWithheld}
	if ctx == nil || runner == nil || output == nil || check == nil || ctx.Err() != nil || check() != nil {
		return withheld
	}
	probe, err := appstoretext.Replace(nil, mappings, true)
	clear(probe)
	if err != nil {
		return withheld
	}
	refs := make([]appstoreref.Ref, len(mappings))
	for i, mapping := range mappings {
		refs[i] = mapping.Reference
	}
	if _, err := appstoretextstream.ValidateTemplate(ctx, bytes.NewReader(nil), refs, appstoretextstream.MaxBytes); err != nil {
		return withheld
	}
	pipeline, cancel := context.WithCancel(ctx)
	defer cancel()
	rawR, rawW := io.Pipe()
	textR, textW := io.Pipe()
	defer rawR.Close()
	defer rawW.Close()
	defer textR.Close()
	defer textW.Close()
	stop := func() {
		cancel()
		rawR.CloseWithError(delivery.ErrDelivery)
		rawW.CloseWithError(delivery.ErrDelivery)
		textR.CloseWithError(delivery.ErrDelivery)
		textW.CloseWithError(delivery.ErrDelivery)
		output.Close()
	}
	stopWatch, watchDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-pipeline.Done():
			stop()
		case <-stopWatch:
		}
	}()
	transformed, validated := make(chan error, 1), make(chan error, 1)
	go func() {
		input := &streamCountReader{ctx: pipeline, input: rawR, check: check}
		err := appstoretext.ReplaceStream(pipeline, input, textW, mappings, true, appstoretext.StreamLimits{Input: appstoretextstream.MaxBytes, Output: appstoretextstream.MaxBytes})
		if err != nil {
			stop()
		} else {
			textW.Close()
		}
		transformed <- err
	}()
	go func() {
		_, err := appstoretextstream.ValidateTemplate(pipeline, io.TeeReader(textR, output), refs, appstoretextstream.MaxBytes)
		if err != nil {
			stop()
		}
		validated <- err
	}()
	exit, runErr := runner(pipeline, profile, command, bytes.NewReader(nil), rawW, io.Discard)
	if runErr != nil || exit != 0 || ctx.Err() != nil {
		stop()
	} else {
		rawW.Close()
	}
	transformErr, validationErr := <-transformed, <-validated
	close(stopWatch)
	<-watchDone
	if runErr != nil || exit != 0 || transformErr != nil || validationErr != nil || ctx.Err() != nil || check() != nil {
		return delivery.DeliveryOutcome{Status: delivery.DeliveryUnknown}
	}
	return delivery.DeliveryOutcome{Status: delivery.DeliveryReceived}
}

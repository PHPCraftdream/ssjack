//go:build linux && amd64

package appstorecrypto

import (
	"bytes"
	"context"
	"crypto/subtle"
	"io"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/appstoretext"
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
	withheld := ReverseTextOutcome{Status: DeliveryWithheld}
	if c == nil || ctx == nil || ctx.Err() != nil || c.grant.Mode != "reverse-copy-v1" || !canonicalID(operationID) || file != c.grant.File || c.isClosed() {
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
	if !reply.SignatureValid() || reply.Outcome() != appstoreanchorreply.ReadState || !present || state.StoreID() != refs[0].StoreID() || state.CommittedSnapshotID() != refs[0].SnapshotID() || state.CommittedFileHash() != mustDigest(grant.EncodedHash) {
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
	spool, err := c.installation.master.pinSnapshot(opctx, tx, ExpectedSnapshot{StoreID: state.StoreID(), SnapshotID: snapshot, EncodedHash: encoded})
	if err != nil {
		return withheld
	}
	defer spool.close()
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
		entry, e := appstoreref.FindMetadata(reference, spool.state.checked.Catalog())
		if e != nil || entry.Length() > reverseTextLimit || aggregate+entry.Length() > reverseTextLimit {
			return withheld
		}
		secret := make([]byte, 0, int(entry.Length()))
		secrets = append(secrets, secret)
		got, e := c.installation.master.streamPinnedObjectToChecked(opctx, spool, entry, writerBuffer{data: &secret}, func() error {
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
	if spool.recheck(opctx) != nil || c.check(opctx) != nil {
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
		return ReverseTextOutcome{Status: DeliveryUnknown}
	}
	raw := capture.data[:n]
	defer clear(raw)
	if !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0 {
		return ReverseTextOutcome{Status: DeliveryUnknown}
	}
	bound := c.binding.digest(base, raw, true)
	if !digestPattern.MatchString(bound) {
		return ReverseTextOutcome{Status: DeliveryUnknown}
	}
	transformed, err := appstoretext.Replace(raw, mappings, true)
	if err != nil || len(transformed) > reverseTextLimit || !utf8.Valid(transformed) || bytes.IndexByte(transformed, 0) >= 0 {
		clear(transformed)
		return ReverseTextOutcome{Status: DeliveryUnknown}
	}
	if spool.recheck(opctx) != nil || c.check(opctx) != nil {
		clear(transformed)
		return ReverseTextOutcome{Status: DeliveryUnknown}
	}
	fresh, err = c.anchor.Read(opctx)
	if err != nil {
		clear(transformed)
		return ReverseTextOutcome{Status: DeliveryUnknown}
	}
	freshState, ok = fresh.State()
	freshPointer, pointerErr = tx.ReadPointer()
	if !fresh.SignatureValid() || fresh.Outcome() != appstoreanchorreply.ReadState || !ok || freshState.Hash() != state.Hash() || pointerErr != nil || freshPointer != wanted || c.check(opctx) != nil {
		clear(transformed)
		return ReverseTextOutcome{Status: DeliveryUnknown}
	}
	if subtle.ConstantTimeCompare([]byte(c.binding.digest(base, raw, true)), []byte(bound)) != 1 || c.check(opctx) != nil {
		clear(transformed)
		return ReverseTextOutcome{Status: DeliveryUnknown}
	}
	return ReverseTextOutcome{Status: DeliveryReceived, Text: transformed}
}

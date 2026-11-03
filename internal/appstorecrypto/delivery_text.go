package appstorecrypto

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"io"

	"github.com/PHPCraftdream/ssjack/internal/appstorecatalog"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/appstoresink"
	"github.com/PHPCraftdream/ssjack/internal/appstoretext"
)

type textBinding struct {
	key         [32]byte
	initialized bool
}

func newTextBinding() (textBinding, error) {
	var binding textBinding
	if _, err := io.ReadFull(rand.Reader, binding.key[:]); err != nil {
		clear(binding.key[:])
		return textBinding{}, ErrDelivery
	}
	binding.initialized = true
	return binding, nil
}

func (b *textBinding) digest(base string, selected []byte, reverse bool) string {
	mac := hmac.New(sha256.New, b.key[:])
	_, _ = mac.Write([]byte("ssjack/appstorecrypto/private-text-binding/v1\x00"))
	_, _ = mac.Write([]byte(base))
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(selected)))
	_, _ = mac.Write(size[:])
	_, _ = mac.Write(selected)
	if reverse {
		_, _ = mac.Write([]byte{1})
	} else {
		_, _ = mac.Write([]byte{0})
	}
	return hex.EncodeToString(mac.Sum(nil))
}

// BindTextOperation creates an opaque, capability-specific operation digest.
func (c *DeliveryCapability) BindTextOperation(baseOperationDigest string, selected []byte, reverse bool) (string, error) {
	if c == nil || !digestPattern.MatchString(baseOperationDigest) || len(selected) > 32<<10 {
		return "", ErrDelivery
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || !c.textBinding.initialized || c.installation == nil || c.installation.master == nil || c.installation.master.Closed() {
		return "", ErrDelivery
	}
	return c.textBinding.digest(baseOperationDigest, selected, reverse), nil
}

func (c *DeliveryCapability) validTextBinding(operation OperationBinding, base string, selected []byte, reverse bool) bool {
	if c == nil || !digestPattern.MatchString(base) || !digestPattern.MatchString(operation.Digest) || len(selected) > 32<<10 {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || !c.textBinding.initialized {
		return false
	}
	want, err := hex.DecodeString(c.textBinding.digest(base, selected, reverse))
	got, gotErr := hex.DecodeString(operation.Digest)
	return err == nil && gotErr == nil && len(want) == sha256.Size && len(got) == sha256.Size && subtle.ConstantTimeCompare(want, got) == 1
}

func (c *DeliveryCapability) PrepareHydration(ctx context.Context, operation OperationBinding, baseDigest string, selected []byte) *DeliveryPlan {
	return c.prepareText(ctx, operation, baseDigest, selected, false)
}

func (c *DeliveryCapability) PrepareReverseCopy(ctx context.Context, operation OperationBinding, baseDigest string, selected []byte) *DeliveryPlan {
	return c.prepareText(ctx, operation, baseDigest, selected, true)
}

func (c *DeliveryCapability) prepareText(ctx context.Context, operation OperationBinding, baseDigest string, selected []byte, reverse bool) *DeliveryPlan {
	if c == nil || len(selected) > 32<<10 {
		return nil
	}
	owned := append([]byte(nil), selected...)
	defer clear(owned)
	if !c.validTextBinding(operation, baseDigest, owned, reverse) {
		return nil
	}
	return c.prepare(ctx, operation, &textSelection{input: owned, reverse: reverse})
}

func transformTextSelection(reference appstoreref.Ref, secret, selection []byte, reverse bool) ([]byte, error) {
	return appstoretext.Replace(selection, []appstoretext.Mapping{{Reference: reference, Value: secret}}, reverse)
}

func (m *Master) deliverTextSelection(ctx context.Context, spool *pinnedSnapshot, entry appstorecatalog.Entry, reference appstoreref.Ref, consumer *appstoresink.Consumer, encoded [32]byte, selection *textSelection, check func() error) (appstoresink.Result, error) {
	if selection == nil || entry.Length() > appstoretext.MaxText {
		return appstoresink.Result{}, ErrDelivery
	}
	secret := make([]byte, 0, entry.Length())
	collected, err := m.streamPinnedObjectToChecked(ctx, spool, entry, writerBuffer{data: &secret}, check)
	if err != nil || collected.Bytes != entry.Length() {
		clear(secret)
		return appstoresink.Result{}, ErrSnapshot
	}
	defer clear(secret)
	transformed, err := transformTextSelection(reference, secret, selection.input, selection.reverse)
	if err != nil {
		return appstoresink.Result{}, ErrDelivery
	}
	defer clear(transformed)
	if err = spool.recheck(ctx); err != nil {
		return appstoresink.Result{}, err
	}
	if err = check(); err != nil {
		return appstoresink.Result{}, err
	}
	if err = consumer.Check(reference, encoded); err != nil {
		return appstoresink.Result{}, err
	}
	session, err := consumer.Begin(ctx, reference, encoded, uint64(len(transformed)))
	if err != nil {
		return appstoresink.Result{}, err
	}
	defer session.Close()
	result := appstoresink.Result{}
	for len(transformed) > 0 {
		if err = check(); err != nil {
			return result, err
		}
		n := len(transformed)
		if n > 16384 {
			n = 16384
		}
		result.MayHaveDelivered = true
		written, writeErr := session.Write(transformed[:n])
		result.Bytes += uint64(written)
		if writeErr != nil || written != n {
			return result, appstoresink.ErrUnavailable
		}
		transformed = transformed[n:]
	}
	if err = spool.recheck(ctx); err != nil {
		return result, err
	}
	if err = consumer.Check(reference, encoded); err != nil {
		return result, err
	}
	if err = check(); err != nil {
		return result, err
	}
	return session.Finish()
}

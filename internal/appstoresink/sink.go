// Package appstoresink binds a configured native consumer to one exact RAM-only handoff.
// Supplied configuration is not proof of human enrollment or production authorization.
package appstoresink

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
)

var (
	ErrInvalid     = errors.New("invalid fixed secret consumer")
	ErrDenied      = errors.New("fixed secret consumer denied")
	ErrUnavailable = errors.New("fixed secret consumer unavailable")
	ErrUnsupported = errors.New("fixed secret consumer unsupported")
	ErrBusy        = errors.New("fixed secret consumer busy")
)

const maxProgram = 16 << 20
const maxChunk = 16384

// Binding is fixed by the trusted caller, never by a delivery request.
type Binding struct {
	Reference    appstoreref.Ref
	EncodedHash  [32]byte
	ArtifactHash [32]byte
	Target       [32]byte
	Revision     [32]byte
	Purpose      [32]byte
	ExpiresAt    time.Time
}

type Config struct {
	Program *os.File
	Binding Binding
}

type Consumer struct{ state *consumerState }
type Delivery struct{ state *deliveryState }

type Result struct {
	Bytes            uint64
	MayHaveDelivered bool
	Complete         bool
}

// New owns a duplicate program descriptor. It starts no process and grants no MCP authority.
func New(config Config) (*Consumer, error) { return newConsumer(config) }
func (c *Consumer) Binding() Binding       { return consumerBinding(c) }
func (c *Consumer) Check(reference appstoreref.Ref, hash [32]byte) error {
	return checkConsumer(c, reference, hash)
}
func (c *Consumer) Begin(ctx context.Context, reference appstoreref.Ref, hash [32]byte, length uint64) (*Delivery, error) {
	return beginDelivery(c, ctx, reference, hash, length)
}
func (c *Consumer) Close() error { return closeConsumer(c) }

// Write never accepts a different sink or more bytes than the exact declared object length.
func (d *Delivery) Write(p []byte) (int, error) { return writeDelivery(d, p) }
func (d *Delivery) Finish() (Result, error)     { return finishDelivery(d) }
func (d *Delivery) Close() error                { return closeDelivery(d) }

func validBinding(b Binding) bool {
	zero := [32]byte{}
	now := time.Now()
	return b.Reference.Valid() && b.EncodedHash != zero && b.ArtifactHash != zero && b.Target != zero && b.Revision != zero && b.Purpose != zero && b.ExpiresAt.After(now) && !b.ExpiresAt.After(now.Add(24*time.Hour))
}

func bindingDigest(b Binding) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("SSAPP-FIXED-CONSUMER-v1"))
	for _, id := range [][16]byte{b.Reference.StoreID(), b.Reference.ObjectID(), b.Reference.VersionID(), b.Reference.SnapshotID()} {
		_, _ = h.Write(id[:])
	}
	for _, digest := range [][32]byte{b.EncodedHash, b.ArtifactHash, b.Target, b.Revision, b.Purpose} {
		_, _ = h.Write(digest[:])
	}
	var expiry [8]byte
	binary.BigEndian.PutUint64(expiry[:], uint64(b.ExpiresAt.UnixNano()))
	_, _ = h.Write(expiry[:])
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

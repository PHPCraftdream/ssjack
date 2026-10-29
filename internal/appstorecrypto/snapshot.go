package appstorecrypto

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"github.com/PHPCraftdream/ssjack/internal/appstorecatalog"
	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
)

var ErrSnapshot = errors.New("application-store snapshot verification failed")
var ErrSnapshotRead = errors.New("application-store snapshot read unavailable")

type ExpectedSnapshot struct {
	StoreID     [16]byte
	SnapshotID  [16]byte
	EncodedHash [32]byte
}

type SnapshotCheck struct {
	header  appstoreheader.Header
	catalog appstorecatalog.Catalog
	hash    [32]byte
	checked bool
}

// CheckSnapshot verifies received bytes against a supplied, not enrolled, expectation.
// It returns metadata only and does not pin a source or authorize a second-pass release.
func (m *Master) CheckSnapshot(ctx context.Context, r io.Reader, expected ExpectedSnapshot) (SnapshotCheck, error) {
	if ctx == nil || expected.StoreID == ([16]byte{}) || expected.SnapshotID == ([16]byte{}) || expected.EncodedHash == ([32]byte{}) {
		return SnapshotCheck{}, ErrSnapshot
	}
	if r == nil {
		return SnapshotCheck{}, ErrSnapshotRead
	}
	if err := ctx.Err(); err != nil {
		return SnapshotCheck{}, err
	}
	if m.Closed() {
		return SnapshotCheck{}, ErrClosed
	}
	var raw [appstoreheader.Size]byte
	if err := snapshotRead(ctx, r, raw[:]); err != nil {
		return SnapshotCheck{}, err
	}
	h, err := appstoreheader.Parse(raw[:])
	if err != nil || h.StoreID() != expected.StoreID || h.SnapshotID() != expected.SnapshotID {
		return SnapshotCheck{}, ErrSnapshot
	}
	if !m.Matches(h) {
		return SnapshotCheck{}, ErrRecord
	}
	buffer := make([]byte, appstoreheader.ChunkSize+16000)
	defer clear(buffer)
	var catalogPlain []byte
	defer func() {
		if catalogPlain != nil {
			clear(catalogPlain[:cap(catalogPlain)])
		}
	}()
	full, transcript := sha256.New(), sha256.New()
	_, _ = full.Write(raw[:])
	for index := uint32(0); index < h.ChunkCount(); index++ {
		var prefix [12]byte
		if err := snapshotRead(ctx, r, prefix[:]); err != nil {
			return SnapshotCheck{}, err
		}
		plainSize, err := recordLength(h, index, false)
		if err != nil {
			return SnapshotCheck{}, ErrSnapshot
		}
		cipherSize := plainSize + 16000
		if binary.BigEndian.Uint32(prefix[:4]) != index || binary.BigEndian.Uint32(prefix[4:8]) != uint32(plainSize) || binary.BigEndian.Uint32(prefix[8:12]) != uint32(cipherSize) {
			return SnapshotCheck{}, ErrSnapshot
		}
		if err := snapshotRead(ctx, r, buffer[:cipherSize]); err != nil {
			return SnapshotCheck{}, err
		}
		_, _ = full.Write(prefix[:])
		_, _ = full.Write(buffer[:cipherSize])
		_, _ = transcript.Write(prefix[:])
		_, _ = transcript.Write(buffer[:cipherSize])
		plain, err := m.openRecord(ctx, h, index, false, buffer[:cipherSize])
		if err != nil {
			return SnapshotCheck{}, err
		}
		if index == 0 {
			catalogPlain = plain
		} else {
			clear(plain[:cap(plain)])
		}
	}
	var footer [12]byte
	if err := snapshotRead(ctx, r, footer[:]); err != nil {
		return SnapshotCheck{}, err
	}
	if string(footer[:4]) != "FIN1" || binary.BigEndian.Uint64(footer[4:12]) != 16048 {
		return SnapshotCheck{}, ErrSnapshot
	}
	if err := snapshotRead(ctx, r, buffer[:16048]); err != nil {
		return SnapshotCheck{}, err
	}
	_, _ = full.Write(footer[:])
	_, _ = full.Write(buffer[:16048])
	final, err := m.openRecord(ctx, h, ^uint32(0), true, buffer[:16048])
	if err != nil {
		return SnapshotCheck{}, err
	}
	var wantedTranscript [32]byte
	copy(wantedTranscript[:], transcript.Sum(nil))
	actualTranscript := [32]byte(final[16:48])
	clear(final[:cap(final)])
	if actualTranscript != wantedTranscript {
		return SnapshotCheck{}, ErrSnapshot
	}
	if err := ctx.Err(); err != nil {
		return SnapshotCheck{}, err
	}
	var extra [1]byte
	n, readErr := r.Read(extra[:])
	if err := ctx.Err(); err != nil {
		return SnapshotCheck{}, err
	}
	if n > 0 {
		return SnapshotCheck{}, ErrSnapshot
	}
	if n != 0 || !errors.Is(readErr, io.EOF) {
		return SnapshotCheck{}, ErrSnapshotRead
	}
	var encoded [32]byte
	copy(encoded[:], full.Sum(nil))
	if encoded != expected.EncodedHash {
		return SnapshotCheck{}, ErrSnapshot
	}
	catalog, err := appstorecatalog.Parse(h, catalogPlain)
	if err != nil {
		return SnapshotCheck{}, ErrSnapshot
	}
	if m.Closed() {
		return SnapshotCheck{}, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return SnapshotCheck{}, err
	}
	return SnapshotCheck{header: h, catalog: catalog, hash: encoded, checked: true}, nil
}

func snapshotRead(ctx context.Context, r io.Reader, b []byte) error {
	for offset := 0; offset < len(b); {
		if err := ctx.Err(); err != nil {
			return err
		}
		end := offset + 32768
		if end > len(b) {
			end = len(b)
		}
		n, err := r.Read(b[offset:end])
		if n < 0 || n > end-offset {
			return ErrSnapshotRead
		}
		offset += n
		if cancelled := ctx.Err(); cancelled != nil {
			return cancelled
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				if offset == len(b) {
					return nil
				}
				return ErrSnapshot
			}
			return ErrSnapshotRead
		}
		if n == 0 {
			return ErrSnapshotRead
		}
	}
	return nil
}

// Valid is conditional byte verification, not trusted expectation or consumer policy.
func (s SnapshotCheck) Valid() bool                      { return s.checked }
func (s SnapshotCheck) Header() appstoreheader.Header    { return s.header }
func (s SnapshotCheck) Catalog() appstorecatalog.Catalog { return s.catalog }
func (s SnapshotCheck) EncodedHash() [32]byte            { return s.hash }

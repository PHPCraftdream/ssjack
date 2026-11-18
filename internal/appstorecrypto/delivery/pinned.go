package delivery

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"os"
	"sync"

	"github.com/PHPCraftdream/ssjack/internal/appstorecatalog"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/masterkey"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
	"github.com/PHPCraftdream/ssjack/internal/appstoresink"
)

type pinnedSnapshotState struct {
	mu       sync.Mutex
	file     *os.File
	revision appstorefile.Revision
	expected masterkey.ExpectedSnapshot
	checked  masterkey.SnapshotCheck
}

// PinnedSnapshot is a private, verified spool of one committed snapshot.
type PinnedSnapshot struct{ state *pinnedSnapshotState }

// PinSnapshot copies, verifies and pins a committed snapshot for private reads.
func PinSnapshot(m *masterkey.Master, ctx context.Context, tx *appstorefile.Transaction, expected masterkey.ExpectedSnapshot) (*PinnedSnapshot, error) {
	if ctx == nil || tx == nil || expected.StoreID == ([16]byte{}) || expected.SnapshotID == ([16]byte{}) || expected.EncodedHash == ([32]byte{}) {
		return nil, masterkey.ErrSnapshot
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	source, err := tx.OpenSnapshot(expected.SnapshotID)
	if err != nil {
		return nil, err
	}
	defer source.Close()
	before, err := appstorefile.Stat(source)
	if err != nil {
		return nil, err
	}
	var raw [appstoreheader.Size]byte
	if err = masterkey.SnapshotRead(ctx, source, raw[:]); err != nil {
		return nil, err
	}
	h, err := appstoreheader.Parse(raw[:])
	if err != nil || h.StoreID() != expected.StoreID || h.SnapshotID() != expected.SnapshotID || before.Size != int64(h.EncodedSize()) || !m.Matches(h) {
		return nil, masterkey.ErrSnapshot
	}
	if _, err = source.Seek(0, io.SeekStart); err != nil {
		return nil, masterkey.ErrSnapshotRead
	}
	spool, err := tx.Temporary()
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = spool.Close()
		}
	}()
	buffer := make([]byte, 32768)
	defer clear(buffer)
	hash := sha256.New()
	for left := h.EncodedSize(); left > 0; {
		n := uint64(len(buffer))
		if n > left {
			n = left
		}
		if err = masterkey.SnapshotRead(ctx, source, buffer[:n]); err != nil {
			return nil, err
		}
		if written, e := spool.Write(buffer[:n]); e != nil || written != int(n) {
			return nil, masterkey.ErrSnapshotRead
		}
		_, _ = hash.Write(buffer[:n])
		left -= n
	}
	if err = masterkey.SnapshotEOF(ctx, source); err != nil {
		return nil, err
	}
	after, err := appstorefile.Stat(source)
	if err != nil || before != after {
		return nil, masterkey.ErrSnapshot
	}
	var encoded [32]byte
	copy(encoded[:], hash.Sum(nil))
	if encoded != expected.EncodedHash {
		return nil, masterkey.ErrSnapshot
	}
	revision, err := appstorefile.StatTemporary(spool)
	if err != nil || revision.Size != before.Size {
		return nil, masterkey.ErrSnapshot
	}
	if _, err = spool.Seek(0, io.SeekStart); err != nil {
		return nil, masterkey.ErrSnapshotRead
	}
	check, err := masterkey.CheckSnapshotHeld(m, ctx, spool, expected)
	if err != nil {
		return nil, err
	}
	p := &PinnedSnapshot{state: &pinnedSnapshotState{file: spool, revision: revision, expected: expected, checked: check}}
	if err = p.Recheck(ctx); err != nil {
		return nil, err
	}
	keep = true
	return p, nil
}

// Recheck verifies that the spool is unchanged.
func (p *PinnedSnapshot) Recheck(ctx context.Context) error {
	if p == nil || p.state == nil || ctx == nil {
		return masterkey.ErrSnapshot
	}
	s := p.state
	if !s.mu.TryLock() {
		return masterkey.ErrBusy
	}
	defer s.mu.Unlock()
	if s.file == nil || !s.checked.Valid() {
		return masterkey.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	before, err := appstorefile.StatTemporary(s.file)
	if err != nil || before != s.revision {
		return masterkey.ErrSnapshot
	}
	if _, err = s.file.Seek(0, io.SeekStart); err != nil {
		return masterkey.ErrSnapshotRead
	}
	buffer := make([]byte, 32768)
	defer clear(buffer)
	hash := sha256.New()
	for left := uint64(s.revision.Size); left > 0; {
		n := uint64(len(buffer))
		if n > left {
			n = left
		}
		if err = masterkey.SnapshotRead(ctx, s.file, buffer[:n]); err != nil {
			return err
		}
		_, _ = hash.Write(buffer[:n])
		left -= n
	}
	if err = masterkey.SnapshotEOF(ctx, s.file); err != nil {
		return err
	}
	after, err := appstorefile.StatTemporary(s.file)
	if err != nil || before != after {
		return masterkey.ErrSnapshot
	}
	var got [32]byte
	copy(got[:], hash.Sum(nil))
	if got != s.expected.EncodedHash {
		return masterkey.ErrSnapshot
	}
	if _, err = s.file.Seek(0, io.SeekStart); err != nil {
		return masterkey.ErrSnapshotRead
	}
	return ctx.Err()
}

// Close releases the spool; copies of the handle observe the close.
func (p *PinnedSnapshot) Close() error {
	if p == nil || p.state == nil {
		return nil
	}
	s := p.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	s.checked = masterkey.SnapshotCheck{}
	return err
}

func streamPinnedObject(m *masterkey.Master, ctx context.Context, pinned *PinnedSnapshot, entry appstorecatalog.Entry, sink *appstoresink.Delivery, checks ...func() error) (appstoresink.Result, error) {
	if sink == nil {
		return appstoresink.Result{}, masterkey.ErrSnapshot
	}
	return streamPinnedObjectTo(m, ctx, pinned, entry, sink, checks...)
}

// Buffer appends written bytes to Data.
type Buffer struct {
	Data *[]byte
}

func (w Buffer) Write(p []byte) (int, error) {
	*w.Data = append(*w.Data, p...)
	return len(p), nil
}

func streamPinnedObjectTo(m *masterkey.Master, ctx context.Context, pinned *PinnedSnapshot, entry appstorecatalog.Entry, sink io.Writer, checks ...func() error) (appstoresink.Result, error) {
	var result appstoresink.Result
	if sink == nil {
		return result, masterkey.ErrSnapshot
	}
	return StreamPinned(m, ctx, pinned, entry, sink, checks...)
}

// StreamPinned decrypts one pinned object into sink in bounded steps.
func StreamPinned(m *masterkey.Master, ctx context.Context, pinned *PinnedSnapshot, entry appstorecatalog.Entry, sink io.Writer, checks ...func() error) (appstoresink.Result, error) {
	var result appstoresink.Result
	if ctx == nil || pinned == nil || pinned.state == nil || sink == nil {
		return result, masterkey.ErrSnapshot
	}
	s := pinned.state
	if !s.mu.TryLock() {
		return result, masterkey.ErrBusy
	}
	defer s.mu.Unlock()
	if s.file == nil || !s.checked.Valid() {
		return result, masterkey.ErrClosed
	}
	header := s.checked.Header()
	payload := header.PlaintextSize() - appstoreheader.ChunkSize
	if entry.ObjectID() == ([16]byte{}) || entry.VersionID() == ([16]byte{}) || entry.Offset() > payload || entry.Length() > payload-entry.Offset() {
		return result, masterkey.ErrSnapshot
	}
	start := uint64(appstoreheader.ChunkSize) + entry.Offset()
	end := start + entry.Length()
	if _, err := s.file.Seek(appstoreheader.Size, io.SeekStart); err != nil {
		return result, masterkey.ErrSnapshotRead
	}
	ciphertext := make([]byte, appstoreheader.ChunkSize+16000)
	defer clear(ciphertext)
	for index := uint32(0); index < header.ChunkCount(); index++ {
		var prefix [12]byte
		if err := masterkey.SnapshotRead(ctx, s.file, prefix[:]); err != nil {
			return result, err
		}
		plainSize, err := masterkey.RecordLength(header, index, false)
		if err != nil {
			return result, err
		}
		cipherSize := plainSize + 16000
		if binary.BigEndian.Uint32(prefix[:4]) != index || binary.BigEndian.Uint32(prefix[4:8]) != uint32(plainSize) || binary.BigEndian.Uint32(prefix[8:]) != uint32(cipherSize) {
			return result, masterkey.ErrSnapshot
		}
		if err := masterkey.SnapshotRead(ctx, s.file, ciphertext[:cipherSize]); err != nil {
			return result, err
		}
		base := uint64(index) * appstoreheader.ChunkSize
		left, right := start, end
		if left < base {
			left = base
		}
		if chunkEnd := base + uint64(plainSize); right > chunkEnd {
			right = chunkEnd
		}
		if left >= right {
			continue
		}
		plain, err := masterkey.OpenRecord(m, ctx, header, index, false, ciphertext[:cipherSize])
		if err != nil {
			return result, err
		}
		selected := plain[left-base : right-base]
		for len(selected) > 0 {
			if err = ctx.Err(); err != nil {
				clear(plain[:cap(plain)])
				return result, err
			}
			for _, check := range checks {
				if check != nil {
					if err = check(); err != nil {
						clear(plain[:cap(plain)])
						return result, err
					}
				}
			}
			n := len(selected)
			if n > 16384 {
				n = 16384
			}
			result.MayHaveDelivered = true
			written, writeErr := sink.Write(selected[:n])
			result.Bytes += uint64(written)
			if writeErr != nil || written != n {
				clear(plain[:cap(plain)])
				return result, appstoresink.ErrUnavailable
			}
			selected = selected[n:]
		}
		clear(plain[:cap(plain)])
	}
	if result.Bytes != entry.Length() {
		return result, masterkey.ErrSnapshot
	}
	return result, nil
}

// Catalog returns the verified catalog of the pinned snapshot.
func (p *PinnedSnapshot) Catalog() appstorecatalog.Catalog { return p.state.checked.Catalog() }

package appstorecrypto

import (
	"context"
	"crypto/sha256"
	"io"
	"os"
	"sync"

	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
)

type pinnedSnapshotState struct {
	mu       sync.Mutex
	file     *os.File
	revision appstorefile.Revision
	expected ExpectedSnapshot
	checked  SnapshotCheck
}

type pinnedSnapshot struct{ state *pinnedSnapshotState }

// The caller owns the operation lease and transaction lock. This grants no release authority.
func (m *Master) pinSnapshot(ctx context.Context, tx *appstorefile.Transaction, expected ExpectedSnapshot) (*pinnedSnapshot, error) {
	if ctx == nil || tx == nil || expected.StoreID == ([16]byte{}) || expected.SnapshotID == ([16]byte{}) || expected.EncodedHash == ([32]byte{}) {
		return nil, ErrSnapshot
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
	if err = snapshotRead(ctx, source, raw[:]); err != nil {
		return nil, err
	}
	h, err := appstoreheader.Parse(raw[:])
	if err != nil || h.StoreID() != expected.StoreID || h.SnapshotID() != expected.SnapshotID || before.Size != int64(h.EncodedSize()) || !m.Matches(h) {
		return nil, ErrSnapshot
	}
	if _, err = source.Seek(0, io.SeekStart); err != nil {
		return nil, ErrSnapshotRead
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
		if err = snapshotRead(ctx, source, buffer[:n]); err != nil {
			return nil, err
		}
		if written, writeErr := spool.Write(buffer[:n]); writeErr != nil || written != int(n) {
			return nil, ErrSnapshotRead
		}
		_, _ = hash.Write(buffer[:n])
		left -= n
	}
	if err = snapshotEOF(ctx, source); err != nil {
		return nil, err
	}
	after, err := appstorefile.Stat(source)
	if err != nil || before != after {
		return nil, ErrSnapshot
	}
	var encoded [32]byte
	copy(encoded[:], hash.Sum(nil))
	if encoded != expected.EncodedHash {
		return nil, ErrSnapshot
	}
	revision, err := appstorefile.StatTemporary(spool)
	if err != nil || revision.Size != before.Size {
		return nil, ErrSnapshot
	}
	if _, err = spool.Seek(0, io.SeekStart); err != nil {
		return nil, ErrSnapshotRead
	}
	check, err := m.checkSnapshot(ctx, spool, expected)
	if err != nil {
		return nil, err
	}
	p := &pinnedSnapshot{state: &pinnedSnapshotState{file: spool, revision: revision, expected: expected, checked: check}}
	if err = p.recheck(ctx); err != nil {
		return nil, err
	}
	keep = true
	return p, nil
}

func (p *pinnedSnapshot) recheck(ctx context.Context) error {
	if p == nil || p.state == nil || ctx == nil {
		return ErrSnapshot
	}
	s := p.state
	if !s.mu.TryLock() {
		return ErrBusy
	}
	defer s.mu.Unlock()
	if s.file == nil || !s.checked.Valid() {
		return ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	before, err := appstorefile.StatTemporary(s.file)
	if err != nil || before != s.revision {
		return ErrSnapshot
	}
	if _, err = s.file.Seek(0, io.SeekStart); err != nil {
		return ErrSnapshotRead
	}
	buffer := make([]byte, 32768)
	defer clear(buffer)
	hash := sha256.New()
	for left := uint64(s.revision.Size); left > 0; {
		n := uint64(len(buffer))
		if n > left {
			n = left
		}
		if err = snapshotRead(ctx, s.file, buffer[:n]); err != nil {
			return err
		}
		_, _ = hash.Write(buffer[:n])
		left -= n
	}
	if err = snapshotEOF(ctx, s.file); err != nil {
		return err
	}
	after, err := appstorefile.StatTemporary(s.file)
	if err != nil || before != after {
		return ErrSnapshot
	}
	var got [32]byte
	copy(got[:], hash.Sum(nil))
	if got != s.expected.EncodedHash {
		return ErrSnapshot
	}
	if _, err = s.file.Seek(0, io.SeekStart); err != nil {
		return ErrSnapshotRead
	}
	return ctx.Err()
}

func (p *pinnedSnapshot) close() error {
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
	s.checked = SnapshotCheck{}
	return err
}

func snapshotEOF(ctx context.Context, f *os.File) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var extra [1]byte
	n, err := f.Read(extra[:])
	if cancelled := ctx.Err(); cancelled != nil {
		return cancelled
	}
	if n != 0 || err != io.EOF {
		return ErrSnapshot
	}
	return nil
}

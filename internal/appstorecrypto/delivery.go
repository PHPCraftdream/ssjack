package appstorecrypto

import (
	"context"
	"crypto/sha256"
	"io"
	"os"
	"sync"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchortls"
	"github.com/PHPCraftdream/ssjack/internal/appstorebudget"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/appstoresink"
)

type pinnedSnapshotState struct {
	mu       sync.Mutex
	file     *os.File
	revision appstorefile.Revision
	expected ExpectedSnapshot
	checked  SnapshotCheck
}

type pinnedSnapshot struct{ state *pinnedSnapshotState }

// Private until an authenticated enrollment path can own consumer configuration.
func (m *Master) deliverCurrent(ctx context.Context, directory *appstorefile.Directory, anchor *appstoreanchortls.Client, reference appstoreref.Ref, consumer *appstoresink.Consumer) (appstoresink.Result, error) {
	if ctx == nil || directory == nil || anchor == nil || consumer == nil {
		return appstoresink.Result{}, ErrSnapshot
	}
	binding := consumer.Binding()
	if directory.StoreID() != reference.StoreID() {
		return appstoresink.Result{}, ErrSnapshot
	}
	if err := consumer.Check(reference, binding.EncodedHash); err != nil {
		return appstoresink.Result{}, err
	}
	release, err := appstorebudget.TryAcquire(reference.StoreID())
	if err != nil {
		return appstoresink.Result{}, ErrBusy
	}
	defer release()
	tx, err := directory.Lock()
	if err != nil {
		return appstoresink.Result{}, err
	}
	defer tx.Close()
	reply, err := anchor.Read(ctx)
	if err != nil {
		return appstoresink.Result{}, err
	}
	state, present := reply.State()
	if !reply.SignatureValid() || reply.Outcome() != appstoreanchorreply.ReadState || !present || state.StoreID() != reference.StoreID() || state.CommittedSnapshotID() != reference.SnapshotID() || state.CommittedFileHash() != binding.EncodedHash {
		return appstoresink.Result{}, ErrSnapshot
	}
	pointer, err := tx.ReadPointer()
	if err != nil {
		return appstoresink.Result{}, err
	}
	var wanted [64]byte
	snapshot, encoded, transaction := state.CommittedSnapshotID(), state.CommittedFileHash(), state.CommittedTransactionID()
	copy(wanted[:16], snapshot[:])
	copy(wanted[16:48], encoded[:])
	copy(wanted[48:], transaction[:])
	if pointer != wanted {
		return appstoresink.Result{}, ErrWriterPointerLag
	}
	spool, err := m.pinSnapshot(ctx, tx, ExpectedSnapshot{StoreID: state.StoreID(), SnapshotID: snapshot, EncodedHash: encoded})
	if err != nil {
		return appstoresink.Result{}, err
	}
	defer spool.close()
	entry, err := appstoreref.FindMetadata(reference, spool.state.checked.Catalog())
	if err != nil {
		return appstoresink.Result{}, err
	}
	if err = spool.recheck(ctx); err != nil {
		return appstoresink.Result{}, err
	}
	if err = consumer.Check(reference, encoded); err != nil {
		return appstoresink.Result{}, err
	}
	session, err := consumer.Begin(ctx, reference, encoded, entry.Length())
	if err != nil {
		return appstoresink.Result{}, err
	}
	defer session.Close()
	result, err := m.streamPinnedObject(ctx, spool, entry, session)
	if err != nil {
		return result, err
	}
	if err = spool.recheck(ctx); err != nil {
		return result, err
	}
	if err = consumer.Check(reference, encoded); err != nil {
		return result, err
	}
	return session.Finish()
}

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

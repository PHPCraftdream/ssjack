// Package snapshotstore holds the encrypted snapshot writer, its recovery and the unlocked installation.
package snapshotstore

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"sync"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorrequest"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchortls"
	"github.com/PHPCraftdream/ssjack/internal/appstorebudget"
	"github.com/PHPCraftdream/ssjack/internal/appstorecatalog"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/masterkey"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
	"github.com/PHPCraftdream/ssjack/internal/appstorejournal"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
)

var ErrWriterPointerLag = errors.New("application-store writer pointer lag")
var ErrWriterPending = errors.New("application-store writer outcome pending")
var ErrWriterBurned = errors.New("application-store reservation burned")
var ErrWriterRejected = errors.New("application-store writer rejected mutation")

const MaxOwnerObjects = 128

var ErrOwnerChanged = errors.New("application-store changed; reload owner state before editing")

func writerQuarantined(tx *appstorefile.Transaction, id [16]byte) (bool, error) {
	f, err := tx.OpenNamed("quarantine", hex.EncodeToString(id[:])+".bin")
	if errors.Is(err, appstorefile.ErrMissing) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := f.Close(); err != nil {
		return false, err
	}
	return true, nil
}

type SnapshotObject struct {
	ObjectID  [16]byte
	MediaType string
	Source    *os.File
	memory    *ramSource
}

type SnapshotCommit struct {
	State       appstoreanchorstate.State
	Refs        []appstoreref.Ref
	EncodedHash [32]byte
}

type snapshotWriterState struct {
	mu        sync.Mutex
	directory *appstorefile.Directory
	transport *appstoreanchortls.Writer
	master    *masterkey.Master
}

type SnapshotWriter struct{ state *snapshotWriterState }

func NewSnapshotWriter(directory *appstorefile.Directory, transport *appstoreanchortls.Writer, master *masterkey.Master) (*SnapshotWriter, error) {
	if directory == nil || transport == nil || master == nil || directory.StoreID() == ([16]byte{}) {
		return nil, masterkey.ErrSnapshot
	}
	masterStore, _, ready := masterkey.Context(master)
	if !ready || masterStore != directory.StoreID() {
		return nil, masterkey.ErrSnapshot
	}
	return &SnapshotWriter{state: &snapshotWriterState{directory: directory, transport: transport, master: master}}, nil
}
func (w *SnapshotWriter) Write(ctx context.Context, objects []SnapshotObject) (SnapshotCommit, error) {
	return w.write(ctx, objects, false, nil, nil)
}

func (w *SnapshotWriter) WriteFirst(ctx context.Context, objects []SnapshotObject) (SnapshotCommit, error) {
	return w.write(ctx, objects, true, nil, nil)
}

func (w *SnapshotWriter) write(ctx context.Context, objects []SnapshotObject, firstOnly bool, expected *appstoreanchorstate.State, prepare OwnerWritePrepare) (SnapshotCommit, error) {
	if w == nil || w.state == nil || ctx == nil || len(objects) > 16383 || (prepare != nil && expected == nil) {
		return SnapshotCommit{}, masterkey.ErrSnapshot
	}
	if err := ctx.Err(); err != nil {
		return SnapshotCommit{}, err
	}
	s := w.state
	if !s.mu.TryLock() {
		return SnapshotCommit{}, masterkey.ErrBusy
	}
	defer s.mu.Unlock()
	store := s.directory.StoreID()
	release, err := appstorebudget.TryAcquire(store)
	if err != nil {
		return SnapshotCommit{}, masterkey.ErrBusy
	}
	defer release()
	tx, err := s.directory.Lock()
	if err != nil {
		if errors.Is(err, appstorefile.ErrBusy) {
			return SnapshotCommit{}, masterkey.ErrBusy
		}
		return SnapshotCommit{}, err
	}
	defer tx.Close()
	state, err := writerRead(ctx, s.transport, store)
	if err != nil {
		return SnapshotCommit{}, err
	}
	if expected != nil {
		if !expected.Valid() || expected.StoreID() != store || expected.Hash() != state.Hash() {
			return SnapshotCommit{}, ErrOwnerChanged
		}
		if err := s.checkWriterHistory(ctx, tx, state, nil); err != nil {
			return SnapshotCommit{}, err
		}
	}
	if prepare == nil {
		state, err = writerReconcileReservations(ctx, tx, s.transport, state)
		if err != nil {
			return SnapshotCommit{}, err
		}
	}
	if expected != nil && expected.Hash() != state.Hash() {
		return SnapshotCommit{}, ErrOwnerChanged
	}
	if firstOnly && (state.Sequence() != 0 || state.CommittedSnapshotID() != ([16]byte{})) {
		return SnapshotCommit{}, ErrWriterRejected
	}
	jf, err := tx.Journal()
	if err != nil {
		return SnapshotCommit{}, err
	}
	defer jf.Close()
	prefix, err := appstorejournal.InspectPrefix(state, jf)
	if err != nil {
		return SnapshotCommit{}, ErrWriterPending
	}
	var extra [1]byte
	n, e := jf.Read(extra[:])
	if n != 0 || !errors.Is(e, io.EOF) {
		return SnapshotCommit{}, ErrWriterPending
	}
	if err := ctx.Err(); err != nil {
		return SnapshotCommit{}, err
	}
	if state.Sequence() == 0 {
		_ = prefix
	}
	if len(objects) > appstorecatalog.MaxEntries {
		return SnapshotCommit{}, masterkey.ErrSnapshot
	}
	for _, o := range objects {
		if o.ObjectID == ([16]byte{}) || (o.Source == nil) == (o.memory == nil) || !validMedia(o.MediaType) {
			return SnapshotCommit{}, masterkey.ErrSnapshot
		}
	}
	prepared, total, err := prepareWriterObjects(ctx, objects)
	if err == nil {
		defer func() {
			for i := range prepared {
				clear(prepared[i].memory)
			}
		}()
	}
	if err != nil {
		return SnapshotCommit{}, err
	}
	if err = s.checkWriterHistory(ctx, tx, state, prepared); err != nil {
		return SnapshotCommit{}, err
	}
	var entry appstorejournal.Entry
	for attempt := 0; attempt < 8; attempt++ {
		entry, err = newWriterEntry(state, store)
		if err != nil {
			return SnapshotCommit{}, err
		}
		checkFile, openErr := tx.Journal()
		if openErr != nil {
			return SnapshotCommit{}, openErr
		}
		_, freshErr := appstorejournal.CheckFreshPair(state, checkFile, entry)
		closeErr := checkFile.Close()
		if closeErr != nil {
			return SnapshotCommit{}, closeErr
		}
		if freshErr == nil {
			break
		}
		if !errors.Is(freshErr, appstorejournal.ErrReused) {
			return SnapshotCommit{}, freshErr
		}
		if attempt == 7 {
			return SnapshotCommit{}, masterkey.ErrSnapshot
		}
	}
	if err := ctx.Err(); err != nil {
		return SnapshotCommit{}, err
	}
	req, err := appstoreanchorrequest.PlanReservation(state, entry)
	if err != nil {
		return SnapshotCommit{}, err
	}
	if prepare != nil {
		proposal, err := ownerWriteProposal(state, entry, prepared)
		if err != nil {
			return SnapshotCommit{}, err
		}
		if err := prepare(ctx, proposal); err != nil {
			return SnapshotCommit{}, err
		}
		if err := ctx.Err(); err != nil {
			return SnapshotCommit{}, err
		}
	}
	if err = tx.AppendJournal(entry.Bytes(), state.JournalCount()); err != nil {
		return SnapshotCommit{}, err
	}
	if _, err = writerMutate(ctx, s.transport, req, state); err != nil {
		if errors.Is(err, ErrWriterRejected) {
			return SnapshotCommit{}, err
		}
		return SnapshotCommit{}, ErrWriterPending
	}
	return s.finishWrite(ctx, tx, state, req, entry, prepared, total)
}

func (s *snapshotWriterState) finishWrite(ctx context.Context, tx *appstorefile.Transaction, previous appstoreanchorstate.State, reserve appstoreanchorrequest.Request, entry appstorejournal.Entry, prepared []writerObject, total uint64) (SnapshotCommit, error) {
	var err error
	if previous.Sequence() > 0 {
		parent, openErr := tx.OpenSnapshot(previous.CommittedSnapshotID())
		if openErr != nil {
			return SnapshotCommit{}, openErr
		}
		retainErr := tx.Retain(ctx, previous.CommittedSnapshotID(), entry.TransactionID(), parent, previous.CommittedFileHash(), 1<<41)
		closeErr := parent.Close()
		if retainErr != nil {
			return SnapshotCommit{}, retainErr
		}
		if closeErr != nil {
			return SnapshotCommit{}, closeErr
		}
	}
	store, snapshot := s.directory.StoreID(), entry.SnapshotID()
	var raw [appstoreheader.Size]byte
	copy(raw[:8], "SSAPP001")
	binary.BigEndian.PutUint16(raw[8:10], 1)
	copy(raw[12:28], store[:])
	copy(raw[28:44], snapshot[:])
	parent := previous.CommittedSnapshotID()
	copy(raw[44:60], parent[:])
	binary.BigEndian.PutUint32(raw[60:64], appstoreheader.ChunkSize)
	binary.BigEndian.PutUint64(raw[64:72], total)
	binary.BigEndian.PutUint32(raw[72:76], uint32((total+appstoreheader.ChunkSize-1)/appstoreheader.ChunkSize))
	_, salts, _ := masterkey.Context(s.master)
	for i := range salts {
		copy(raw[80+i*32:112+i*32], salts[i][:])
	}
	for attempt := 0; attempt < 8; attempt++ {
		if _, err = rand.Read(raw[208:220]); err != nil {
			return SnapshotCommit{}, err
		}
		var nonce [12]byte
		copy(nonce[:], raw[208:220])
		if nonce != ([12]byte{}) {
			break
		}
		if attempt == 7 {
			return SnapshotCommit{}, masterkey.ErrSnapshot
		}
	}
	h, err := appstoreheader.Parse(raw[:])
	if err != nil {
		return SnapshotCommit{}, err
	}
	candidate, err := tx.CreateCandidate(snapshot)
	if err != nil {
		return SnapshotCommit{}, err
	}
	sealHash, sealErr := sealWriterSnapshot(s.master, ctx, h, prepared, candidate)
	closeErr := candidate.Close()
	if sealErr != nil {
		return SnapshotCommit{}, sealErr
	}
	if closeErr != nil {
		return SnapshotCommit{}, closeErr
	}
	if err = tx.SyncCandidate(snapshot); err != nil {
		return SnapshotCommit{}, err
	}
	pinned, err := tx.OpenCandidate(snapshot)
	if err != nil {
		return SnapshotCommit{}, err
	}
	_, checkErr := masterkey.CheckSnapshotHeld(s.master, ctx, pinned, masterkey.ExpectedSnapshot{StoreID: store, SnapshotID: snapshot, EncodedHash: sealHash})
	closeErr = pinned.Close()
	if checkErr != nil {
		return SnapshotCommit{}, checkErr
	}
	if closeErr != nil {
		return SnapshotCommit{}, closeErr
	}
	reserved, ok := reserve.ProposedState()
	if !ok {
		return SnapshotCommit{}, masterkey.ErrSnapshot
	}
	commit, err := appstoreanchorrequest.PlanCommit(reserve, sealHash)
	if err != nil {
		return SnapshotCommit{}, err
	}
	intent, err := appstoreanchorrequest.NewIntent(commit)
	if err != nil {
		return SnapshotCommit{}, err
	}
	txn := entry.TransactionID()
	if err = tx.CreateIntent(txn, intent.Bytes()); err != nil {
		return SnapshotCommit{}, err
	}
	loaded, err := tx.LoadIntent(txn)
	if err != nil || loaded != intent.Bytes() {
		return SnapshotCommit{}, masterkey.ErrSnapshot
	}
	if err = ctx.Err(); err != nil {
		return SnapshotCommit{}, err
	}
	next, err := writerMutate(ctx, s.transport, commit, reserved)
	if err != nil {
		if errors.Is(err, ErrWriterRejected) {
			return SnapshotCommit{}, err
		}
		return SnapshotCommit{}, ErrWriterPending
	}
	out := SnapshotCommit{State: next, EncodedHash: sealHash}
	for _, object := range prepared {
		ref, refErr := appstoreref.New(store, object.id, object.version, snapshot)
		if refErr != nil {
			return out, refErr
		}
		out.Refs = append(out.Refs, ref)
	}
	if err = tx.Publish(snapshot); err != nil {
		return out, ErrWriterPointerLag
	}
	var tuple [64]byte
	copy(tuple[:16], snapshot[:])
	copy(tuple[16:48], sealHash[:])
	copy(tuple[48:], txn[:])
	if err = tx.Pointer(tuple); err != nil {
		return out, ErrWriterPointerLag
	}
	return out, nil
}

// WriteFrom adds optimistic concurrency, not authority, to an existing writer.
func (w *SnapshotWriter) WriteFrom(ctx context.Context, expected appstoreanchorstate.State, objects []SnapshotObject) (SnapshotCommit, error) {
	return w.write(ctx, objects, false, &expected, nil)
}

// Previous state and IDs are concurrency metadata, never authority by themselves.
type OwnerWriteProposal struct {
	Previous      appstoreanchorstate.State
	TransactionID [16]byte
	SnapshotID    [16]byte
	References    []appstoreref.Ref
}

type OwnerWritePrepare func(context.Context, OwnerWriteProposal) error

func ownerWriteProposal(previous appstoreanchorstate.State, entry appstorejournal.Entry, objects []writerObject) (OwnerWriteProposal, error) {
	proposal := OwnerWriteProposal{Previous: previous, TransactionID: entry.TransactionID(), SnapshotID: entry.SnapshotID(), References: make([]appstoreref.Ref, 0, len(objects))}
	for _, object := range objects {
		reference, err := appstoreref.New(previous.StoreID(), object.id, object.version, entry.SnapshotID())
		if err != nil {
			return OwnerWriteProposal{}, err
		}
		proposal.References = append(proposal.References, reference)
	}
	return proposal, nil
}

// WriteFromPrepared calls prepare before journal append or reservation dispatch.
// The callback must persist intent, honor context and not reenter this store.
func (w *SnapshotWriter) WriteFromPrepared(ctx context.Context, expected appstoreanchorstate.State, objects []SnapshotObject, prepare OwnerWritePrepare) (SnapshotCommit, error) {
	if prepare == nil {
		return SnapshotCommit{}, masterkey.ErrSnapshot
	}
	return w.write(ctx, objects, false, &expected, prepare)
}

// WriterDirectory returns the store directory of a writer for sibling packages.
func WriterDirectory(w *SnapshotWriter) *appstorefile.Directory { return w.state.directory }

// WriterMaster returns the master of a writer for sibling packages.
func WriterMaster(w *SnapshotWriter) *masterkey.Master { return w.state.master }

// CheckHistory verifies the writer history up to the committed state.
func CheckHistory(ctx context.Context, w *SnapshotWriter, tx *appstorefile.Transaction, current appstoreanchorstate.State) error {
	return w.state.checkWriterHistory(ctx, tx, current, nil)
}

// ReadAnchor reads the current anchor state of a store.
func ReadAnchor(ctx context.Context, w *appstoreanchortls.Writer, store [16]byte) (appstoreanchorstate.State, error) {
	return writerRead(ctx, w, store)
}

// Pointer returns the writer pointer tuple of a committed state.
func Pointer(state appstoreanchorstate.State) [64]byte {
	var pointer [64]byte
	snapshot, encoded, transaction := state.CommittedSnapshotID(), state.CommittedFileHash(), state.CommittedTransactionID()
	copy(pointer[:16], snapshot[:])
	copy(pointer[16:48], encoded[:])
	copy(pointer[48:], transaction[:])
	return pointer
}

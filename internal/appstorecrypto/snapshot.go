package appstorecrypto

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"sync"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorrequest"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorresult"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchortls"
	"github.com/PHPCraftdream/ssjack/internal/appstorebudget"
	"github.com/PHPCraftdream/ssjack/internal/appstorecatalog"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
	"github.com/PHPCraftdream/ssjack/internal/appstorejournal"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
)

var ErrSnapshot = errors.New("application-store snapshot verification failed")
var ErrSnapshotRead = errors.New("application-store snapshot read unavailable")
var ErrWriterPointerLag = errors.New("application-store writer pointer lag")
var ErrWriterPending = errors.New("application-store writer outcome pending")
var ErrWriterBurned = errors.New("application-store reservation burned")
var ErrWriterRejected = errors.New("application-store writer rejected mutation")

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
	release, err := appstorebudget.TryAcquire(expected.StoreID)
	if err != nil {
		if errors.Is(err, appstorebudget.ErrBusy) {
			return SnapshotCheck{}, ErrBusy
		}
		return SnapshotCheck{}, ErrSnapshot
	}
	defer release()
	return m.checkSnapshot(ctx, r, expected)
}

func (m *Master) checkSnapshot(ctx context.Context, r io.Reader, expected ExpectedSnapshot) (SnapshotCheck, error) {
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
	master    *Master
}

func (s *snapshotWriterState) recoverPredecessor(ctx context.Context, tx *appstorefile.Transaction, proposed appstoreanchorstate.State, candidate SnapshotCheck) (appstoreanchorstate.State, error) {
	if ctx == nil || tx == nil || s == nil || s.directory == nil || s.master == nil || !proposed.Valid() || proposed.StoreID() != s.directory.StoreID() || !candidate.Valid() {
		return appstoreanchorstate.State{}, ErrSnapshot
	}
	store := proposed.StoreID()
	candidateEntries := candidate.Catalog().Entries()
	previous, err := appstoreanchorstate.Genesis(store)
	if err != nil {
		return appstoreanchorstate.State{}, ErrSnapshot
	}
	for sequence := uint64(1); sequence < proposed.Sequence(); sequence++ {
		if err := ctx.Err(); err != nil {
			return appstoreanchorstate.State{}, err
		}
		req, err := writerIntentAt(tx, store, sequence)
		if err != nil {
			return appstoreanchorstate.State{}, err
		}
		next, ok := req.ProposedState()
		if !ok || next.Sequence() != sequence || next.JournalCount() <= previous.JournalCount() || next.JournalCount() > proposed.JournalCount() {
			return appstoreanchorstate.State{}, ErrSnapshot
		}
		j, err := tx.Journal()
		if err != nil {
			return appstoreanchorstate.State{}, ErrSnapshot
		}
		_, err = appstorejournal.InspectPrefix(next, j)
		if err == nil && next.JournalCount() > 0 {
			_, err = j.Seek(int64(next.JournalCount()-1)*appstorejournal.Size, io.SeekStart)
		}
		var rawEntry [appstorejournal.Size]byte
		if err == nil {
			_, err = io.ReadFull(j, rawEntry[:])
		}
		closeErr := j.Close()
		if err != nil || closeErr != nil {
			return appstoreanchorstate.State{}, ErrSnapshot
		}
		entry, err := appstorejournal.ParseEntry(rawEntry[:], next.JournalCount()-1)
		if err != nil || entry.SnapshotID() != next.CommittedSnapshotID() || entry.TransactionID() != next.CommittedTransactionID() {
			return appstoreanchorstate.State{}, ErrSnapshot
		}
		prevRaw := previous.Bytes()
		nextRaw := next.Bytes()
		copy(prevRaw[96:136], nextRaw[96:136])
		expected, err := appstoreanchorstate.Parse(prevRaw[:], store)
		if err != nil {
			return appstoreanchorstate.State{}, ErrSnapshot
		}
		expectedHash, ok := req.ExpectedStateHash()
		if !ok || expectedHash != expected.Hash() {
			return appstoreanchorstate.State{}, ErrSnapshot
		}
		quarantined, quarantineErr := writerQuarantined(tx, next.CommittedSnapshotID())
		if quarantineErr != nil || quarantined {
			return appstoreanchorstate.State{}, ErrWriterPending
		}
		f, err := tx.OpenSnapshot(next.CommittedSnapshotID())
		if err != nil {
			return appstoreanchorstate.State{}, ErrSnapshot
		}
		check, checkErr := s.master.checkSnapshot(ctx, f, ExpectedSnapshot{StoreID: store, SnapshotID: next.CommittedSnapshotID(), EncodedHash: next.CommittedFileHash()})
		closeErr = f.Close()
		if checkErr != nil || closeErr != nil || !check.Valid() || check.Header().ParentID() != previous.CommittedSnapshotID() || !s.master.Matches(check.Header()) {
			return appstoreanchorstate.State{}, ErrRecord
		}
		checkEntries := check.Catalog().Entries()
		for _, old := range candidateEntries {
			for _, ent := range checkEntries {
				if ent.ObjectID() == old.ObjectID() && ent.VersionID() == old.VersionID() {
					return appstoreanchorstate.State{}, ErrRecord
				}
			}
		}
		previous = next
	}
	if proposed.Sequence() != previous.Sequence()+1 || proposed.JournalCount() <= previous.JournalCount() || candidate.Header().ParentID() != previous.CommittedSnapshotID() {
		return appstoreanchorstate.State{}, ErrSnapshot
	}
	if previous.Sequence() > 0 {
		f, err := tx.OpenRecovery(previous.CommittedSnapshotID(), proposed.CommittedTransactionID())
		if err != nil {
			return appstoreanchorstate.State{}, ErrSnapshot
		}
		check, checkErr := s.master.checkSnapshot(ctx, f, ExpectedSnapshot{StoreID: store, SnapshotID: previous.CommittedSnapshotID(), EncodedHash: previous.CommittedFileHash()})
		closeErr := f.Close()
		if checkErr != nil || closeErr != nil || !check.Valid() {
			return appstoreanchorstate.State{}, ErrSnapshot
		}
	}
	raw := previous.Bytes()
	proposedRaw := proposed.Bytes()
	copy(raw[96:136], proposedRaw[96:136])
	reconstructed, err := appstoreanchorstate.Parse(raw[:], store)
	if err != nil {
		return appstoreanchorstate.State{}, ErrSnapshot
	}
	return reconstructed, nil
}
func (s *snapshotWriterState) checkWriterHistory(ctx context.Context, tx *appstorefile.Transaction, current appstoreanchorstate.State, proposed []writerObject) error {
	if ctx == nil || tx == nil || s == nil || s.directory == nil || s.master == nil || !current.Valid() || current.StoreID() != s.directory.StoreID() {
		return ErrSnapshot
	}
	store := current.StoreID()
	if err := ctx.Err(); err != nil {
		return err
	}
	if current.Sequence() == 0 {
		if current.CommittedSnapshotID() != ([16]byte{}) || current.CommittedTransactionID() != ([16]byte{}) || current.CommittedFileHash() != ([32]byte{}) {
			return ErrSnapshot
		}
		for _, kind := range []string{"intents", "snapshots", "candidates", "recovery"} {
			if err := tx.Entries(kind, func(string) error { return ErrWriterPending }); err != nil {
				return err
			}
		}
		return nil
	}
	var previous, selected appstoreanchorstate.State
	previous, err := appstoreanchorstate.Genesis(store)
	if err != nil {
		return ErrSnapshot
	}
	historyIDs := make([][16]byte, 0, int(current.Sequence()))
	for sequence := uint64(1); sequence <= current.Sequence(); sequence++ {
		var found bool
		var chosen appstoreanchorrequest.Request
		if err := tx.Entries("intents", func(name string) error {
			if e := ctx.Err(); e != nil {
				return e
			}
			if len(name) != 36 || name[32:] != ".bin" {
				return ErrSnapshot
			}
			b, e := hex.DecodeString(name[:32])
			if e != nil || len(b) != 16 || hex.EncodeToString(b) != name[:32] {
				return ErrSnapshot
			}
			var txn [16]byte
			copy(txn[:], b)
			raw, e := tx.LoadIntent(txn)
			if e != nil {
				return ErrSnapshot
			}
			intent, e := appstoreanchorrequest.ParseIntent(raw[:], store)
			if e != nil {
				return ErrSnapshot
			}
			req, ok := intent.Request()
			if !ok {
				return ErrSnapshot
			}
			n, ok := req.ProposedState()
			if !ok {
				return ErrSnapshot
			}
			if n.Sequence() > current.Sequence() {
				return ErrWriterPending
			}
			if n.Sequence() == sequence {
				if found {
					return ErrSnapshot
				}
				found, chosen = true, req
			}
			return nil
		}); err != nil {
			return err
		}
		if !found {
			return ErrSnapshot
		}
		next, _ := chosen.ProposedState()
		if next.Sequence() != sequence || next.Sequence() != previous.Sequence()+1 || next.JournalCount() <= previous.JournalCount() || next.JournalCount() > current.JournalCount() {
			return ErrSnapshot
		}
		j, e := tx.Journal()
		if e != nil {
			return ErrSnapshot
		}
		prefix, e := appstorejournal.InspectPrefix(next, j)
		if e != nil || prefix.Count() != next.JournalCount() || next.JournalCount() == 0 {
			j.Close()
			return ErrSnapshot
		}
		if _, e = j.Seek(int64(next.JournalCount()-1)*appstorejournal.Size, io.SeekStart); e != nil {
			j.Close()
			return ErrSnapshot
		}
		var rawEntry [appstorejournal.Size]byte
		_, e = io.ReadFull(j, rawEntry[:])
		j.Close()
		if e != nil {
			return ErrSnapshot
		}
		entry, e := appstorejournal.ParseEntry(rawEntry[:], next.JournalCount()-1)
		if e != nil || entry.SnapshotID() != next.CommittedSnapshotID() || entry.TransactionID() != next.CommittedTransactionID() {
			return ErrSnapshot
		}
		prevRaw := previous.Bytes()
		nextRaw := next.Bytes()
		copy(prevRaw[96:136], nextRaw[96:136])
		expected, ok := chosen.ExpectedStateHash()
		if !ok {
			return ErrSnapshot
		}
		expectedReserved, e := appstoreanchorstate.Parse(prevRaw[:], store)
		if e != nil || expected != expectedReserved.Hash() {
			return ErrSnapshot
		}
		quarantined, quarantineErr := writerQuarantined(tx, next.CommittedSnapshotID())
		if quarantineErr != nil || quarantined {
			return ErrWriterPending
		}
		f, e := tx.OpenSnapshot(next.CommittedSnapshotID())
		if e != nil {
			return ErrSnapshot
		}
		check, e := s.master.checkSnapshot(ctx, f, ExpectedSnapshot{StoreID: store, SnapshotID: next.CommittedSnapshotID(), EncodedHash: next.CommittedFileHash()})
		closeErr := f.Close()
		if e != nil || closeErr != nil || !check.Valid() || check.Header().SnapshotID() != next.CommittedSnapshotID() || check.Header().ParentID() != previous.CommittedSnapshotID() || !s.master.Matches(check.Header()) {
			return ErrSnapshot
		}
		for _, id := range historyIDs {
			if id == next.CommittedSnapshotID() {
				return ErrSnapshot
			}
		}
		checkEntries := check.Catalog().Entries()
		for _, old := range proposed {
			for _, ent := range checkEntries {
				if ent.ObjectID() == old.id && ent.VersionID() == old.version {
					return ErrSnapshot
				}
			}
		}
		previous, selected = next, next
		historyIDs = append(historyIDs, next.CommittedSnapshotID())
	}
	if selected.Sequence() != current.Sequence() || selected.CommittedSnapshotID() != current.CommittedSnapshotID() || selected.CommittedTransactionID() != current.CommittedTransactionID() || selected.CommittedFileHash() != current.CommittedFileHash() {
		return ErrWriterPending
	}
	var snapshotCount uint64
	if err := tx.Entries("snapshots", func(name string) error {
		snapshotCount++
		if len(name) != 36 || name[32:] != ".bin" {
			return ErrSnapshot
		}
		b, e := hex.DecodeString(name[:32])
		if e != nil || len(b) != 16 || hex.EncodeToString(b) != name[:32] {
			return ErrSnapshot
		}
		var id [16]byte
		copy(id[:], b)
		found := false
		for _, known := range historyIDs {
			if known == id {
				found = true
				break
			}
		}
		if !found {
			return ErrSnapshot
		}
		return nil
	}); err != nil {
		return err
	}
	if snapshotCount != uint64(len(historyIDs)) {
		return ErrSnapshot
	}
	if err := tx.Entries("candidates", func(string) error { return ErrWriterPending }); err != nil {
		return err
	}
	if err := tx.Entries("recovery", func(name string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(name) != 69 || name[32] != '-' || name[65:] != ".bin" {
			return ErrWriterPending
		}
		decodeID := func(text string) ([16]byte, bool) {
			var id [16]byte
			b, e := hex.DecodeString(text)
			if e != nil || len(b) != len(id) || hex.EncodeToString(b) != text {
				return id, false
			}
			copy(id[:], b)
			return id, id != ([16]byte{})
		}
		snapshotID, ok := decodeID(name[:32])
		if !ok {
			return ErrWriterPending
		}
		txnID, ok := decodeID(name[33:65])
		if !ok {
			return ErrWriterPending
		}
		var matched bool
		var expectedHash [32]byte
		var oldState appstoreanchorstate.State
		if err := tx.Entries("intents", func(intentName string) error {
			if len(intentName) != 36 || intentName[32:] != ".bin" {
				return ErrWriterPending
			}
			id, valid := decodeID(intentName[:32])
			if !valid {
				return ErrWriterPending
			}
			raw, e := tx.LoadIntent(id)
			if e != nil {
				return ErrWriterPending
			}
			intent, e := appstoreanchorrequest.ParseIntent(raw[:], store)
			if e != nil {
				return ErrWriterPending
			}
			req, exists := intent.Request()
			if !exists {
				return ErrWriterPending
			}
			state, exists := req.ProposedState()
			if !exists || state.CommittedSnapshotID() != snapshotID {
				return nil
			}
			if matched || state.Sequence() > current.Sequence() {
				return ErrWriterPending
			}
			matched = true
			expectedHash = state.CommittedFileHash()
			oldState = state
			return nil
		}); err != nil {
			return err
		}
		if !matched {
			return ErrWriterPending
		}
		known := false
		for _, id := range historyIDs {
			if id == snapshotID {
				known = true
				break
			}
		}
		if !known {
			return ErrWriterPending
		}
		journal, err := tx.Journal()
		if err != nil {
			return ErrWriterPending
		}
		var journalMatch bool
		for index := oldState.JournalCount(); index < current.JournalCount(); index++ {
			var raw [appstorejournal.Size]byte
			if _, err = journal.ReadAt(raw[:], int64(index)*appstorejournal.Size); err != nil {
				break
			}
			entry, parseErr := appstorejournal.ParseEntry(raw[:], index)
			if parseErr != nil {
				err = parseErr
				break
			}
			if entry.TransactionID() == txnID {
				if journalMatch {
					err = ErrSnapshot
					break
				}
				journalMatch = true
			}
		}
		closeErr := journal.Close()
		if err != nil || closeErr != nil || !journalMatch {
			return ErrWriterPending
		}
		f, err := tx.OpenNamed("recovery", name)
		if err != nil {
			return ErrWriterPending
		}
		check, checkErr := s.master.checkSnapshot(ctx, f, ExpectedSnapshot{StoreID: store, SnapshotID: snapshotID, EncodedHash: expectedHash})
		closeErr = f.Close()
		if checkErr != nil || closeErr != nil || !check.Valid() || check.Header().SnapshotID() != snapshotID || !s.master.Matches(check.Header()) {
			return ErrWriterPending
		}
		parentKnown := check.Header().ParentID() == ([16]byte{}) && snapshotID == historyIDs[0]
		for _, id := range historyIDs {
			if id == check.Header().ParentID() {
				parentKnown = true
				break
			}
		}
		if !parentKnown {
			return ErrWriterPending
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

type SnapshotWriter struct{ state *snapshotWriterState }

func NewSnapshotWriter(directory *appstorefile.Directory, transport *appstoreanchortls.Writer, master *Master) (*SnapshotWriter, error) {
	if directory == nil || transport == nil || master == nil || directory.StoreID() == ([16]byte{}) || master.state == nil {
		return nil, ErrSnapshot
	}
	master.state.mu.Lock()
	ready := master.state.ready && master.state.store == directory.StoreID()
	master.state.mu.Unlock()
	if !ready {
		return nil, ErrSnapshot
	}
	return &SnapshotWriter{state: &snapshotWriterState{directory: directory, transport: transport, master: master}}, nil
}
func (w *SnapshotWriter) Write(ctx context.Context, objects []SnapshotObject) (SnapshotCommit, error) {
	return w.write(ctx, objects, false)
}

func (w *SnapshotWriter) WriteFirst(ctx context.Context, objects []SnapshotObject) (SnapshotCommit, error) {
	return w.write(ctx, objects, true)
}

func (w *SnapshotWriter) write(ctx context.Context, objects []SnapshotObject, firstOnly bool) (SnapshotCommit, error) {
	if w == nil || w.state == nil || ctx == nil || len(objects) > 16383 {
		return SnapshotCommit{}, ErrSnapshot
	}
	if err := ctx.Err(); err != nil {
		return SnapshotCommit{}, err
	}
	s := w.state
	if !s.mu.TryLock() {
		return SnapshotCommit{}, ErrBusy
	}
	defer s.mu.Unlock()
	store := s.directory.StoreID()
	release, err := appstorebudget.TryAcquire(store)
	if err != nil {
		return SnapshotCommit{}, ErrBusy
	}
	defer release()
	tx, err := s.directory.Lock()
	if err != nil {
		if errors.Is(err, appstorefile.ErrBusy) {
			return SnapshotCommit{}, ErrBusy
		}
		return SnapshotCommit{}, err
	}
	defer tx.Close()
	state, err := writerRead(ctx, s.transport, store)
	if err != nil {
		return SnapshotCommit{}, err
	}
	state, err = writerReconcileReservations(ctx, tx, s.transport, state)
	if err != nil {
		return SnapshotCommit{}, err
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
		return SnapshotCommit{}, ErrSnapshot
	}
	for _, o := range objects {
		if o.ObjectID == ([16]byte{}) || (o.Source == nil) == (o.memory == nil) || !validMedia(o.MediaType) {
			return SnapshotCommit{}, ErrSnapshot
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
			return SnapshotCommit{}, ErrSnapshot
		}
	}
	if err := ctx.Err(); err != nil {
		return SnapshotCommit{}, err
	}
	req, err := appstoreanchorrequest.PlanReservation(state, entry)
	if err != nil {
		return SnapshotCommit{}, err
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
	s.master.state.mu.Lock()
	salts := s.master.state.salts
	s.master.state.mu.Unlock()
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
			return SnapshotCommit{}, ErrSnapshot
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
	sealHash, sealErr := s.master.sealWriterSnapshot(ctx, h, prepared, candidate)
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
	_, checkErr := s.master.checkSnapshot(ctx, pinned, ExpectedSnapshot{StoreID: store, SnapshotID: snapshot, EncodedHash: sealHash})
	closeErr = pinned.Close()
	if checkErr != nil {
		return SnapshotCommit{}, checkErr
	}
	if closeErr != nil {
		return SnapshotCommit{}, closeErr
	}
	reserved, ok := reserve.ProposedState()
	if !ok {
		return SnapshotCommit{}, ErrSnapshot
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
		return SnapshotCommit{}, ErrSnapshot
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
func (w *SnapshotWriter) Recover(ctx context.Context) (SnapshotCommit, error) {
	if w == nil || w.state == nil || ctx == nil {
		return SnapshotCommit{}, ErrSnapshot
	}
	if err := ctx.Err(); err != nil {
		return SnapshotCommit{}, err
	}
	s := w.state
	if !s.mu.TryLock() {
		return SnapshotCommit{}, ErrBusy
	}
	defer s.mu.Unlock()
	release, err := appstorebudget.TryAcquire(s.directory.StoreID())
	if err != nil {
		return SnapshotCommit{}, ErrBusy
	}
	defer release()
	tx, err := s.directory.Lock()
	if err != nil {
		if errors.Is(err, appstorefile.ErrBusy) {
			return SnapshotCommit{}, ErrBusy
		}
		return SnapshotCommit{}, err
	}
	defer tx.Close()
	anchor, err := writerRead(ctx, s.transport, s.directory.StoreID())
	if err != nil {
		return SnapshotCommit{}, err
	}
	anchor, err = writerReconcileReservations(ctx, tx, s.transport, anchor)
	if err != nil {
		return SnapshotCommit{}, err
	}
	if err := ctx.Err(); err != nil {
		return SnapshotCommit{}, err
	}
	jf, err := tx.Journal()
	if err != nil {
		return SnapshotCommit{}, ErrWriterPending
	}
	prefix, err := appstorejournal.InspectPrefix(anchor, jf)
	if err != nil {
		_ = jf.Close()
		return SnapshotCommit{}, ErrWriterPending
	}
	if _, err = jf.Seek(0, io.SeekEnd); err != nil {
		_ = jf.Close()
		return SnapshotCommit{}, ErrWriterPending
	}
	eof, err := jf.Seek(0, io.SeekCurrent)
	_ = jf.Close()
	if err != nil || eof != int64(prefix.Count())*appstorejournal.Size || prefix.Count() == 0 {
		return SnapshotCommit{}, ErrWriterPending
	}
	jf, err = tx.Journal()
	if err != nil {
		return SnapshotCommit{}, ErrWriterPending
	}
	_, err = jf.Seek(int64(prefix.Count()-1)*appstorejournal.Size, io.SeekStart)
	var rawEntry [appstorejournal.Size]byte
	if err == nil {
		_, err = io.ReadFull(jf, rawEntry[:])
	}
	_ = jf.Close()
	if err != nil {
		return SnapshotCommit{}, ErrWriterPending
	}
	entry, err := appstorejournal.ParseEntry(rawEntry[:], prefix.Count()-1)
	if err != nil {
		return SnapshotCommit{}, ErrWriterPending
	}
	txn, snapshot := entry.TransactionID(), entry.SnapshotID()
	rawIntent, err := tx.LoadIntent(txn)
	if errors.Is(err, appstorefile.ErrMissing) {
		return SnapshotCommit{State: anchor}, ErrWriterBurned
	}
	if err != nil {
		return SnapshotCommit{}, ErrWriterPending
	}
	intent, err := appstoreanchorrequest.ParseIntent(rawIntent[:], anchor.StoreID())
	if err != nil {
		return SnapshotCommit{}, ErrWriterPending
	}
	req, ok := intent.Request()
	if !ok {
		return SnapshotCommit{}, ErrWriterPending
	}
	proposed, ok := req.ProposedState()
	if !ok || proposed.CommittedSnapshotID() != snapshot || proposed.CommittedTransactionID() != txn || proposed.JournalCount() != prefix.Count() || proposed.JournalHead() != prefix.Head() {
		return SnapshotCommit{}, ErrWriterPending
	}
	expected, ok := req.ExpectedStateHash()
	if !ok {
		return SnapshotCommit{}, ErrWriterPending
	}
	reserved := anchor.Hash() == expected
	committed := anchor.Bytes() == proposed.Bytes()
	if !reserved && !committed {
		return SnapshotCommit{}, ErrWriterPending
	}
	quarantined, quarantineErr := writerQuarantined(tx, snapshot)
	if quarantineErr != nil {
		return SnapshotCommit{}, ErrWriterPending
	}
	if quarantined {
		return SnapshotCommit{State: anchor}, ErrWriterBurned
	}
	var f *os.File
	candidatePresent := true
	f, err = tx.OpenCandidate(snapshot)
	if errors.Is(err, appstorefile.ErrMissing) && committed {
		candidatePresent = false
		f, err = tx.OpenSnapshot(snapshot)
	}
	if err != nil {
		return SnapshotCommit{}, ErrWriterPending
	}
	check, checkErr := s.master.checkSnapshot(ctx, f, ExpectedSnapshot{StoreID: anchor.StoreID(), SnapshotID: snapshot, EncodedHash: proposed.CommittedFileHash()})
	closeErr := f.Close()
	if checkErr != nil || closeErr != nil || !check.Valid() {
		return SnapshotCommit{}, ErrWriterPending
	}
	store := anchor.StoreID()
	reservedState, proofErr := s.recoverPredecessor(ctx, tx, proposed, check)
	if proofErr != nil || expected != reservedState.Hash() {
		return SnapshotCommit{}, ErrWriterPending
	}
	if reserved {
		if err := tx.SyncCandidate(snapshot); err != nil {
			return SnapshotCommit{}, ErrWriterPending
		}
		if anchor.Bytes() != reservedState.Bytes() {
			return SnapshotCommit{}, ErrWriterPending
		}
		if err := ctx.Err(); err != nil {
			return SnapshotCommit{}, err
		}
		loaded, loadErr := tx.LoadIntent(txn)
		if loadErr != nil || loaded != rawIntent {
			return SnapshotCommit{}, ErrWriterPending
		}
		reply, classification, submitErr := s.transport.Submit(ctx, req)
		if writerSubmissionRejected(req, reply, classification, submitErr) {
			return SnapshotCommit{}, ErrWriterRejected
		}
		anchor, err = writerRead(ctx, s.transport, store)
		if err != nil || anchor.Bytes() != proposed.Bytes() {
			return SnapshotCommit{}, ErrWriterPending
		}
	} else if anchor.Bytes() != proposed.Bytes() {
		return SnapshotCommit{}, ErrWriterPending
	}
	out := SnapshotCommit{State: proposed, EncodedHash: proposed.CommittedFileHash()}
	for _, ent := range check.Catalog().Entries() {
		ref, e := appstoreref.New(anchor.StoreID(), ent.ObjectID(), ent.VersionID(), snapshot)
		if e != nil {
			return SnapshotCommit{}, ErrWriterPending
		}
		out.Refs = append(out.Refs, ref)
	}
	if err := ctx.Err(); err != nil {
		return SnapshotCommit{}, err
	}
	if candidatePresent {
		if err := tx.Publish(snapshot); err != nil {
			return out, ErrWriterPointerLag
		}
	}
	var tuple [64]byte
	copy(tuple[:16], snapshot[:])
	hash := proposed.CommittedFileHash()
	copy(tuple[16:48], hash[:])
	copy(tuple[48:], txn[:])
	if err := tx.Pointer(tuple); err != nil {
		return out, ErrWriterPointerLag
	}
	return out, nil
}

func writerReconcileReservations(ctx context.Context, tx *appstorefile.Transaction, transport *appstoreanchortls.Writer, observed appstoreanchorstate.State) (appstoreanchorstate.State, error) {
	if ctx == nil || tx == nil || transport == nil || !observed.Valid() {
		return appstoreanchorstate.State{}, ErrWriterPending
	}
	journal, err := tx.Journal()
	if err != nil {
		return appstoreanchorstate.State{}, err
	}
	defer journal.Close()
	revision, err := appstorefile.Stat(journal)
	if err != nil {
		return appstoreanchorstate.State{}, err
	}
	if revision.Size < 0 || revision.Size > 40*int64(appstoreanchorstate.MaxReservations) || revision.Size%40 != 0 {
		return appstoreanchorstate.State{}, ErrWriterPending
	}
	localTotal := uint64(revision.Size / 40)
	if localTotal < observed.JournalCount() {
		return appstoreanchorstate.State{}, ErrWriterPending
	}
	if _, err = journal.Seek(0, io.SeekStart); err != nil {
		return appstoreanchorstate.State{}, err
	}
	if _, err = appstorejournal.InspectPrefix(observed, journal); err != nil {
		return appstoreanchorstate.State{}, ErrWriterPending
	}
	if err = tx.SyncJournal(); err != nil {
		return appstoreanchorstate.State{}, err
	}
	state := observed
	var raw [appstorejournal.Size]byte
	// Reservations before the committed cursor are burned if they have no
	// corresponding intent. Valid intents are left for normal recovery.
	for index := uint64(0); index < state.JournalCount(); index++ {
		if err = ctx.Err(); err != nil {
			return appstoreanchorstate.State{}, err
		}
		if _, err = journal.Seek(int64(index*appstorejournal.Size), io.SeekStart); err != nil {
			return appstoreanchorstate.State{}, err
		}
		if _, err = io.ReadFull(journal, raw[:]); err != nil {
			return appstoreanchorstate.State{}, ErrWriterPending
		}
		entry, parseErr := appstorejournal.ParseEntry(raw[:], index)
		if parseErr != nil {
			return appstoreanchorstate.State{}, ErrWriterPending
		}
		if entry.SnapshotID() == state.CommittedSnapshotID() {
			if entry.TransactionID() != state.CommittedTransactionID() {
				return appstoreanchorstate.State{}, ErrWriterPending
			}
			continue
		}
		if _, intentErr := tx.LoadIntent(entry.TransactionID()); errors.Is(intentErr, appstorefile.ErrMissing) {
			if err = tx.Quarantine(entry.SnapshotID()); err != nil && !errors.Is(err, appstorefile.ErrMissing) {
				return appstoreanchorstate.State{}, err
			}
		} else if intentErr != nil {
			return appstoreanchorstate.State{}, ErrWriterPending
		}
	}
	for index := observed.JournalCount(); index < localTotal; index++ {
		if err = ctx.Err(); err != nil {
			return appstoreanchorstate.State{}, err
		}
		if _, err = journal.Seek(int64(index*appstorejournal.Size), io.SeekStart); err != nil {
			return appstoreanchorstate.State{}, err
		}
		if _, err = io.ReadFull(journal, raw[:]); err != nil {
			return appstoreanchorstate.State{}, ErrWriterPending
		}
		entry, parseErr := appstorejournal.ParseEntry(raw[:], index)
		if parseErr != nil {
			return appstoreanchorstate.State{}, ErrWriterPending
		}
		if _, err = journal.Seek(0, io.SeekStart); err != nil {
			return appstoreanchorstate.State{}, err
		}
		if _, err = appstorejournal.CheckFreshPair(state, journal, entry); err != nil {
			return appstoreanchorstate.State{}, ErrWriterPending
		}
		req, planErr := appstoreanchorrequest.PlanReservation(state, entry)
		if planErr != nil {
			return appstoreanchorstate.State{}, ErrWriterPending
		}
		if err = tx.Quarantine(entry.SnapshotID()); err != nil && !errors.Is(err, appstorefile.ErrMissing) {
			return appstoreanchorstate.State{}, err
		}
		fresh, readErr := writerRead(ctx, transport, state.StoreID())
		if readErr != nil {
			return appstoreanchorstate.State{}, readErr
		}
		proposed, _ := req.ProposedState()
		if fresh.Bytes() == proposed.Bytes() {
			state = fresh
		} else if fresh.Bytes() == state.Bytes() {
			state, err = writerMutate(ctx, transport, req, state)
			if err != nil {
				return appstoreanchorstate.State{}, err
			}
		} else {
			return appstoreanchorstate.State{}, ErrWriterPending
		}
	}
	fresh, readErr := writerRead(ctx, transport, state.StoreID())
	if readErr != nil {
		return appstoreanchorstate.State{}, readErr
	}
	if fresh.Bytes() != state.Bytes() {
		return appstoreanchorstate.State{}, ErrWriterPending
	}
	return fresh, nil
}

func writerRead(ctx context.Context, w *appstoreanchortls.Writer, store [16]byte) (appstoreanchorstate.State, error) {
	reply, err := w.Read(ctx)
	if err != nil {
		return appstoreanchorstate.State{}, err
	}
	if !reply.SignatureValid() || reply.Operation() != appstoreanchorreply.Read || reply.Outcome() != appstoreanchorreply.ReadState {
		return appstoreanchorstate.State{}, ErrSnapshot
	}
	state, ok := reply.State()
	if !ok || state.StoreID() != store {
		return appstoreanchorstate.State{}, ErrSnapshot
	}
	return state, nil
}
func writerSubmissionRejected(request appstoreanchorrequest.Request, reply appstoreanchorreply.Reply, classification appstoreanchorresult.MutationResult, err error) bool {
	if classification == appstoreanchorresult.ReportedRejected {
		return true
	}
	if err != nil || !reply.SignatureValid() || byte(reply.Operation()) != request.Operation() || reply.RequestID() != request.RequestID() || reply.StoreID() != request.StoreID() || reply.Outcome() != appstoreanchorreply.Rejected {
		return false
	}
	return true
}

func writerMutate(ctx context.Context, w *appstoreanchortls.Writer, req appstoreanchorrequest.Request, expected appstoreanchorstate.State) (appstoreanchorstate.State, error) {
	reply, classification, submitErr := w.Submit(ctx, req)
	if writerSubmissionRejected(req, reply, classification, submitErr) {
		return appstoreanchorstate.State{}, ErrWriterRejected
	}
	got, err := writerRead(ctx, w, req.StoreID())
	if err != nil {
		return appstoreanchorstate.State{}, err
	}
	proposed, _ := req.ProposedState()
	if got.Bytes() == proposed.Bytes() {
		return got, nil
	}
	if got.Bytes() != expected.Bytes() {
		return appstoreanchorstate.State{}, ErrWriterPending
	}
	reply, classification, submitErr = w.Submit(ctx, req)
	if writerSubmissionRejected(req, reply, classification, submitErr) {
		return appstoreanchorstate.State{}, ErrWriterRejected
	}
	got, err = writerRead(ctx, w, req.StoreID())
	if err != nil {
		return appstoreanchorstate.State{}, err
	}
	if got.Bytes() != proposed.Bytes() {
		return appstoreanchorstate.State{}, ErrWriterPending
	}
	return got, nil
}
func newWriterEntry(s appstoreanchorstate.State, store [16]byte) (appstorejournal.Entry, error) {
	var snap, txn [16]byte
	for snap == ([16]byte{}) || txn == ([16]byte{}) || snap == txn {
		if _, e := rand.Read(snap[:]); e != nil {
			return appstorejournal.Entry{}, e
		}
		if _, e := rand.Read(txn[:]); e != nil {
			return appstorejournal.Entry{}, e
		}
	}
	_ = store
	return appstorejournal.NewEntry(s.JournalCount(), snap, txn)
}

func writerIntentAt(tx *appstorefile.Transaction, store [16]byte, sequence uint64) (appstoreanchorrequest.Request, error) {
	var chosen appstoreanchorrequest.Request
	var found bool
	if tx == nil || store == ([16]byte{}) || sequence == 0 {
		return chosen, ErrWriterPending
	}
	err := tx.Entries("intents", func(name string) error {
		if len(name) != 36 || name[32:] != ".bin" {
			return ErrWriterPending
		}
		decoded, err := hex.DecodeString(name[:32])
		if err != nil || len(decoded) != 16 || hex.EncodeToString(decoded) != name[:32] {
			return ErrWriterPending
		}
		var txn [16]byte
		copy(txn[:], decoded)
		raw, err := tx.LoadIntent(txn)
		if err != nil {
			return ErrWriterPending
		}
		intent, err := appstoreanchorrequest.ParseIntent(raw[:], store)
		if err != nil {
			return ErrWriterPending
		}
		req, ok := intent.Request()
		if !ok {
			return ErrWriterPending
		}
		state, ok := req.ProposedState()
		if !ok {
			return ErrWriterPending
		}
		if state.Sequence() == sequence {
			if found {
				return ErrWriterPending
			}
			chosen, found = req, true
		}
		return nil
	})
	if err != nil {
		return appstoreanchorrequest.Request{}, err
	}
	if !found {
		return appstoreanchorrequest.Request{}, ErrWriterPending
	}
	return chosen, nil
}
func validMedia(s string) bool {
	if len(s) < 1 || len(s) > 15 {
		return false
	}
	slash := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '/' {
			if slash || i == 0 || i == len(s)-1 {
				return false
			}
			slash = true
		} else if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '.' && c != '+' && c != '-' {
			return false
		}
	}
	return true
}

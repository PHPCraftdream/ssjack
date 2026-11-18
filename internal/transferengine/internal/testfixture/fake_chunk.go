package testfixture

import (
	"context"
	"crypto/sha256"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlink"
	"github.com/PHPCraftdream/ssjack/internal/transferremote"
)

// VClock is a virtual clock: the fake advances it as bytes and sessions
// "take time", so measurements are exact and no test sleeps or waits on a
// timer.
type VClock struct {
	mu sync.Mutex
	t  time.Time
}

func NewVClock() *VClock { return &VClock{t: time.Unix(1_700_000_000, 0)} }

func (c *VClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *VClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// FakeStage is one chunk staging directory: the parts by range. A part whose
// data length differs from its range models a lying size.
type FakeStage struct {
	Parts map[transferlink.Range][]byte
}

// PartFailure scripts a failed stream or part session: the session reads cut
// bytes of its input first, then ends with err, or, when err is nil, as a link
// drop (a session without a remote exit status).
type PartFailure struct {
	Cut int64
	Err error
}

type GCCall struct {
	Parent  string
	Exclude string
}

// FakeChunkRemote extends FakeRemote with the chunked layer
// (transferremote.ChunkRemote) in memory: staging directories with parts,
// listing, assembly, garbage collection and disk space. Every method advances
// the virtual clock; bytes cost bps bytes per second, every session costs
// setup. Failures are scripted through the knobs below.
type FakeChunkRemote struct {
	*FakeRemote
	Clock *VClock
	Bps   int64
	Setup time.Duration

	cmu           sync.Mutex
	caps          transferremote.ChunkCaps
	stages        map[string]*FakeStage
	foreign       map[string]bool // listing and ensure see a foreign object
	ensureForeign map[string]bool // only EnsureStaging sees a foreign object
	overflowLists map[int]bool    // 1-based ListStaging call numbers that overflow
	diskAvail     int64
	diskOK        bool
	diskErr       error
	gcErr         error
	partLog       []transferlink.Range // every UploadPart call
	stored        []transferlink.Range // parts stored by UploadPart
	removed       [][]string
	gcLog         []GCCall
	listCalls     int
	streamCalls   int
	assembleCalls int
	publishCalls  int

	streamFault   func(n int) *PartFailure
	partFault     func(n int, rg transferlink.Range) *PartFailure
	onPart        func(n int, rg transferlink.Range) // before part n is handled
	assembleFault func(n int) error
	publishFault  func(n int) error
}

var _ transferremote.ChunkRemote = (*FakeChunkRemote)(nil)

func NewFakeChunkRemote(clock *VClock) *FakeChunkRemote {
	return &FakeChunkRemote{
		FakeRemote: NewFakeRemote(),
		Clock:      clock,
		Bps:        1 << 20,
		Setup:      100 * time.Millisecond,
		caps:       transferremote.ChunkCaps{Own: true, Read: transferremote.ReadDD, Mtime: transferremote.MtimeGNU, DF: true},
		stages:     map[string]*FakeStage{},
		foreign:    map[string]bool{},

		ensureForeign: map[string]bool{},
		overflowLists: map[int]bool{},
		diskAvail:     1 << 40,
		diskOK:        true,
	}
}

func StageErr(code int) error {
	return &transfercore.Error{Class: transfercore.ClassRemoteFailed, Message: "remote operation failed", ExitCode: code}
}

// Transit advances the clock by the time n bytes take at the link speed.
func (f *FakeChunkRemote) Transit(n int64) {
	if f.Bps > 0 && n > 0 {
		f.Clock.Advance(time.Duration(n) * time.Second / time.Duration(f.Bps))
	}
}

func (f *FakeChunkRemote) ChunkCaps() transferremote.ChunkCaps {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	return f.caps
}

// stageFor returns the stage of key or the remote error a template would exit
// with. The caller holds cmu.
func (f *FakeChunkRemote) stageFor(key string) (*FakeStage, error) {
	if f.foreign[key] {
		return nil, StageErr(transferremote.ExitStageForeign)
	}
	st, ok := f.stages[key]
	if !ok {
		return nil, StageErr(transferremote.ExitStageMissing)
	}
	return st, nil
}

func (f *FakeChunkRemote) EnsureStaging(ctx context.Context, parent, key string) (transferremote.StagingState, error) {
	f.Record("EnsureStaging")
	if err := f.CtxErr(ctx); err != nil {
		return 0, err
	}
	f.Clock.Advance(f.Setup)
	f.cmu.Lock()
	defer f.cmu.Unlock()
	if f.foreign[key] || f.ensureForeign[key] {
		return transferremote.StagingForeign, nil
	}
	if _, ok := f.stages[key]; ok {
		return transferremote.StagingReused, nil
	}
	f.stages[key] = &FakeStage{Parts: map[transferlink.Range][]byte{}}
	return transferremote.StagingCreated, nil
}

func (f *FakeChunkRemote) UploadPart(ctx context.Context, parent, key string, part transferlink.Range, src io.Reader) (transferremote.PartResult, error) {
	f.Record("UploadPart")
	f.cmu.Lock()
	f.partLog = append(f.partLog, part)
	n := len(f.partLog)
	hook, fault := f.onPart, f.partFault
	f.cmu.Unlock()
	if hook != nil {
		hook(n, part)
	}
	if err := f.CtxErr(ctx); err != nil {
		return transferremote.PartResult{}, err
	}
	f.Clock.Advance(f.Setup)
	f.cmu.Lock()
	_, err := f.stageFor(key)
	f.cmu.Unlock()
	if err != nil {
		return transferremote.PartResult{}, err
	}
	if fault != nil {
		if failure := fault(n, part); failure != nil {
			sent, _ := io.CopyN(io.Discard, src, failure.Cut)
			f.Transit(sent)
			if failure.Err != nil {
				return transferremote.PartResult{}, failure.Err
			}
			return transferremote.PartResult{}, transferremote.LinkFailure()
		}
	}
	data, err := io.ReadAll(io.LimitReader(src, part.Len))
	if err != nil {
		return transferremote.PartResult{}, err
	}
	f.Transit(int64(len(data)))
	if int64(len(data)) != part.Len {
		return transferremote.PartResult{Count: int64(len(data))}, nil
	}
	f.cmu.Lock()
	defer f.cmu.Unlock()
	if st, ok := f.stages[key]; ok {
		st.Parts[part] = data
	}
	f.stored = append(f.stored, part)
	return transferremote.PartResult{Count: part.Len, Stored: true}, nil
}

func (f *FakeChunkRemote) ListStaging(ctx context.Context, parent, key string, fileSize int64) (transferremote.StagingListing, error) {
	f.Record("ListStaging")
	if err := f.CtxErr(ctx); err != nil {
		return transferremote.StagingListing{}, err
	}
	f.Clock.Advance(f.Setup)
	f.cmu.Lock()
	defer f.cmu.Unlock()
	f.listCalls++
	st, err := f.stageFor(key)
	if err != nil {
		return transferremote.StagingListing{}, err
	}
	if f.overflowLists[f.listCalls] {
		return transferremote.StagingListing{Overflow: true}, nil
	}
	type entry struct {
		rng  transferlink.Range
		data []byte
	}
	entries := make([]entry, 0, len(st.Parts))
	for r, d := range st.Parts {
		entries = append(entries, entry{rng: r, data: d})
	}
	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i].rng, entries[j].rng
		if a.Off != b.Off {
			return a.Off < b.Off
		}
		return a.Len > b.Len
	})
	var listing transferremote.StagingListing
	var cursor int64
	for _, e := range entries {
		name, _ := transferlink.PartName(e.rng)
		if int64(len(e.data)) != e.rng.Len || e.rng.Off < cursor || e.rng.Off > fileSize || e.rng.Len > fileSize-e.rng.Off {
			listing.Remove = append(listing.Remove, name)
			continue
		}
		listing.Parts = append(listing.Parts, e.rng)
		cursor = e.rng.End()
	}
	return listing, nil
}

func (f *FakeChunkRemote) RemoveStagingEntries(ctx context.Context, parent, key string, names []string) error {
	f.Record("RemoveStagingEntries")
	if err := f.CtxErr(ctx); err != nil {
		return err
	}
	f.Clock.Advance(f.Setup)
	f.cmu.Lock()
	defer f.cmu.Unlock()
	f.removed = append(f.removed, append([]string(nil), names...))
	st, err := f.stageFor(key)
	if err != nil {
		return err
	}
	for r := range st.Parts {
		name, _ := transferlink.PartName(r)
		for _, n := range names {
			if n == name {
				delete(st.Parts, r)
			}
		}
	}
	return nil
}

func (f *FakeChunkRemote) AssembleStaging(ctx context.Context, parent, key string, parts []transferlink.Range, size int64, executable bool) (transferremote.Assembled, error) {
	f.Record("AssembleStaging")
	if err := f.CtxErr(ctx); err != nil {
		return transferremote.Assembled{}, err
	}
	f.cmu.Lock()
	f.assembleCalls++
	n := f.assembleCalls
	fault := f.assembleFault
	f.cmu.Unlock()
	f.Clock.Advance(f.Setup)
	if fault != nil {
		if err := fault(n); err != nil {
			return transferremote.Assembled{}, err
		}
	}
	ordered := append([]transferlink.Range(nil), parts...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Off < ordered[j].Off })
	f.cmu.Lock()
	st, err := f.stageFor(key)
	if err != nil {
		f.cmu.Unlock()
		return transferremote.Assembled{}, err
	}
	var data []byte
	for _, p := range ordered {
		d, ok := st.Parts[p]
		if !ok {
			f.cmu.Unlock()
			return transferremote.Assembled{}, StageErr(transferremote.ExitPartMissing)
		}
		data = append(data, d...)
	}
	f.cmu.Unlock()
	path := parent + "/.ssjack-transfer-" + key + "/assembled." + strconv.Itoa(n) + ".tmp"
	f.FakeRemote.Put(path, data)
	return transferremote.Assembled{Path: path, Size: int64(len(data)), SHA256: sha256.Sum256(data)}, nil
}

func (f *FakeChunkRemote) RemoveChunkStaging(ctx context.Context, parent, key string) error {
	f.Record("RemoveChunkStaging")
	if err := f.CtxErr(ctx); err != nil {
		return err
	}
	f.Clock.Advance(f.Setup)
	f.cmu.Lock()
	foreign := f.foreign[key] || f.ensureForeign[key]
	if !foreign {
		delete(f.stages, key)
	}
	f.cmu.Unlock()
	if foreign {
		return StageErr(transferremote.ExitStageForeign)
	}
	prefix := parent + "/.ssjack-transfer-" + key + "/"
	f.FakeRemote.Mu.Lock()
	defer f.FakeRemote.Mu.Unlock()
	for p := range f.FakeRemote.Files {
		if strings.HasPrefix(p, prefix) {
			delete(f.FakeRemote.Files, p)
		}
	}
	return nil
}

func (f *FakeChunkRemote) CollectStaging(ctx context.Context, parent, excludeKey string) (int, error) {
	f.Record("CollectStaging")
	if err := f.CtxErr(ctx); err != nil {
		return 0, err
	}
	f.cmu.Lock()
	defer f.cmu.Unlock()
	f.gcLog = append(f.gcLog, GCCall{Parent: parent, Exclude: excludeKey})
	return 0, f.gcErr
}

func (f *FakeChunkRemote) DiskAvailable(ctx context.Context, parent string) (int64, bool, error) {
	f.Record("DiskAvailable")
	if err := f.CtxErr(ctx); err != nil {
		return 0, false, err
	}
	f.cmu.Lock()
	defer f.cmu.Unlock()
	return f.diskAvail, f.diskOK, f.diskErr
}

func (f *FakeChunkRemote) StatSource(ctx context.Context, path string) (transferremote.SourceStat, error) {
	f.Record("StatSource")
	return transferremote.SourceStat{}, transfercore.Fail(transfercore.ClassUnsupportedRemote, "remote target is missing required transfer tools")
}

func (f *FakeChunkRemote) ReadRange(ctx context.Context, path string, part transferlink.Range, grid, fileSize int64, dst io.Writer) (int64, error) {
	f.Record("ReadRange")
	return 0, transfercore.Fail(transfercore.ClassUnsupportedRemote, "remote target is missing required transfer tools")
}

// WriteFile is the whole-stream upload, with scripted failures and the time
// the bytes take on the virtual link.
func (f *FakeChunkRemote) WriteFile(ctx context.Context, path string, src io.Reader, executable bool) (int64, error) {
	f.cmu.Lock()
	f.streamCalls++
	n := f.streamCalls
	fault := f.streamFault
	f.cmu.Unlock()
	var failure *PartFailure
	if fault != nil {
		failure = fault(n)
	}
	if failure == nil {
		written, err := f.FakeRemote.WriteFile(ctx, path, src, executable)
		f.Transit(written)
		return written, err
	}
	f.Record("WriteFile")
	if err := f.CtxErr(ctx); err != nil {
		return 0, err
	}
	sent, _ := io.CopyN(io.Discard, src, failure.Cut)
	f.Transit(sent)
	if failure.Err != nil {
		return sent, failure.Err
	}
	return sent, transferremote.LinkFailure()
}

func (f *FakeChunkRemote) PublishFile(ctx context.Context, staging, dest string, overwrite bool) error {
	f.cmu.Lock()
	f.publishCalls++
	n := f.publishCalls
	fault := f.publishFault
	f.cmu.Unlock()
	if fault != nil {
		if err := fault(n); err != nil {
			f.Record("PublishFile")
			return err
		}
	}
	return f.FakeRemote.PublishFile(ctx, staging, dest, overwrite)
}

// SeedStage creates the staging directory of key with parts, as a previous
// process left it.
func (f *FakeChunkRemote) SeedStage(key string, parts map[transferlink.Range][]byte) {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	st := &FakeStage{Parts: map[transferlink.Range][]byte{}}
	for r, d := range parts {
		st.Parts[r] = append([]byte(nil), d...)
	}
	f.stages[key] = st
}

// DropStage removes the staging directory of key behind the engine's back.
func (f *FakeChunkRemote) DropStage(key string) {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	delete(f.stages, key)
}

func (f *FakeChunkRemote) HasStage(key string) bool {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	_, ok := f.stages[key]
	return ok
}

func (f *FakeChunkRemote) StageCount() int {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	return len(f.stages)
}

// StageParts returns the parts held by the staging of key, ordered by offset.
func (f *FakeChunkRemote) StageParts(key string) []transferlink.Range {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	st, ok := f.stages[key]
	if !ok {
		return nil
	}
	out := make([]transferlink.Range, 0, len(st.Parts))
	for r := range st.Parts {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Off < out[j].Off })
	return out
}

func (f *FakeChunkRemote) PartAttempts() []transferlink.Range {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	return append([]transferlink.Range(nil), f.partLog...)
}

func (f *FakeChunkRemote) StoredParts() []transferlink.Range {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	return append([]transferlink.Range(nil), f.stored...)
}

func (f *FakeChunkRemote) SetDisk(avail int64, ok bool) {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	f.diskAvail, f.diskOK = avail, ok
}

func (f *FakeChunkRemote) SetCaps(c transferremote.ChunkCaps) {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	f.caps = c
}

// SetForeign marks (or clears) a foreign staging object seen by listing and
// ensure. Exposed for test migrants that script foreign-stage scenarios.
func (f *FakeChunkRemote) SetForeign(key string, foreign bool) {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	f.foreign[key] = foreign
}

// IsForeign reports whether listing and ensure see a foreign object at key.
func (f *FakeChunkRemote) IsForeign(key string) bool {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	return f.foreign[key]
}

// SetEnsureForeign marks (or clears) a foreign object only EnsureStaging sees.
func (f *FakeChunkRemote) SetEnsureForeign(key string, foreign bool) {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	f.ensureForeign[key] = foreign
}

// SetOverflowList marks the 1-based ListStaging call n as overflowing.
func (f *FakeChunkRemote) SetOverflowList(n int, overflow bool) {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	f.overflowLists[n] = overflow
}

// SetDiskErr scripts the DiskAvailable error.
func (f *FakeChunkRemote) SetDiskErr(err error) {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	f.diskErr = err
}

// SetGCErr scripts the CollectStaging error.
func (f *FakeChunkRemote) SetGCErr(err error) {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	f.gcErr = err
}

// SetStreamFault scripts the whole-stream WriteFile failures.
func (f *FakeChunkRemote) SetStreamFault(fault func(n int) *PartFailure) {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	f.streamFault = fault
}

// SetPartFault scripts the UploadPart failures.
func (f *FakeChunkRemote) SetPartFault(fault func(n int, rg transferlink.Range) *PartFailure) {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	f.partFault = fault
}

// SetOnPart sets the hook run before part n is handled.
func (f *FakeChunkRemote) SetOnPart(hook func(n int, rg transferlink.Range)) {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	f.onPart = hook
}

// SetAssembleFault scripts the AssembleStaging failures.
func (f *FakeChunkRemote) SetAssembleFault(fault func(n int) error) {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	f.assembleFault = fault
}

// SetPublishFault scripts the PublishFile failures.
func (f *FakeChunkRemote) SetPublishFault(fault func(n int) error) {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	f.publishFault = fault
}

// RemovedEntries returns every RemoveStagingEntries name list, in call order.
func (f *FakeChunkRemote) RemovedEntries() [][]string {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	return append([][]string(nil), f.removed...)
}

// GCLog returns every CollectStaging call, in call order.
func (f *FakeChunkRemote) GCLog() []GCCall {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	return append([]GCCall(nil), f.gcLog...)
}

// ListCallCount returns the number of ListStaging calls.
func (f *FakeChunkRemote) ListCallCount() int {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	return f.listCalls
}

// StreamCallCount returns the number of whole-stream WriteFile calls.
func (f *FakeChunkRemote) StreamCallCount() int {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	return f.streamCalls
}

// AssembleCallCount returns the number of AssembleStaging calls.
func (f *FakeChunkRemote) AssembleCallCount() int {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	return f.assembleCalls
}

// PublishCallCount returns the number of PublishFile calls.
func (f *FakeChunkRemote) PublishCallCount() int {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	return f.publishCalls
}

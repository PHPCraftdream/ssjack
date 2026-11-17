package transferengine

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

// vclock is a virtual clock: the fake advances it as bytes and sessions
// "take time", so measurements are exact and no test sleeps or waits on a
// timer.
type vclock struct {
	mu sync.Mutex
	t  time.Time
}

func newVClock() *vclock { return &vclock{t: time.Unix(1_700_000_000, 0)} }

func (c *vclock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *vclock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// fakeStage is one chunk staging directory: the parts by range. A part whose
// data length differs from its range models a lying size.
type fakeStage struct {
	parts map[transferlink.Range][]byte
}

// partFailure scripts a failed stream or part session: the session reads cut
// bytes of its input first, then ends with err, or, when err is nil, as a link
// drop (a session without a remote exit status).
type partFailure struct {
	cut int64
	err error
}

type gcCall struct {
	parent  string
	exclude string
}

// fakeChunkRemote extends fakeRemote with the chunked layer
// (transferremote.ChunkRemote) in memory: staging directories with parts,
// listing, assembly, garbage collection and disk space. Every method advances
// the virtual clock; bytes cost bps bytes per second, every session costs
// setup. Failures are scripted through the knobs below.
type fakeChunkRemote struct {
	*fakeRemote
	clock *vclock
	bps   int64
	setup time.Duration

	cmu           sync.Mutex
	caps          transferremote.ChunkCaps
	stages        map[string]*fakeStage
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
	gcLog         []gcCall
	listCalls     int
	streamCalls   int
	assembleCalls int
	publishCalls  int

	streamFault   func(n int) *partFailure
	partFault     func(n int, rg transferlink.Range) *partFailure
	onPart        func(n int, rg transferlink.Range) // before part n is handled
	assembleFault func(n int) error
	publishFault  func(n int) error
}

var _ transferremote.ChunkRemote = (*fakeChunkRemote)(nil)

func newFakeChunkRemote(clock *vclock) *fakeChunkRemote {
	return &fakeChunkRemote{
		fakeRemote: newFakeRemote(),
		clock:      clock,
		bps:        1 << 20,
		setup:      100 * time.Millisecond,
		caps:       transferremote.ChunkCaps{Own: true, Read: transferremote.ReadDD, Mtime: transferremote.MtimeGNU, DF: true},
		stages:     map[string]*fakeStage{},
		foreign:    map[string]bool{},

		ensureForeign: map[string]bool{},
		overflowLists: map[int]bool{},
		diskAvail:     1 << 40,
		diskOK:        true,
	}
}

func stageErr(code int) error {
	return &transfercore.Error{Class: transfercore.ClassRemoteFailed, Message: "remote operation failed", ExitCode: code}
}

// transit advances the clock by the time n bytes take at the link speed.
func (f *fakeChunkRemote) transit(n int64) {
	if f.bps > 0 && n > 0 {
		f.clock.Advance(time.Duration(n) * time.Second / time.Duration(f.bps))
	}
}

func (f *fakeChunkRemote) ChunkCaps() transferremote.ChunkCaps {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	return f.caps
}

// stageFor returns the stage of key or the remote error a template would exit
// with. The caller holds cmu.
func (f *fakeChunkRemote) stageFor(key string) (*fakeStage, error) {
	if f.foreign[key] {
		return nil, stageErr(transferremote.ExitStageForeign)
	}
	st, ok := f.stages[key]
	if !ok {
		return nil, stageErr(transferremote.ExitStageMissing)
	}
	return st, nil
}

func (f *fakeChunkRemote) EnsureStaging(ctx context.Context, parent, key string) (transferremote.StagingState, error) {
	f.record("EnsureStaging")
	if err := f.ctxErr(ctx); err != nil {
		return 0, err
	}
	f.clock.Advance(f.setup)
	f.cmu.Lock()
	defer f.cmu.Unlock()
	if f.foreign[key] || f.ensureForeign[key] {
		return transferremote.StagingForeign, nil
	}
	if _, ok := f.stages[key]; ok {
		return transferremote.StagingReused, nil
	}
	f.stages[key] = &fakeStage{parts: map[transferlink.Range][]byte{}}
	return transferremote.StagingCreated, nil
}

func (f *fakeChunkRemote) UploadPart(ctx context.Context, parent, key string, part transferlink.Range, src io.Reader) (transferremote.PartResult, error) {
	f.record("UploadPart")
	f.cmu.Lock()
	f.partLog = append(f.partLog, part)
	n := len(f.partLog)
	hook, fault := f.onPart, f.partFault
	f.cmu.Unlock()
	if hook != nil {
		hook(n, part)
	}
	if err := f.ctxErr(ctx); err != nil {
		return transferremote.PartResult{}, err
	}
	f.clock.Advance(f.setup)
	f.cmu.Lock()
	_, err := f.stageFor(key)
	f.cmu.Unlock()
	if err != nil {
		return transferremote.PartResult{}, err
	}
	if fault != nil {
		if failure := fault(n, part); failure != nil {
			sent, _ := io.CopyN(io.Discard, src, failure.cut)
			f.transit(sent)
			if failure.err != nil {
				return transferremote.PartResult{}, failure.err
			}
			return transferremote.PartResult{}, transferremote.LinkFailure()
		}
	}
	data, err := io.ReadAll(io.LimitReader(src, part.Len))
	if err != nil {
		return transferremote.PartResult{}, err
	}
	f.transit(int64(len(data)))
	if int64(len(data)) != part.Len {
		return transferremote.PartResult{Count: int64(len(data))}, nil
	}
	f.cmu.Lock()
	defer f.cmu.Unlock()
	if st, ok := f.stages[key]; ok {
		st.parts[part] = data
	}
	f.stored = append(f.stored, part)
	return transferremote.PartResult{Count: part.Len, Stored: true}, nil
}

func (f *fakeChunkRemote) ListStaging(ctx context.Context, parent, key string, fileSize int64) (transferremote.StagingListing, error) {
	f.record("ListStaging")
	if err := f.ctxErr(ctx); err != nil {
		return transferremote.StagingListing{}, err
	}
	f.clock.Advance(f.setup)
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
	entries := make([]entry, 0, len(st.parts))
	for r, d := range st.parts {
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

func (f *fakeChunkRemote) RemoveStagingEntries(ctx context.Context, parent, key string, names []string) error {
	f.record("RemoveStagingEntries")
	if err := f.ctxErr(ctx); err != nil {
		return err
	}
	f.clock.Advance(f.setup)
	f.cmu.Lock()
	defer f.cmu.Unlock()
	f.removed = append(f.removed, append([]string(nil), names...))
	st, err := f.stageFor(key)
	if err != nil {
		return err
	}
	for r := range st.parts {
		name, _ := transferlink.PartName(r)
		for _, n := range names {
			if n == name {
				delete(st.parts, r)
			}
		}
	}
	return nil
}

func (f *fakeChunkRemote) AssembleStaging(ctx context.Context, parent, key string, parts []transferlink.Range, size int64, executable bool) (transferremote.Assembled, error) {
	f.record("AssembleStaging")
	if err := f.ctxErr(ctx); err != nil {
		return transferremote.Assembled{}, err
	}
	f.cmu.Lock()
	f.assembleCalls++
	n := f.assembleCalls
	fault := f.assembleFault
	f.cmu.Unlock()
	f.clock.Advance(f.setup)
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
		d, ok := st.parts[p]
		if !ok {
			f.cmu.Unlock()
			return transferremote.Assembled{}, stageErr(transferremote.ExitPartMissing)
		}
		data = append(data, d...)
	}
	f.cmu.Unlock()
	path := parent + "/.ssjack-transfer-" + key + "/assembled." + strconv.Itoa(n) + ".tmp"
	f.fakeRemote.put(path, data)
	return transferremote.Assembled{Path: path, Size: int64(len(data)), SHA256: sha256.Sum256(data)}, nil
}

func (f *fakeChunkRemote) RemoveChunkStaging(ctx context.Context, parent, key string) error {
	f.record("RemoveChunkStaging")
	if err := f.ctxErr(ctx); err != nil {
		return err
	}
	f.clock.Advance(f.setup)
	f.cmu.Lock()
	foreign := f.foreign[key] || f.ensureForeign[key]
	if !foreign {
		delete(f.stages, key)
	}
	f.cmu.Unlock()
	if foreign {
		return stageErr(transferremote.ExitStageForeign)
	}
	prefix := parent + "/.ssjack-transfer-" + key + "/"
	f.fakeRemote.mu.Lock()
	defer f.fakeRemote.mu.Unlock()
	for p := range f.fakeRemote.files {
		if strings.HasPrefix(p, prefix) {
			delete(f.fakeRemote.files, p)
		}
	}
	return nil
}

func (f *fakeChunkRemote) CollectStaging(ctx context.Context, parent, excludeKey string) (int, error) {
	f.record("CollectStaging")
	if err := f.ctxErr(ctx); err != nil {
		return 0, err
	}
	f.cmu.Lock()
	defer f.cmu.Unlock()
	f.gcLog = append(f.gcLog, gcCall{parent: parent, exclude: excludeKey})
	return 0, f.gcErr
}

func (f *fakeChunkRemote) DiskAvailable(ctx context.Context, parent string) (int64, bool, error) {
	f.record("DiskAvailable")
	if err := f.ctxErr(ctx); err != nil {
		return 0, false, err
	}
	f.cmu.Lock()
	defer f.cmu.Unlock()
	return f.diskAvail, f.diskOK, f.diskErr
}

func (f *fakeChunkRemote) StatSource(ctx context.Context, path string) (transferremote.SourceStat, error) {
	f.record("StatSource")
	return transferremote.SourceStat{}, transfercore.Fail(transfercore.ClassUnsupportedRemote, "remote target is missing required transfer tools")
}

func (f *fakeChunkRemote) ReadRange(ctx context.Context, path string, part transferlink.Range, grid, fileSize int64, dst io.Writer) (int64, error) {
	f.record("ReadRange")
	return 0, transfercore.Fail(transfercore.ClassUnsupportedRemote, "remote target is missing required transfer tools")
}

// WriteFile is the whole-stream upload, with scripted failures and the time
// the bytes take on the virtual link.
func (f *fakeChunkRemote) WriteFile(ctx context.Context, path string, src io.Reader, executable bool) (int64, error) {
	f.cmu.Lock()
	f.streamCalls++
	n := f.streamCalls
	fault := f.streamFault
	f.cmu.Unlock()
	var failure *partFailure
	if fault != nil {
		failure = fault(n)
	}
	if failure == nil {
		written, err := f.fakeRemote.WriteFile(ctx, path, src, executable)
		f.transit(written)
		return written, err
	}
	f.record("WriteFile")
	if err := f.ctxErr(ctx); err != nil {
		return 0, err
	}
	sent, _ := io.CopyN(io.Discard, src, failure.cut)
	f.transit(sent)
	if failure.err != nil {
		return sent, failure.err
	}
	return sent, transferremote.LinkFailure()
}

func (f *fakeChunkRemote) PublishFile(ctx context.Context, staging, dest string, overwrite bool) error {
	f.cmu.Lock()
	f.publishCalls++
	n := f.publishCalls
	fault := f.publishFault
	f.cmu.Unlock()
	if fault != nil {
		if err := fault(n); err != nil {
			f.record("PublishFile")
			return err
		}
	}
	return f.fakeRemote.PublishFile(ctx, staging, dest, overwrite)
}

// seedStage creates the staging directory of key with parts, as a previous
// process left it.
func (f *fakeChunkRemote) seedStage(key string, parts map[transferlink.Range][]byte) {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	st := &fakeStage{parts: map[transferlink.Range][]byte{}}
	for r, d := range parts {
		st.parts[r] = append([]byte(nil), d...)
	}
	f.stages[key] = st
}

// dropStage removes the staging directory of key behind the engine's back.
func (f *fakeChunkRemote) dropStage(key string) {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	delete(f.stages, key)
}

func (f *fakeChunkRemote) hasStage(key string) bool {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	_, ok := f.stages[key]
	return ok
}

func (f *fakeChunkRemote) stageCount() int {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	return len(f.stages)
}

// stageParts returns the parts held by the staging of key, ordered by offset.
func (f *fakeChunkRemote) stageParts(key string) []transferlink.Range {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	st, ok := f.stages[key]
	if !ok {
		return nil
	}
	out := make([]transferlink.Range, 0, len(st.parts))
	for r := range st.parts {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Off < out[j].Off })
	return out
}

func (f *fakeChunkRemote) partAttempts() []transferlink.Range {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	return append([]transferlink.Range(nil), f.partLog...)
}

func (f *fakeChunkRemote) storedParts() []transferlink.Range {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	return append([]transferlink.Range(nil), f.stored...)
}

func (f *fakeChunkRemote) setDisk(avail int64, ok bool) {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	f.diskAvail, f.diskOK = avail, ok
}

func (f *fakeChunkRemote) setCaps(c transferremote.ChunkCaps) {
	f.cmu.Lock()
	defer f.cmu.Unlock()
	f.caps = c
}

package testfixture

import (
	"context"
	"io"
	"sync"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlink"
	"github.com/PHPCraftdream/ssjack/internal/transferremote"
)

// DLMTime is the whole-second modification time the fake reports for every
// remote file until a test changes it.
const DLMTime = 1_600_000_000

type DLRangeCall struct {
	Part transferlink.Range
	Grid int64
}

// FakeDownloadRemote adds the download side of the chunked layer (StatSource,
// ReadRange and a whole-stream ReadFile with scripted failures) to
// FakeChunkRemote, which keeps the upload side and the clock. Bytes cost the
// same virtual time as for uploads, every session costs the setup time.
type FakeDownloadRemote struct {
	*FakeChunkRemote

	dmu        sync.Mutex
	mtime      int64
	statCalls  int
	readCalls  int
	rangeCalls int
	rangeLog   []DLRangeCall

	statFault  func(n int) error                               // StatSource call n (1-based) fails with this error
	readFault  func(n int) *PartFailure                        // whole-stream ReadFile call n
	rangeFault func(n int, rg transferlink.Range) *PartFailure // ReadRange call n
	onStat     func(n int)                                     // before StatSource call n is answered
	onRange    func(n int, rg transferlink.Range)              // before ReadRange call n is handled
}

var _ transferremote.ChunkRemote = (*FakeDownloadRemote)(nil)

func NewFakeDownloadRemote(clock *VClock) *FakeDownloadRemote {
	return &FakeDownloadRemote{FakeChunkRemote: NewFakeChunkRemote(clock), mtime: DLMTime}
}

func (f *FakeDownloadRemote) SetMTime(m int64) {
	f.dmu.Lock()
	f.mtime = m
	f.dmu.Unlock()
}

func (f *FakeDownloadRemote) CurrentMTime() int64 {
	f.dmu.Lock()
	defer f.dmu.Unlock()
	return f.mtime
}

func (f *FakeDownloadRemote) StatCount() int {
	f.dmu.Lock()
	defer f.dmu.Unlock()
	return f.statCalls
}

func (f *FakeDownloadRemote) ReadCount() int {
	f.dmu.Lock()
	defer f.dmu.Unlock()
	return f.readCalls
}

// Ranges returns the part of every ReadRange call, in call order.
func (f *FakeDownloadRemote) Ranges() []transferlink.Range {
	f.dmu.Lock()
	defer f.dmu.Unlock()
	out := make([]transferlink.Range, len(f.rangeLog))
	for i, c := range f.rangeLog {
		out[i] = c.Part
	}
	return out
}

func (f *FakeDownloadRemote) RangeCalled() []DLRangeCall {
	f.dmu.Lock()
	defer f.dmu.Unlock()
	return append([]DLRangeCall(nil), f.rangeLog...)
}

// WriteInChunks writes data in small pieces, so a transfer crosses several
// write boundaries, and returns the bytes written.
func WriteInChunks(dst io.Writer, data []byte) (int64, error) {
	var n int64
	for len(data) > 0 {
		step := min(len(data), 4096)
		w, err := dst.Write(data[:step])
		n += int64(w)
		if err != nil {
			return n, err
		}
		data = data[step:]
	}
	return n, nil
}

func (f *FakeDownloadRemote) StatSource(ctx context.Context, path string) (transferremote.SourceStat, error) {
	f.Record("StatSource")
	if err := f.CtxErr(ctx); err != nil {
		return transferremote.SourceStat{}, err
	}
	f.dmu.Lock()
	f.statCalls++
	n := f.statCalls
	hook, fault := f.onStat, f.statFault
	f.dmu.Unlock()
	if hook != nil {
		hook(n)
	}
	f.Clock.Advance(f.Setup)
	if fault != nil {
		if err := fault(n); err != nil {
			return transferremote.SourceStat{}, err
		}
	}
	data, ok := f.Get(path)
	if !ok {
		return transferremote.SourceStat{}, transfercore.Fail(transfercore.ClassRefusedPath, "remote path was refused")
	}
	return transferremote.SourceStat{Size: int64(len(data)), MTime: f.CurrentMTime()}, nil
}

func (f *FakeDownloadRemote) ReadRange(ctx context.Context, path string, part transferlink.Range, grid, fileSize int64, dst io.Writer) (int64, error) {
	f.Record("ReadRange")
	f.dmu.Lock()
	f.rangeCalls++
	n := f.rangeCalls
	f.rangeLog = append(f.rangeLog, DLRangeCall{Part: part, Grid: grid})
	hook, fault := f.onRange, f.rangeFault
	f.dmu.Unlock()
	if hook != nil {
		hook(n, part)
	}
	if err := f.CtxErr(ctx); err != nil {
		return 0, err
	}
	f.Clock.Advance(f.Setup)
	data, ok := f.Get(path)
	if !ok {
		return 0, transfercore.Fail(transfercore.ClassRefusedPath, "remote path was refused")
	}
	var avail []byte
	if part.Off < int64(len(data)) {
		avail = data[part.Off:min(part.End(), int64(len(data)))]
	}
	var failure *PartFailure
	if fault != nil {
		failure = fault(n, part)
	}
	deliver := avail
	if failure != nil && failure.Cut < int64(len(deliver)) {
		deliver = deliver[:failure.Cut]
	}
	written, err := WriteInChunks(dst, deliver)
	f.Transit(written)
	if err != nil {
		return written, err
	}
	if failure != nil {
		if failure.Err != nil {
			return written, failure.Err
		}
		return written, transferremote.LinkFailure()
	}
	if written != part.Len {
		return written, transfercore.Fail(transfercore.ClassIntegrity, "remote range read returned an unexpected length")
	}
	return written, nil
}

// ReadFile is the whole-stream download with scripted failures: a failing
// call delivers cut bytes of the file, then ends with err or as a link drop.
func (f *FakeDownloadRemote) ReadFile(ctx context.Context, path string, dst io.Writer) (int64, error) {
	f.dmu.Lock()
	f.readCalls++
	n := f.readCalls
	fault := f.readFault
	f.dmu.Unlock()
	var failure *PartFailure
	if fault != nil {
		failure = fault(n)
	}
	if failure == nil {
		written, err := f.FakeChunkRemote.FakeRemote.ReadFile(ctx, path, dst)
		f.Transit(written)
		return written, err
	}
	f.Record("ReadFile")
	if err := f.CtxErr(ctx); err != nil {
		return 0, err
	}
	data, ok := f.Get(path)
	if !ok {
		return 0, transfercore.Fail(transfercore.ClassRefusedPath, "remote path was refused")
	}
	deliver := data
	if failure.Cut < int64(len(deliver)) {
		deliver = deliver[:failure.Cut]
	}
	written, err := WriteInChunks(dst, deliver)
	f.Transit(written)
	if err != nil {
		return written, err
	}
	if failure.Err != nil {
		return written, failure.Err
	}
	return written, transferremote.LinkFailure()
}

// SetStatFault scripts the StatSource failures.
func (f *FakeDownloadRemote) SetStatFault(fault func(n int) error) {
	f.dmu.Lock()
	defer f.dmu.Unlock()
	f.statFault = fault
}

// SetReadFault scripts the whole-stream ReadFile failures.
func (f *FakeDownloadRemote) SetReadFault(fault func(n int) *PartFailure) {
	f.dmu.Lock()
	defer f.dmu.Unlock()
	f.readFault = fault
}

// SetRangeFault scripts the ReadRange failures.
func (f *FakeDownloadRemote) SetRangeFault(fault func(n int, rg transferlink.Range) *PartFailure) {
	f.dmu.Lock()
	defer f.dmu.Unlock()
	f.rangeFault = fault
}

// SetOnStat sets the hook run before StatSource call n is answered.
func (f *FakeDownloadRemote) SetOnStat(hook func(n int)) {
	f.dmu.Lock()
	defer f.dmu.Unlock()
	f.onStat = hook
}

// SetOnRange sets the hook run before ReadRange call n is handled.
func (f *FakeDownloadRemote) SetOnRange(hook func(n int, rg transferlink.Range)) {
	f.dmu.Lock()
	defer f.dmu.Unlock()
	f.onRange = hook
}

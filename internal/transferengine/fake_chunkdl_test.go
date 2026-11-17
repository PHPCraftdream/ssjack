package transferengine

import (
	"context"
	"io"
	"sync"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlink"
	"github.com/PHPCraftdream/ssjack/internal/transferremote"
)

// dlMTime is the whole-second modification time the fake reports for every
// remote file until a test changes it.
const dlMTime = 1_600_000_000

type dlRangeCall struct {
	part transferlink.Range
	grid int64
}

// fakeDownloadRemote adds the download side of the chunked layer (StatSource,
// ReadRange and a whole-stream ReadFile with scripted failures) to
// fakeChunkRemote, which keeps the upload side and the clock. Bytes cost the
// same virtual time as for uploads, every session costs the setup time.
type fakeDownloadRemote struct {
	*fakeChunkRemote

	dmu        sync.Mutex
	mtime      int64
	statCalls  int
	readCalls  int
	rangeCalls int
	rangeLog   []dlRangeCall

	statFault  func(n int) error                               // StatSource call n (1-based) fails with this error
	readFault  func(n int) *partFailure                        // whole-stream ReadFile call n
	rangeFault func(n int, rg transferlink.Range) *partFailure // ReadRange call n
	onStat     func(n int)                                     // before StatSource call n is answered
	onRange    func(n int, rg transferlink.Range)              // before ReadRange call n is handled
}

var _ transferremote.ChunkRemote = (*fakeDownloadRemote)(nil)

func newFakeDownloadRemote(clock *vclock) *fakeDownloadRemote {
	return &fakeDownloadRemote{fakeChunkRemote: newFakeChunkRemote(clock), mtime: dlMTime}
}

func (f *fakeDownloadRemote) setMTime(m int64) {
	f.dmu.Lock()
	f.mtime = m
	f.dmu.Unlock()
}

func (f *fakeDownloadRemote) currentMTime() int64 {
	f.dmu.Lock()
	defer f.dmu.Unlock()
	return f.mtime
}

func (f *fakeDownloadRemote) statCount() int {
	f.dmu.Lock()
	defer f.dmu.Unlock()
	return f.statCalls
}

func (f *fakeDownloadRemote) readCount() int {
	f.dmu.Lock()
	defer f.dmu.Unlock()
	return f.readCalls
}

// ranges returns the part of every ReadRange call, in call order.
func (f *fakeDownloadRemote) ranges() []transferlink.Range {
	f.dmu.Lock()
	defer f.dmu.Unlock()
	out := make([]transferlink.Range, len(f.rangeLog))
	for i, c := range f.rangeLog {
		out[i] = c.part
	}
	return out
}

func (f *fakeDownloadRemote) rangeCalled() []dlRangeCall {
	f.dmu.Lock()
	defer f.dmu.Unlock()
	return append([]dlRangeCall(nil), f.rangeLog...)
}

// writeInChunks writes data in small pieces, so a transfer crosses several
// write boundaries, and returns the bytes written.
func writeInChunks(dst io.Writer, data []byte) (int64, error) {
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

func (f *fakeDownloadRemote) StatSource(ctx context.Context, path string) (transferremote.SourceStat, error) {
	f.record("StatSource")
	if err := f.ctxErr(ctx); err != nil {
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
	f.clock.Advance(f.setup)
	if fault != nil {
		if err := fault(n); err != nil {
			return transferremote.SourceStat{}, err
		}
	}
	data, ok := f.get(path)
	if !ok {
		return transferremote.SourceStat{}, transfercore.Fail(transfercore.ClassRefusedPath, "remote path was refused")
	}
	return transferremote.SourceStat{Size: int64(len(data)), MTime: f.currentMTime()}, nil
}

func (f *fakeDownloadRemote) ReadRange(ctx context.Context, path string, part transferlink.Range, grid, fileSize int64, dst io.Writer) (int64, error) {
	f.record("ReadRange")
	f.dmu.Lock()
	f.rangeCalls++
	n := f.rangeCalls
	f.rangeLog = append(f.rangeLog, dlRangeCall{part: part, grid: grid})
	hook, fault := f.onRange, f.rangeFault
	f.dmu.Unlock()
	if hook != nil {
		hook(n, part)
	}
	if err := f.ctxErr(ctx); err != nil {
		return 0, err
	}
	f.clock.Advance(f.setup)
	data, ok := f.get(path)
	if !ok {
		return 0, transfercore.Fail(transfercore.ClassRefusedPath, "remote path was refused")
	}
	var avail []byte
	if part.Off < int64(len(data)) {
		avail = data[part.Off:min(part.End(), int64(len(data)))]
	}
	var failure *partFailure
	if fault != nil {
		failure = fault(n, part)
	}
	deliver := avail
	if failure != nil && failure.cut < int64(len(deliver)) {
		deliver = deliver[:failure.cut]
	}
	written, err := writeInChunks(dst, deliver)
	f.transit(written)
	if err != nil {
		return written, err
	}
	if failure != nil {
		if failure.err != nil {
			return written, failure.err
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
func (f *fakeDownloadRemote) ReadFile(ctx context.Context, path string, dst io.Writer) (int64, error) {
	f.dmu.Lock()
	f.readCalls++
	n := f.readCalls
	fault := f.readFault
	f.dmu.Unlock()
	var failure *partFailure
	if fault != nil {
		failure = fault(n)
	}
	if failure == nil {
		written, err := f.fakeChunkRemote.fakeRemote.ReadFile(ctx, path, dst)
		f.transit(written)
		return written, err
	}
	f.record("ReadFile")
	if err := f.ctxErr(ctx); err != nil {
		return 0, err
	}
	data, ok := f.get(path)
	if !ok {
		return 0, transfercore.Fail(transfercore.ClassRefusedPath, "remote path was refused")
	}
	deliver := data
	if failure.cut < int64(len(deliver)) {
		deliver = deliver[:failure.cut]
	}
	written, err := writeInChunks(dst, deliver)
	f.transit(written)
	if err != nil {
		return written, err
	}
	if failure.err != nil {
		return written, failure.err
	}
	return written, transferremote.LinkFailure()
}

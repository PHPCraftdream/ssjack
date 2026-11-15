package transferengine

import (
	"context"
	"io"
	"sync"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferremote"
)

// fakeRemote models transferremote.Remote in memory: flat regular files,
// remote directories and job-owned staging directories. The directory
// primitives stream archive/tar data in the "./"-rooted layout of
// `tar -c -f - .`. All failures are *transfercore.Error values with fixed,
// content-free messages, mirroring the real layer's classes.
type fakeRemote struct {
	mu      sync.Mutex
	seq     int
	files   map[string][]byte
	dirs    map[string]bool // remote directories, including staging directories
	staging map[string]bool
	created map[string]bool // staging paths this job created (cleanup authority)
	calls   []string
	publish []fakePublish
	probes  int

	// knobs for failure and timing injection
	failProbe       error  // Probe returns this error
	corruptStage    bool   // flip the last byte written into staging
	corruptTree     bool   // flip the last byte of the first staged tree file before VerifyTree compares
	failCleanup     bool   // CleanupStaging fails
	failTarIn       error  // TarIn refuses before reading anything
	failTarOut      error  // TarOut refuses before writing anything
	onCreateStaging func() // runs during CreateStaging after path validation, before registration
	onWriteChunk    func() // runs once after the first upload chunk is read
	onReadStart     func() // runs before a download streams
	onReadChunk     func() // runs once after the first download chunk is written
	onTarInChunk    func() // runs once after the first tar entry is read
	onTarOutChunk   func() // runs once after the first tar entry is written
	onTarOutStart   func() // runs before TarOut snapshots the tree, without the fake lock held
}

// fakePublish is one recorded remote publication.
type fakePublish struct {
	staging   string
	dest      string
	overwrite bool
}

var _ transferremote.Remote = (*fakeRemote)(nil)

func newFakeRemote() *fakeRemote {
	return &fakeRemote{
		files:   map[string][]byte{},
		dirs:    map[string]bool{},
		staging: map[string]bool{},
		created: map[string]bool{},
	}
}

func cancelledError() error {
	return transfercore.Fail(transfercore.ClassCancelled, "transfer was cancelled")
}

func (f *fakeRemote) ctxErr(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return cancelledError()
	}
	return nil
}

func (f *fakeRemote) record(call string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
}

func (f *fakeRemote) callCount(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c == name {
			n++
		}
	}
	return n
}

func (f *fakeRemote) callsSnapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeRemote) put(path string, data []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[path] = append([]byte(nil), data...)
}

func (f *fakeRemote) get(path string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, ok := f.files[path]
	return append([]byte(nil), data...), ok
}

func (f *fakeRemote) stagingCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.staging)
}

func (f *fakeRemote) publishCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.publish)
}

// readAllChunked reads src in small chunks so transfers cross several read
// boundaries; hook runs once after the first chunk.
func readAllChunked(ctx context.Context, src io.Reader, hook func()) ([]byte, int64, error) {
	var data []byte
	var n int64
	buf := make([]byte, 1024)
	first := true
	for {
		if err := ctx.Err(); err != nil {
			return data, n, cancelledError()
		}
		read, err := src.Read(buf)
		n += int64(read)
		data = append(data, buf[:read]...)
		if first {
			first = false
			if hook != nil {
				hook()
			}
		}
		if err != nil {
			if err == io.EOF {
				return data, n, nil
			}
			return data, n, err
		}
	}
}

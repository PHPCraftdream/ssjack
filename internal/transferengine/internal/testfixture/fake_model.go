// Package testfixture holds the in-memory transfer engine test fixtures: the
// fake remotes, the virtual clock and the shared helpers. It is imported only
// by test packages.
package testfixture

import (
	"context"
	"io"
	"sync"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferremote"
)

// FakeRemote models transferremote.Remote in memory: flat regular files,
// remote directories and job-owned staging directories. The directory
// primitives stream archive/tar data in the "./"-rooted layout of
// `tar -c -f - .`. All failures are *transfercore.Error values with fixed,
// content-free messages, mirroring the real layer's classes.
type FakeRemote struct {
	Mu      sync.Mutex
	Seq     int
	Files   map[string][]byte
	Dirs    map[string]bool // remote directories, including staging directories
	Staging map[string]bool
	Created map[string]bool // staging paths this job created (cleanup authority)
	Calls   []string
	Publish []FakePublish
	Probes  int

	// knobs for failure and timing injection
	FailProbe       error  // Probe returns this error
	CorruptStage    bool   // flip the last byte written into staging
	CorruptTree     bool   // flip the last byte of the first staged tree file before VerifyTree compares
	FailCleanup     bool   // CleanupStaging fails
	FailTarIn       error  // TarIn refuses before reading anything
	FailTarOut      error  // TarOut refuses before writing anything
	OnCreateStaging func() // runs during CreateStaging after path validation, before registration
	OnWriteChunk    func() // runs once after the first upload chunk is read
	OnReadStart     func() // runs before a download streams
	OnReadChunk     func() // runs once after the first download chunk is written
	OnTarInChunk    func() // runs once after the first tar entry is read
	OnTarOutChunk   func() // runs once after the first tar entry is written
	OnTarOutStart   func() // runs before TarOut snapshots the tree, without the fake lock held
}

// FakePublish is one recorded remote publication.
type FakePublish struct {
	Staging   string
	Dest      string
	Overwrite bool
}

var _ transferremote.Remote = (*FakeRemote)(nil)

func NewFakeRemote() *FakeRemote {
	return &FakeRemote{
		Files:   map[string][]byte{},
		Dirs:    map[string]bool{},
		Staging: map[string]bool{},
		Created: map[string]bool{},
	}
}

func CancelledError() error {
	return transfercore.Fail(transfercore.ClassCancelled, "transfer was cancelled")
}

func (f *FakeRemote) CtxErr(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return CancelledError()
	}
	return nil
}

func (f *FakeRemote) Record(call string) {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	f.Calls = append(f.Calls, call)
}

func (f *FakeRemote) CallCount(name string) int {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	n := 0
	for _, c := range f.Calls {
		if c == name {
			n++
		}
	}
	return n
}

func (f *FakeRemote) CallsSnapshot() []string {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	return append([]string(nil), f.Calls...)
}

func (f *FakeRemote) Put(path string, data []byte) {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	f.Files[path] = append([]byte(nil), data...)
}

func (f *FakeRemote) Get(path string) ([]byte, bool) {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	data, ok := f.Files[path]
	return append([]byte(nil), data...), ok
}

func (f *FakeRemote) StagingCount() int {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	return len(f.Staging)
}

func (f *FakeRemote) PublishCount() int {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	return len(f.Publish)
}

// ReadAllChunked reads src in small chunks so transfers cross several read
// boundaries; hook runs once after the first chunk.
func ReadAllChunked(ctx context.Context, src io.Reader, hook func()) ([]byte, int64, error) {
	var data []byte
	var n int64
	buf := make([]byte, 1024)
	first := true
	for {
		if err := ctx.Err(); err != nil {
			return data, n, CancelledError()
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

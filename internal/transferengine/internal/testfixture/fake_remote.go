package testfixture

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

func (f *FakeRemote) Probe(ctx context.Context) error {
	f.Record("Probe")
	f.Mu.Lock()
	f.Probes++
	fail := f.FailProbe
	f.Mu.Unlock()
	if fail != nil {
		return fail
	}
	return f.CtxErr(ctx)
}

func (f *FakeRemote) CreateStaging(ctx context.Context, parent string) (string, error) {
	f.Record("CreateStaging")
	if err := f.CtxErr(ctx); err != nil {
		return "", err
	}
	if !strings.HasPrefix(parent, "/") || parent == "/" {
		return "", transfercore.Fail(transfercore.ClassRefusedPath, "remote path was refused")
	}
	if f.OnCreateStaging != nil {
		f.OnCreateStaging()
	}
	f.Mu.Lock()
	defer f.Mu.Unlock()
	f.Seq++
	name := fmt.Sprintf(".ssjack-transfer-%016x", f.Seq)
	p := parent + "/" + name
	if _, ok := f.Files[p]; ok || f.Staging[p] || f.Dirs[p] {
		return "", transfercore.Fail(transfercore.ClassExists, "remote destination already exists")
	}
	f.Staging[p] = true
	f.Dirs[p] = true
	f.Created[p] = true
	return p, nil
}

func (f *FakeRemote) CleanupStaging(ctx context.Context, parent, name string) error {
	f.Record("CleanupStaging")
	if err := f.CtxErr(ctx); err != nil {
		return err
	}
	p := parent + "/" + name
	f.Mu.Lock()
	defer f.Mu.Unlock()
	if !f.Created[p] {
		return transfercore.Fail(transfercore.ClassRefusedPath, "staging path was not created by this job")
	}
	if f.FailCleanup {
		return transfercore.Fail(transfercore.ClassRemoteFailed, "remote operation failed")
	}
	delete(f.Staging, p)
	delete(f.Dirs, p)
	delete(f.Created, p)
	for path := range f.Files {
		if strings.HasPrefix(path, p+"/") {
			delete(f.Files, path)
		}
	}
	for path := range f.Dirs {
		if strings.HasPrefix(path, p+"/") {
			delete(f.Dirs, path)
		}
	}
	return nil
}

func (f *FakeRemote) WriteFile(ctx context.Context, path string, src io.Reader, executable bool) (int64, error) {
	f.Record("WriteFile")
	if err := f.CtxErr(ctx); err != nil {
		return 0, err
	}
	f.Mu.Lock()
	_, exists := f.Files[path]
	corrupt := f.CorruptStage
	hook := f.OnWriteChunk
	f.Mu.Unlock()
	if exists {
		return 0, transfercore.Fail(transfercore.ClassExists, "remote destination already exists")
	}
	data, n, err := ReadAllChunked(ctx, src, hook)
	if err != nil {
		return n, err
	}
	if corrupt && len(data) > 0 {
		data[len(data)-1] ^= 0xff
	}
	f.Mu.Lock()
	f.Files[path] = data
	f.Mu.Unlock()
	return n, nil
}

func (f *FakeRemote) StatFile(ctx context.Context, path string) (int64, [32]byte, error) {
	f.Record("StatFile")
	if err := f.CtxErr(ctx); err != nil {
		return 0, [32]byte{}, err
	}
	f.Mu.Lock()
	defer f.Mu.Unlock()
	data, ok := f.Files[path]
	if !ok {
		return 0, [32]byte{}, transfercore.Fail(transfercore.ClassRefusedPath, "remote path was refused")
	}
	return int64(len(data)), sha256.Sum256(data), nil
}

func (f *FakeRemote) ReadFile(ctx context.Context, path string, dst io.Writer) (int64, error) {
	f.Record("ReadFile")
	if err := f.CtxErr(ctx); err != nil {
		return 0, err
	}
	f.Mu.Lock()
	data, ok := f.Files[path]
	startHook := f.OnReadStart
	chunkHook := f.OnReadChunk
	f.Mu.Unlock()
	if !ok {
		return 0, transfercore.Fail(transfercore.ClassRefusedPath, "remote path was refused")
	}
	if startHook != nil {
		startHook()
		f.Mu.Lock()
		data = f.Files[path]
		f.Mu.Unlock()
	}
	var n int64
	const chunk = 1024
	buf := make([]byte, chunk)
	first := true
	for start := 0; start < len(data); start += chunk {
		if err := ctx.Err(); err != nil {
			return n, CancelledError()
		}
		end := start + chunk
		if end > len(data) {
			end = len(data)
		}
		w, err := dst.Write(buf[:copy(buf, data[start:end])])
		n += int64(w)
		if err != nil {
			return n, err
		}
		if first {
			first = false
			if chunkHook != nil {
				chunkHook()
			}
		}
	}
	return n, nil
}

func (f *FakeRemote) PublishFile(ctx context.Context, staging, dest string, overwrite bool) error {
	f.Record("PublishFile")
	if err := f.CtxErr(ctx); err != nil {
		return err
	}
	f.Mu.Lock()
	defer f.Mu.Unlock()
	data, ok := f.Files[staging]
	if !ok {
		return transfercore.Fail(transfercore.ClassRefusedPath, "remote path was refused")
	}
	_, destIsFile := f.Files[dest]
	destIsDir := f.Dirs[dest] || f.Staging[dest]
	switch {
	case !overwrite && (destIsFile || destIsDir):
		return transfercore.Fail(transfercore.ClassExists, "remote destination already exists")
	case overwrite && destIsDir:
		return transfercore.Fail(transfercore.ClassRefusedPath, "remote path was refused")
	}
	f.Files[dest] = append([]byte(nil), data...)
	delete(f.Files, staging)
	f.Publish = append(f.Publish, FakePublish{Staging: staging, Dest: dest, Overwrite: overwrite})
	return nil
}

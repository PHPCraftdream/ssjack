package transferengine

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

func (f *fakeRemote) Probe(ctx context.Context) error {
	f.record("Probe")
	f.mu.Lock()
	f.probes++
	fail := f.failProbe
	f.mu.Unlock()
	if fail != nil {
		return fail
	}
	return f.ctxErr(ctx)
}

func (f *fakeRemote) CreateStaging(ctx context.Context, parent string) (string, error) {
	f.record("CreateStaging")
	if err := f.ctxErr(ctx); err != nil {
		return "", err
	}
	if !strings.HasPrefix(parent, "/") || parent == "/" {
		return "", transfercore.Fail(transfercore.ClassRefusedPath, "remote path was refused")
	}
	if f.onCreateStaging != nil {
		f.onCreateStaging()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	name := fmt.Sprintf(".ssjack-transfer-%016x", f.seq)
	p := parent + "/" + name
	if _, ok := f.files[p]; ok || f.staging[p] || f.dirs[p] {
		return "", transfercore.Fail(transfercore.ClassExists, "remote destination already exists")
	}
	f.staging[p] = true
	f.dirs[p] = true
	f.created[p] = true
	return p, nil
}

func (f *fakeRemote) CleanupStaging(ctx context.Context, parent, name string) error {
	f.record("CleanupStaging")
	if err := f.ctxErr(ctx); err != nil {
		return err
	}
	p := parent + "/" + name
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.created[p] {
		return transfercore.Fail(transfercore.ClassRefusedPath, "staging path was not created by this job")
	}
	if f.failCleanup {
		return transfercore.Fail(transfercore.ClassRemoteFailed, "remote operation failed")
	}
	delete(f.staging, p)
	delete(f.dirs, p)
	delete(f.created, p)
	for path := range f.files {
		if strings.HasPrefix(path, p+"/") {
			delete(f.files, path)
		}
	}
	for path := range f.dirs {
		if strings.HasPrefix(path, p+"/") {
			delete(f.dirs, path)
		}
	}
	return nil
}

func (f *fakeRemote) WriteFile(ctx context.Context, path string, src io.Reader, executable bool) (int64, error) {
	f.record("WriteFile")
	if err := f.ctxErr(ctx); err != nil {
		return 0, err
	}
	f.mu.Lock()
	_, exists := f.files[path]
	corrupt := f.corruptStage
	hook := f.onWriteChunk
	f.mu.Unlock()
	if exists {
		return 0, transfercore.Fail(transfercore.ClassExists, "remote destination already exists")
	}
	data, n, err := readAllChunked(ctx, src, hook)
	if err != nil {
		return n, err
	}
	if corrupt && len(data) > 0 {
		data[len(data)-1] ^= 0xff
	}
	f.mu.Lock()
	f.files[path] = data
	f.mu.Unlock()
	return n, nil
}

func (f *fakeRemote) StatFile(ctx context.Context, path string) (int64, [32]byte, error) {
	f.record("StatFile")
	if err := f.ctxErr(ctx); err != nil {
		return 0, [32]byte{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	data, ok := f.files[path]
	if !ok {
		return 0, [32]byte{}, transfercore.Fail(transfercore.ClassRefusedPath, "remote path was refused")
	}
	return int64(len(data)), sha256.Sum256(data), nil
}

func (f *fakeRemote) ReadFile(ctx context.Context, path string, dst io.Writer) (int64, error) {
	f.record("ReadFile")
	if err := f.ctxErr(ctx); err != nil {
		return 0, err
	}
	f.mu.Lock()
	data, ok := f.files[path]
	startHook := f.onReadStart
	chunkHook := f.onReadChunk
	f.mu.Unlock()
	if !ok {
		return 0, transfercore.Fail(transfercore.ClassRefusedPath, "remote path was refused")
	}
	if startHook != nil {
		startHook()
		f.mu.Lock()
		data = f.files[path]
		f.mu.Unlock()
	}
	var n int64
	const chunk = 1024
	buf := make([]byte, chunk)
	first := true
	for start := 0; start < len(data); start += chunk {
		if err := ctx.Err(); err != nil {
			return n, cancelledError()
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

func (f *fakeRemote) PublishFile(ctx context.Context, staging, dest string, overwrite bool) error {
	f.record("PublishFile")
	if err := f.ctxErr(ctx); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	data, ok := f.files[staging]
	if !ok {
		return transfercore.Fail(transfercore.ClassRefusedPath, "remote path was refused")
	}
	_, destIsFile := f.files[dest]
	destIsDir := f.dirs[dest] || f.staging[dest]
	switch {
	case !overwrite && (destIsFile || destIsDir):
		return transfercore.Fail(transfercore.ClassExists, "remote destination already exists")
	case overwrite && destIsDir:
		return transfercore.Fail(transfercore.ClassRefusedPath, "remote path was refused")
	}
	f.files[dest] = append([]byte(nil), data...)
	delete(f.files, staging)
	f.publish = append(f.publish, fakePublish{staging: staging, dest: dest, overwrite: overwrite})
	return nil
}

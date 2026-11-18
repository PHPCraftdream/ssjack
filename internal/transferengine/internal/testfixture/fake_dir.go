package testfixture

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"io"
	"sort"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

func KeysUnder[V any](m map[string]V, prefix string) []string {
	var out []string
	for path := range m {
		if strings.HasPrefix(path, prefix) {
			out = append(out, path)
		}
	}
	sort.Strings(out)
	return out
}

// Mkdir records p and every ancestor component as a remote directory.
func (f *FakeRemote) Mkdir(p string) {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	f.MkdirLocked(p)
}

// MkdirLocked adds p and every ancestor to dirs; mutex held, leading "/" required.
func (f *FakeRemote) MkdirLocked(p string) {
	if !strings.HasPrefix(p, "/") {
		return
	}
	parts := strings.Split(p, "/")
	for i := 1; i <= len(parts); i++ {
		f.Dirs[strings.Join(parts[:i], "/")] = true
	}
}

// FilesUnder returns the sorted slash-relative paths of files below dir.
func (f *FakeRemote) FilesUnder(dir string) []string {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	return f.FilesUnderLocked(dir)
}

func (f *FakeRemote) FilesUnderLocked(dir string) []string {
	var out []string
	for _, path := range KeysUnder(f.Files, dir+"/") {
		out = append(out, strings.TrimPrefix(path, dir+"/"))
	}
	return out
}

// DirsUnder returns the sorted slash-relative paths of directories below dir.
func (f *FakeRemote) DirsUnder(dir string) []string {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	return f.DirsUnderLocked(dir)
}

func (f *FakeRemote) DirsUnderLocked(dir string) []string {
	var out []string
	for _, path := range KeysUnder(f.Dirs, dir+"/") {
		out = append(out, strings.TrimPrefix(path, dir+"/"))
	}
	return out
}

func (f *FakeRemote) PreflightTree(ctx context.Context, root string) (transfercore.Manifest, error) {
	f.Record("PreflightTree")
	if err := f.CtxErr(ctx); err != nil {
		return transfercore.Manifest{}, err
	}
	f.Mu.Lock()
	defer f.Mu.Unlock()
	if !f.Dirs[root] {
		return transfercore.Manifest{}, transfercore.Fail(transfercore.ClassRefusedPath, "remote path was refused")
	}
	m := transfercore.Manifest{Dirs: f.DirsUnderLocked(root)}
	for _, rel := range f.FilesUnderLocked(root) {
		m.Files = append(m.Files, transfercore.Entry{Path: rel, Size: int64(len(f.Files[root+"/"+rel])), SHA256: sha256.Sum256(f.Files[root+"/"+rel])})
	}
	m.Normalize()
	return m, nil
}

func (f *FakeRemote) TarOut(ctx context.Context, root string, dst io.Writer) error {
	f.Record("TarOut")
	if err := f.CtxErr(ctx); err != nil {
		return err
	}
	f.Mu.Lock()
	fail, isDir, startHook, chunkHook := f.FailTarOut, f.Dirs[root], f.OnTarOutStart, f.OnTarOutChunk
	f.Mu.Unlock()
	if fail != nil {
		return fail
	} else if !isDir {
		return transfercore.Fail(transfercore.ClassRefusedPath, "remote path was refused")
	}
	if startHook != nil {
		startHook()
	}
	f.Mu.Lock()
	var hdrs []*tar.Header
	var blobs [][]byte
	for _, rel := range f.DirsUnderLocked(root) {
		hdrs = append(hdrs, &tar.Header{Name: "./" + rel + "/", Typeflag: tar.TypeDir, Mode: 0o755})
		blobs = append(blobs, nil)
	}
	for _, rel := range f.FilesUnderLocked(root) {
		hdrs = append(hdrs, &tar.Header{Name: "./" + rel, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(f.Files[root+"/"+rel]))})
		blobs = append(blobs, append([]byte(nil), f.Files[root+"/"+rel]...))
	}
	f.Mu.Unlock()
	tw := tar.NewWriter(dst)
	first := true
	for i, hdr := range hdrs {
		if ctx.Err() != nil {
			return CancelledError()
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return transfercore.Fail(transfercore.ClassRemoteFailed, "remote operation failed")
		}
		if first {
			first = false
			if chunkHook != nil {
				chunkHook()
			}
		}
		if len(blobs[i]) > 0 {
			if _, err := tw.Write(blobs[i]); err != nil {
				return transfercore.Fail(transfercore.ClassRemoteFailed, "remote operation failed")
			}
		}
	}
	if err := tw.Close(); err != nil {
		return transfercore.Fail(transfercore.ClassRemoteFailed, "remote operation failed")
	}
	return nil
}

func (f *FakeRemote) TarIn(ctx context.Context, root string, src io.Reader) error {
	f.Record("TarIn")
	if err := f.CtxErr(ctx); err != nil {
		return err
	}
	f.Mu.Lock()
	fail, isDir, chunkHook := f.FailTarIn, f.Dirs[root], f.OnTarInChunk
	f.Mu.Unlock()
	if fail != nil {
		return fail
	} else if !isDir {
		return transfercore.Fail(transfercore.ClassRefusedPath, "remote path was refused")
	}
	tr := tar.NewReader(src)
	first := true
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		} else if err != nil {
			return transfercore.Fail(transfercore.ClassIntegrity, "archive is truncated or malformed")
		}
		if first {
			first = false
			if chunkHook != nil {
				chunkHook()
			}
		}
		if ctx.Err() != nil {
			return CancelledError()
		}
		dir := hdr.Typeflag == tar.TypeDir
		if !dir && hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			return transfercore.Fail(transfercore.ClassRefusedPath, "archive contains an unsupported entry type")
		}
		name := hdr.Name
		if dir && strings.HasSuffix(name, "/") {
			name = strings.TrimSuffix(name, "/")
		}
		if name == "." {
			continue
		}
		name = strings.TrimPrefix(name, "./")
		if name == "" {
			return transfercore.Fail(transfercore.ClassIntegrity, "archive is truncated or malformed")
		}
		if err := transfercore.ValidateRelPath(name, transfercore.DefaultLimits()); err != nil {
			return err
		}
		if dir {
			f.Mu.Lock()
			f.MkdirLocked(root + "/" + name)
			f.Mu.Unlock()
			continue
		}
		data := make([]byte, hdr.Size)
		if _, err := io.ReadFull(tr, data); err != nil {
			return transfercore.Fail(transfercore.ClassIntegrity, "archive is truncated or malformed")
		}
		f.Mu.Lock()
		if i := strings.LastIndex(name, "/"); i >= 0 {
			f.MkdirLocked(root + "/" + name[:i])
		}
		f.Files[root+"/"+name] = data
		f.Mu.Unlock()
	}
}

func (f *FakeRemote) VerifyTree(ctx context.Context, root string, manifest transfercore.Manifest) error {
	f.Record("VerifyTree")
	if err := f.CtxErr(ctx); err != nil {
		return err
	}
	f.Mu.Lock()
	defer f.Mu.Unlock()
	if !f.Dirs[root] {
		return transfercore.Fail(transfercore.ClassRefusedPath, "remote path was refused")
	}
	files := f.FilesUnderLocked(root)
	if f.CorruptTree && len(files) > 0 && len(f.Files[root+"/"+files[0]]) > 0 {
		data := f.Files[root+"/"+files[0]]
		data[len(data)-1] ^= 0xff
	}
	manifest.Normalize()
	dirs := f.DirsUnderLocked(root)
	if len(dirs) != len(manifest.Dirs) || len(files) != len(manifest.Files) {
		return transfercore.Fail(transfercore.ClassIntegrity, "remote copy does not match the source")
	}
	for i := range dirs {
		if dirs[i] != manifest.Dirs[i] {
			return transfercore.Fail(transfercore.ClassIntegrity, "remote copy does not match the source")
		}
	}
	sums := map[string][32]byte{}
	for _, rel := range files {
		sums[rel] = sha256.Sum256(f.Files[root+"/"+rel])
	}
	for _, e := range manifest.Files {
		if sum, ok := sums[e.Path]; !ok || sum != e.SHA256 {
			return transfercore.Fail(transfercore.ClassIntegrity, "remote copy does not match the source")
		}
	}
	return nil
}

func (f *FakeRemote) PublishDir(ctx context.Context, staging, dest string, overwrite bool) error {
	f.Record("PublishDir")
	if err := f.CtxErr(ctx); err != nil {
		return err
	}
	f.Mu.Lock()
	defer f.Mu.Unlock()
	if !f.Dirs[staging] {
		return transfercore.Fail(transfercore.ClassRefusedPath, "remote path was refused")
	}
	_, destIsFile := f.Files[dest]
	destIsDir := f.Dirs[dest] || f.Staging[dest]
	switch {
	case !overwrite && (destIsFile || destIsDir):
		return transfercore.Fail(transfercore.ClassExists, "remote destination already exists")
	case overwrite && destIsFile:
		return transfercore.Fail(transfercore.ClassRefusedPath, "remote path was refused")
	}
	f.MoveSubtreeLocked(staging, dest, destIsDir)
	f.Publish = append(f.Publish, FakePublish{Staging: staging, Dest: dest, Overwrite: overwrite})
	return nil
}

// MoveSubtreeLocked drops p's markers, clears dest's old subtree when
// clearDest is set, and re-prefixes everything below p+"/" to dest. Keys are
// collected before deletion so no map is mutated while ranging.
func (f *FakeRemote) MoveSubtreeLocked(p, dest string, clearDest bool) {
	if clearDest {
		delete(f.Dirs, dest)
		delete(f.Staging, dest)
		for _, path := range KeysUnder(f.Dirs, dest+"/") {
			delete(f.Dirs, path)
			delete(f.Staging, path)
		}
		for _, path := range KeysUnder(f.Files, dest+"/") {
			delete(f.Files, path)
		}
	}
	delete(f.Staging, p)
	delete(f.Dirs, p)
	f.Dirs[dest] = true
	for _, path := range KeysUnder(f.Files, p+"/") {
		f.Files[dest+strings.TrimPrefix(path, p)] = f.Files[path]
		delete(f.Files, path)
	}
	for _, path := range KeysUnder(f.Dirs, p+"/") {
		f.Dirs[dest+strings.TrimPrefix(path, p)] = true
		delete(f.Dirs, path)
	}
}

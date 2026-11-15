package transferengine

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"io"
	"sort"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

func keysUnder[V any](m map[string]V, prefix string) []string {
	var out []string
	for path := range m {
		if strings.HasPrefix(path, prefix) {
			out = append(out, path)
		}
	}
	sort.Strings(out)
	return out
}

// mkdir records p and every ancestor component as a remote directory.
func (f *fakeRemote) mkdir(p string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mkdirLocked(p)
}

// mkdirLocked adds p and every ancestor to dirs; mutex held, leading "/" required.
func (f *fakeRemote) mkdirLocked(p string) {
	if !strings.HasPrefix(p, "/") {
		return
	}
	parts := strings.Split(p, "/")
	for i := 1; i <= len(parts); i++ {
		f.dirs[strings.Join(parts[:i], "/")] = true
	}
}

// filesUnder returns the sorted slash-relative paths of files below dir.
func (f *fakeRemote) filesUnder(dir string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.filesUnderLocked(dir)
}

func (f *fakeRemote) filesUnderLocked(dir string) []string {
	var out []string
	for _, path := range keysUnder(f.files, dir+"/") {
		out = append(out, strings.TrimPrefix(path, dir+"/"))
	}
	return out
}

// dirsUnder returns the sorted slash-relative paths of directories below dir.
func (f *fakeRemote) dirsUnder(dir string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dirsUnderLocked(dir)
}

func (f *fakeRemote) dirsUnderLocked(dir string) []string {
	var out []string
	for _, path := range keysUnder(f.dirs, dir+"/") {
		out = append(out, strings.TrimPrefix(path, dir+"/"))
	}
	return out
}

func (f *fakeRemote) PreflightTree(ctx context.Context, root string) (transfercore.Manifest, error) {
	f.record("PreflightTree")
	if err := f.ctxErr(ctx); err != nil {
		return transfercore.Manifest{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.dirs[root] {
		return transfercore.Manifest{}, transfercore.Fail(transfercore.ClassRefusedPath, "remote path was refused")
	}
	m := transfercore.Manifest{Dirs: f.dirsUnderLocked(root)}
	for _, rel := range f.filesUnderLocked(root) {
		m.Files = append(m.Files, transfercore.Entry{Path: rel, Size: int64(len(f.files[root+"/"+rel])), SHA256: sha256.Sum256(f.files[root+"/"+rel])})
	}
	m.Normalize()
	return m, nil
}

func (f *fakeRemote) TarOut(ctx context.Context, root string, dst io.Writer) error {
	f.record("TarOut")
	if err := f.ctxErr(ctx); err != nil {
		return err
	}
	f.mu.Lock()
	fail, isDir, startHook, chunkHook := f.failTarOut, f.dirs[root], f.onTarOutStart, f.onTarOutChunk
	f.mu.Unlock()
	if fail != nil {
		return fail
	} else if !isDir {
		return transfercore.Fail(transfercore.ClassRefusedPath, "remote path was refused")
	}
	if startHook != nil {
		startHook()
	}
	f.mu.Lock()
	var hdrs []*tar.Header
	var blobs [][]byte
	for _, rel := range f.dirsUnderLocked(root) {
		hdrs = append(hdrs, &tar.Header{Name: "./" + rel + "/", Typeflag: tar.TypeDir, Mode: 0o755})
		blobs = append(blobs, nil)
	}
	for _, rel := range f.filesUnderLocked(root) {
		hdrs = append(hdrs, &tar.Header{Name: "./" + rel, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(f.files[root+"/"+rel]))})
		blobs = append(blobs, append([]byte(nil), f.files[root+"/"+rel]...))
	}
	f.mu.Unlock()
	tw := tar.NewWriter(dst)
	first := true
	for i, hdr := range hdrs {
		if ctx.Err() != nil {
			return cancelledError()
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

func (f *fakeRemote) TarIn(ctx context.Context, root string, src io.Reader) error {
	f.record("TarIn")
	if err := f.ctxErr(ctx); err != nil {
		return err
	}
	f.mu.Lock()
	fail, isDir, chunkHook := f.failTarIn, f.dirs[root], f.onTarInChunk
	f.mu.Unlock()
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
			return cancelledError()
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
			f.mu.Lock()
			f.mkdirLocked(root + "/" + name)
			f.mu.Unlock()
			continue
		}
		data := make([]byte, hdr.Size)
		if _, err := io.ReadFull(tr, data); err != nil {
			return transfercore.Fail(transfercore.ClassIntegrity, "archive is truncated or malformed")
		}
		f.mu.Lock()
		if i := strings.LastIndex(name, "/"); i >= 0 {
			f.mkdirLocked(root + "/" + name[:i])
		}
		f.files[root+"/"+name] = data
		f.mu.Unlock()
	}
}

func (f *fakeRemote) VerifyTree(ctx context.Context, root string, manifest transfercore.Manifest) error {
	f.record("VerifyTree")
	if err := f.ctxErr(ctx); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.dirs[root] {
		return transfercore.Fail(transfercore.ClassRefusedPath, "remote path was refused")
	}
	files := f.filesUnderLocked(root)
	if f.corruptTree && len(files) > 0 && len(f.files[root+"/"+files[0]]) > 0 {
		data := f.files[root+"/"+files[0]]
		data[len(data)-1] ^= 0xff
	}
	manifest.Normalize()
	dirs := f.dirsUnderLocked(root)
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
		sums[rel] = sha256.Sum256(f.files[root+"/"+rel])
	}
	for _, e := range manifest.Files {
		if sum, ok := sums[e.Path]; !ok || sum != e.SHA256 {
			return transfercore.Fail(transfercore.ClassIntegrity, "remote copy does not match the source")
		}
	}
	return nil
}

func (f *fakeRemote) PublishDir(ctx context.Context, staging, dest string, overwrite bool) error {
	f.record("PublishDir")
	if err := f.ctxErr(ctx); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.dirs[staging] {
		return transfercore.Fail(transfercore.ClassRefusedPath, "remote path was refused")
	}
	_, destIsFile := f.files[dest]
	destIsDir := f.dirs[dest] || f.staging[dest]
	switch {
	case !overwrite && (destIsFile || destIsDir):
		return transfercore.Fail(transfercore.ClassExists, "remote destination already exists")
	case overwrite && destIsFile:
		return transfercore.Fail(transfercore.ClassRefusedPath, "remote path was refused")
	}
	f.moveSubtreeLocked(staging, dest, destIsDir)
	f.publish = append(f.publish, fakePublish{staging: staging, dest: dest, overwrite: overwrite})
	return nil
}

// moveSubtreeLocked drops p's markers, clears dest's old subtree when
// clearDest is set, and re-prefixes everything below p+"/" to dest. Keys are
// collected before deletion so no map is mutated while ranging.
func (f *fakeRemote) moveSubtreeLocked(p, dest string, clearDest bool) {
	if clearDest {
		delete(f.dirs, dest)
		delete(f.staging, dest)
		for _, path := range keysUnder(f.dirs, dest+"/") {
			delete(f.dirs, path)
			delete(f.staging, path)
		}
		for _, path := range keysUnder(f.files, dest+"/") {
			delete(f.files, path)
		}
	}
	delete(f.staging, p)
	delete(f.dirs, p)
	f.dirs[dest] = true
	for _, path := range keysUnder(f.files, p+"/") {
		f.files[dest+strings.TrimPrefix(path, p)] = f.files[path]
		delete(f.files, path)
	}
	for _, path := range keysUnder(f.dirs, p+"/") {
		f.dirs[dest+strings.TrimPrefix(path, p)] = true
		delete(f.dirs, path)
	}
}

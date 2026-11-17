package transferlocal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlink"
)

// The chunked download keeps its bytes in a deterministic, marked staging
// directory next to the destination: .ssjack-transfer-<32 hex key>, mode 0700,
// holding a marker, the finished parts (part-<off>-<len>) and, while it
// assembles, the assembled file. Unlike the one-shot Staging it survives a
// link failure, so every adoption and removal runs the strict checks of
// docs/FILE-TRANSFER.md: the object must be a real directory (no symlink or
// reparse point), private, owned by this principal, and carry the marker with
// the same key. A directory that fails any check is a foreign object: it is
// never reused, written to or removed.

const (
	chunkKeyDigits   = 32
	chunkMarkerName  = "marker"
	chunkMarkerMagic = "SSJACK-STAGING 1 "
	chunkSourceLine  = "SSJACK-SOURCE-SHA256 "
	chunkMarkerMax   = 512
	chunkPartPrefix  = "part-"
	assembledPrefix  = "assembled."
	tempSuffix       = ".tmp"
)

const (
	// ChunkStaleAfter is how long a keyed staging directory must have been
	// idle (its marker is touched after every completed part) before a later
	// transfer into the same directory may collect it.
	ChunkStaleAfter = 24 * time.Hour
	// ChunkGCLimit bounds the directories one garbage collection removes.
	ChunkGCLimit = 16
)

var (
	// ErrChunkPartInvalid reports that a part to be assembled is missing, not
	// a regular file or no longer as long as its name says.
	ErrChunkPartInvalid = errors.New("chunk part is missing or invalid")
	// ErrChunkStagingGone reports that the staging directory vanished.
	ErrChunkStagingGone = errors.New("chunk staging directory is gone")

	errPartClosed  = errors.New("part writer is closed")
	errPartOverrun = errors.New("part is longer than expected")
)

// ChunkState is the verdict of OpenChunkStaging.
type ChunkState int

const (
	// ChunkAbsent: there is no staging directory (and none was asked for).
	ChunkAbsent ChunkState = iota + 1
	// ChunkCreated: a fresh directory with its marker was created.
	ChunkCreated
	// ChunkReused: an existing directory passed every adoption check.
	ChunkReused
	// ChunkForeign: the staging name holds an object that failed an adoption
	// check; it was not used, written to or removed.
	ChunkForeign
)

// ChunkStaging is the keyed staging directory of one chunked download. It is
// owned by one goroutine.
type ChunkStaging struct {
	parentAbs string // destination's parent directory
	name      string // .ssjack-transfer-<key>
	path      string // absolute staging directory path
	destBase  string // destination file name inside parentAbs
	overwrite bool
	key       string
	identity  string // pathIdentity of the directory while it is this job's own
	assembled string // name of the assembled file waiting for Publish
	published bool
}

type chunkVerdict int

const (
	verdictAbsent chunkVerdict = iota + 1
	verdictForeign
	verdictOwn
)

// validChunkKey reports whether key is 32 lowercase hex digits.
func validChunkKey(key string) bool {
	if len(key) != chunkKeyDigits {
		return false
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// chunkKeyFromName extracts the key of a keyed staging directory name.
func chunkKeyFromName(name string) (string, bool) {
	key, ok := strings.CutPrefix(name, stagingPrefix)
	if !ok || !validChunkKey(key) {
		return "", false
	}
	return key, true
}

func internalFail(message string) error {
	return transfercore.Fail(transfercore.ClassInternal, message)
}

// chunkParent validates the destination under the same rules as NewStaging and
// returns the destination's parent directory and final component.
func (r *Root) chunkParent(destRel string) (parentAbs, base string, err error) {
	if err := validateLocalRelPath(destRel, transfercore.DefaultLimits()); err != nil {
		return "", "", err
	}
	if forbiddenRelPath(destRel) {
		return "", "", refusedPath("destination contains a forbidden control directory")
	}
	if err := verifyRealDirTree(r.path); err != nil {
		return "", "", err
	}
	parentRel, base := splitRelName(destRel)
	parentAbs = r.path
	if parentRel != "" {
		parentAbs = filepath.Join(r.path, filepath.FromSlash(parentRel))
		if err := verifyRealDirTree(parentAbs); err != nil {
			return "", "", err
		}
	}
	return parentAbs, base, nil
}

// OpenChunkStaging looks at the keyed staging directory of the download of
// destRel: it adopts an existing one, and creates it when create is set. key
// is the 32-hex staging key and source the SHA-256 the remote file had before
// the transfer: the marker records it, and a directory of this key whose
// recorded hash differs is a staging of another version of the source and is
// removed (it is the job's own by every other check) before anything else
// happens. A foreign object yields ChunkForeign and a nil staging. The
// destination existing without overwrite is not checked here, see
// CheckDestination.
func (r *Root) OpenChunkStaging(destRel, key string, source [32]byte, overwrite, create bool) (*ChunkStaging, ChunkState, error) {
	if !validChunkKey(key) {
		return nil, 0, internalFail("staging key is invalid")
	}
	parentAbs, base, err := r.chunkParent(destRel)
	if err != nil {
		return nil, 0, err
	}
	s := &ChunkStaging{
		parentAbs: parentAbs, name: stagingPrefix + key, path: filepath.Join(parentAbs, stagingPrefix+key),
		destBase: base, overwrite: overwrite, key: key,
	}
	verdict, recorded := s.inspect()
	if verdict == verdictOwn && recorded != source {
		if err := s.Remove(); err != nil {
			return nil, ChunkForeign, nil
		}
		verdict = verdictAbsent
	}
	switch verdict {
	case verdictForeign:
		return nil, ChunkForeign, nil
	case verdictOwn:
		return s, ChunkReused, nil
	}
	if !create {
		return nil, ChunkAbsent, nil
	}
	if err := createStageDir(s.path); err != nil {
		if err == errDestinationExists {
			return nil, ChunkForeign, nil
		}
		return nil, 0, internalFail("staging directory could not be created")
	}
	if err := s.writeMarker(source); err != nil {
		s.discardFresh()
		return nil, 0, internalFail("staging directory could not be created")
	}
	if verdict, _ := s.inspect(); verdict != verdictOwn {
		s.discardFresh()
		return nil, 0, internalFail("staging directory could not be created")
	}
	_ = syncDirectory(s.parentAbs)
	return s, ChunkCreated, nil
}

// discardFresh removes a directory this call has just created but could not
// complete. Only a real directory is removed; a link is dropped by name.
func (s *ChunkStaging) discardFresh() {
	info, err := statPath(s.path)
	if err != nil || !info.exist {
		return
	}
	if info.reparse || !info.dir {
		_ = os.Remove(s.path)
		return
	}
	_ = os.RemoveAll(s.path)
}

type chunkMarker struct {
	key string
	sum [32]byte
}

func formatChunkMarker(key string, source [32]byte) string {
	return chunkMarkerMagic + key + "\n" + chunkSourceLine + hex.EncodeToString(source[:]) + "\n"
}

func parseChunkMarker(text string) (chunkMarker, bool) {
	lines := strings.Split(text, "\n")
	if len(lines) != 3 || lines[2] != "" {
		return chunkMarker{}, false
	}
	key, ok := strings.CutPrefix(lines[0], chunkMarkerMagic)
	if !ok || !validChunkKey(key) {
		return chunkMarker{}, false
	}
	digest, ok := strings.CutPrefix(lines[1], chunkSourceLine)
	if !ok {
		return chunkMarker{}, false
	}
	raw, err := hex.DecodeString(digest)
	if err != nil || len(raw) != sha256.Size {
		return chunkMarker{}, false
	}
	m := chunkMarker{key: key}
	copy(m.sum[:], raw)
	return m, true
}

// readChunkMarker reads the marker file no-follow: a small regular file with a
// single link, in the format above.
func readChunkMarker(path string) (chunkMarker, bool) {
	info, err := statPath(path)
	if err != nil || !info.exist || !info.regular || info.reparse || info.multiLinked ||
		info.size <= 0 || info.size > chunkMarkerMax {
		return chunkMarker{}, false
	}
	file, _, err := openRegularNoFollow(path)
	if err != nil {
		return chunkMarker{}, false
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, chunkMarkerMax+1))
	if err != nil || len(data) > chunkMarkerMax {
		return chunkMarker{}, false
	}
	return parseChunkMarker(string(data))
}

func (s *ChunkStaging) writeMarker(source [32]byte) error {
	file, err := createExclusiveFile(filepath.Join(s.path, chunkMarkerName), 0600)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(file, formatChunkMarker(s.key, source)); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

// inspect applies the adoption checks. On verdictOwn it records the directory
// identity and returns the pre-hash the marker holds.
func (s *ChunkStaging) inspect() (chunkVerdict, [32]byte) {
	info, err := statPath(s.path)
	if err != nil {
		return verdictForeign, [32]byte{}
	}
	if !info.exist {
		return verdictAbsent, [32]byte{}
	}
	if !info.dir || info.reparse || !privateOwnedDir(s.path, info) {
		return verdictForeign, [32]byte{}
	}
	marker, ok := readChunkMarker(filepath.Join(s.path, chunkMarkerName))
	if !ok || marker.key != s.key {
		return verdictForeign, [32]byte{}
	}
	identity, err := pathIdentity(s.path)
	if err != nil {
		return verdictForeign, [32]byte{}
	}
	s.identity = identity
	return verdictOwn, marker.sum
}

// CheckDestination refuses an existing destination without overwrite, as
// NewStaging does when it creates a one-shot staging directory.
func (s *ChunkStaging) CheckDestination() error {
	if s.overwrite {
		return nil
	}
	info, err := statPath(filepath.Join(s.parentAbs, s.destBase))
	if err != nil {
		return refusedPath("destination cannot be inspected")
	}
	if info.exist {
		return transfercore.Fail(transfercore.ClassExists, "destination already exists")
	}
	return nil
}

// Remove removes the staging directory after re-checking that it still is the
// object this job adopted or created: a real directory with the same identity
// and the marker of the same key. An absent directory is success; a changed
// one is never removed.
func (s *ChunkStaging) Remove() error {
	if s.published {
		return nil
	}
	if !validChunkKey(s.key) || s.name != stagingPrefix+s.key || s.path != filepath.Join(s.parentAbs, s.name) {
		return internalFail("staging name is invalid")
	}
	info, err := statPath(s.path)
	if err != nil {
		return internalFail("staging could not be removed")
	}
	if !info.exist {
		return nil
	}
	if !info.dir || info.reparse {
		return internalFail("staging was replaced by unrelated content")
	}
	identity, err := pathIdentity(s.path)
	if err != nil || identity != s.identity {
		return internalFail("staging was replaced by unrelated content")
	}
	if marker, ok := readChunkMarker(filepath.Join(s.path, chunkMarkerName)); !ok || marker.key != s.key {
		return internalFail("staging was replaced by unrelated content")
	}
	if err := removeTree(s.path); err != nil {
		return internalFail("staging could not be removed")
	}
	_ = syncDirectory(s.parentAbs)
	return nil
}

// FreeBytes returns the bytes available to this process on the filesystem of
// the staging directory; ok is false when the platform cannot tell.
func (s *ChunkStaging) FreeBytes() (int64, bool) { return freeBytes(s.parentAbs) }

func (s *ChunkStaging) removeEntry(name string) {
	_ = os.Remove(filepath.Join(s.path, name))
}

// ListParts reads the finished parts of a file of fileSize bytes. Names that
// are not strict part names, entries that are not single-link regular files,
// stale temporary files, left-over assembly files and entries that overlap an
// accepted part, have the wrong size or end past the file are removed and not
// counted (best effort). More than maxParts part entries mark the staging as
// corrupt: overflow is true and nothing is removed.
func (s *ChunkStaging) ListParts(fileSize int64, maxParts int) (parts []transferlink.Range, overflow bool, err error) {
	entries, err := os.ReadDir(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, ErrChunkStagingGone
		}
		return nil, false, internalFail("staging could not be listed")
	}
	if len(entries) > 2*maxParts+64 {
		return nil, true, nil
	}
	var listed []transferlink.Listed
	var junk []string
	count := 0
	for _, entry := range entries {
		name := entry.Name()
		switch {
		case name == chunkMarkerName:
		case strings.HasPrefix(name, assembledPrefix) || name == payloadName:
			junk = append(junk, name)
		case strings.HasPrefix(name, chunkPartPrefix):
			if strings.HasSuffix(name, tempSuffix) {
				junk = append(junk, name)
				continue
			}
			count++
			rng, perr := transferlink.ParsePartName(name)
			info, serr := statPath(filepath.Join(s.path, name))
			if perr != nil || serr != nil || !info.exist || !info.regular || info.reparse || info.multiLinked {
				junk = append(junk, name)
				continue
			}
			listed = append(listed, transferlink.Listed{Name: name, Range: rng, Size: info.size})
		}
	}
	if count > maxParts {
		return nil, true, nil
	}
	accepted, rejected := transferlink.AcceptListed(fileSize, listed)
	for _, name := range append(junk, rejected...) {
		s.removeEntry(name)
	}
	return accepted, false, nil
}

// PartWriter receives the bytes of one part into a temporary file of the
// staging directory. Commit makes it a part, Abort drops it.
type PartWriter struct {
	s     *ChunkStaging
	tmp   string
	final string
	want  int64

	mu     sync.Mutex
	file   *os.File
	n      int64
	done   bool
	closed bool
}

// CreatePart opens part-<off>-<len>.<random>.tmp exclusively. The random
// suffix keeps a lingering writer of an earlier attempt away from this one.
func (s *ChunkStaging) CreatePart(part transferlink.Range) (*PartWriter, error) {
	name, err := transferlink.PartName(part)
	if err != nil {
		return nil, internalFail("part name is invalid")
	}
	rnd, err := randomHex(16)
	if err != nil {
		return nil, internalFail("part could not be created")
	}
	tmp := filepath.Join(s.path, name+"."+rnd+tempSuffix)
	file, err := createExclusiveFile(tmp, 0600)
	if err != nil {
		if info, statErr := statPath(s.path); statErr == nil && !info.exist {
			return nil, ErrChunkStagingGone
		}
		return nil, internalFail("part could not be created")
	}
	return &PartWriter{s: s, tmp: tmp, final: filepath.Join(s.path, name), want: part.Len, file: file}, nil
}

// Write appends to the part; bytes beyond the part length are refused.
func (w *PartWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.done {
		return 0, errPartClosed
	}
	if int64(len(p)) > w.want-w.n {
		return 0, errPartOverrun
	}
	n, err := w.file.Write(p)
	w.n += int64(n)
	return n, err
}

// Written returns the bytes written so far.
func (w *PartWriter) Written() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.n
}

func (w *PartWriter) discardLocked() {
	if !w.closed {
		w.closed = true
		_ = w.file.Close()
	}
	_ = os.Remove(w.tmp)
}

// Abort drops the part; it is idempotent and a no-op after Commit.
func (w *PartWriter) Abort() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.done {
		return
	}
	w.done = true
	w.discardLocked()
}

// Commit checks the length, flushes the data and renames the temporary file to
// the final part name, then refreshes the marker's time (its idleness is what
// garbage collection looks at). A part with another length is dropped.
func (w *PartWriter) Commit() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.done {
		return internalFail("part writer already finished")
	}
	w.done = true
	if w.n != w.want {
		w.discardLocked()
		return transfercore.Fail(transfercore.ClassIntegrity, "part has an unexpected length")
	}
	if err := w.file.Sync(); err != nil {
		w.discardLocked()
		return internalFail("part could not be flushed")
	}
	w.closed = true
	if err := w.file.Close(); err != nil {
		_ = os.Remove(w.tmp)
		return internalFail("part could not be written")
	}
	if err := os.Rename(w.tmp, w.final); err != nil {
		_ = os.Remove(w.tmp)
		return internalFail("part could not be stored")
	}
	now := time.Now()
	_ = os.Chtimes(filepath.Join(w.s.path, chunkMarkerName), now, now)
	_ = syncDirectory(w.s.path)
	return nil
}

// contextReader fails a read once the context is done.
type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *contextReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// dropAssembled removes left-over assembly files of earlier attempts.
func (s *ChunkStaging) dropAssembled() {
	entries, err := os.ReadDir(s.path)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if name := entry.Name(); strings.HasPrefix(name, assembledPrefix) || name == payloadName {
			s.removeEntry(name)
		}
	}
	s.assembled = ""
}

// Assemble concatenates the parts, which must tile [0, size) exactly, in
// offset order into a new assembled.<random>.tmp inside the staging directory
// while hashing, flushes it and returns the SHA-256 of the whole. Every part is
// re-checked while it is read: a missing or changed one is ErrChunkPartInvalid
// and the half-written file is removed; the parts themselves are never
// modified. The file stays for Publish.
func (s *ChunkStaging) Assemble(ctx context.Context, parts []transferlink.Range, size int64) ([32]byte, error) {
	var sum [32]byte
	if err := transferlink.ValidateTiling(size, parts); err != nil {
		return sum, internalFail("parts do not tile the file")
	}
	ordered := append([]transferlink.Range(nil), parts...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Off < ordered[j].Off })
	s.dropAssembled()
	rnd, err := randomHex(16)
	if err != nil {
		return sum, internalFail("assembled file could not be created")
	}
	name := assembledPrefix + rnd + tempSuffix
	path := filepath.Join(s.path, name)
	out, err := createExclusiveFile(path, 0600)
	if err != nil {
		if info, statErr := statPath(s.path); statErr == nil && !info.exist {
			return sum, ErrChunkStagingGone
		}
		return sum, internalFail("assembled file could not be created")
	}
	fail := func(err error) ([32]byte, error) {
		_ = out.Close()
		_ = os.Remove(path)
		return [32]byte{}, err
	}
	h := sha256.New()
	dst := io.MultiWriter(out, h)
	for _, p := range ordered {
		partName, err := transferlink.PartName(p)
		if err != nil {
			return fail(internalFail("part name is invalid"))
		}
		file, fsize, err := openRegularNoFollow(filepath.Join(s.path, partName))
		if err != nil || fsize != p.Len {
			if file != nil {
				_ = file.Close()
			}
			return fail(ErrChunkPartInvalid)
		}
		n, copyErr := io.Copy(dst, &contextReader{ctx: ctx, r: file})
		_ = file.Close()
		if copyErr != nil {
			if ctx.Err() != nil {
				return fail(ctx.Err())
			}
			return fail(internalFail("assembled file could not be written"))
		}
		if n != p.Len {
			return fail(ErrChunkPartInvalid)
		}
	}
	if err := out.Sync(); err != nil {
		return fail(internalFail("assembled file could not be flushed"))
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(path)
		return sum, internalFail("assembled file could not be written")
	}
	s.assembled = name
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

// Publish moves the assembled file to the destination with the publication
// code of the one-shot staging (no-overwrite: hard link then unlink;
// overwrite: rename onto a regular file) and removes the staging directory. On
// failure nothing is published and the staging directory stays for Remove.
func (s *ChunkStaging) Publish() error {
	if s.assembled == "" || s.published {
		return internalFail("nothing is assembled")
	}
	payload := filepath.Join(s.path, payloadName)
	if info, err := statPath(payload); err == nil && info.exist {
		_ = os.Remove(payload)
	}
	if err := os.Rename(filepath.Join(s.path, s.assembled), payload); err != nil {
		return internalFail("assembled file could not be staged")
	}
	s.assembled = ""
	one := &Staging{
		parent: s.parentAbs, name: s.name, path: s.path, destRel: s.destBase,
		overwrite: s.overwrite, identity: s.identity,
	}
	if err := one.Publish(KindFile); err != nil {
		return err
	}
	s.published = true
	return nil
}

// CollectStaleChunkStaging removes at most ChunkGCLimit keyed staging
// directories from the parent directory of destRel that pass every adoption
// check and whose marker has been idle for ChunkStaleAfter, never the one of
// excludeKey (empty for none). Every check is repeated immediately before the
// removal; one-shot staging names, unmarked directories, foreign objects and
// everything else are left alone and errors are ignored. It returns the number
// of directories removed.
func (r *Root) CollectStaleChunkStaging(destRel, excludeKey string) int {
	parentAbs, _, err := r.chunkParent(destRel)
	if err != nil {
		return 0
	}
	entries, err := os.ReadDir(parentAbs)
	if err != nil {
		return 0
	}
	removed := 0
	for _, entry := range entries {
		if removed >= ChunkGCLimit {
			break
		}
		if !entry.IsDir() {
			continue
		}
		key, ok := chunkKeyFromName(entry.Name())
		if !ok || key == excludeKey {
			continue
		}
		s := &ChunkStaging{
			parentAbs: parentAbs, name: entry.Name(), path: filepath.Join(parentAbs, entry.Name()), key: key,
		}
		if s.removeIfIdle() {
			removed++
		}
	}
	return removed
}

// idle reports whether the directory is an own staging directory whose marker
// is older than ChunkStaleAfter.
func (s *ChunkStaging) idle() bool {
	if verdict, _ := s.inspect(); verdict != verdictOwn {
		return false
	}
	info, err := os.Lstat(filepath.Join(s.path, chunkMarkerName))
	if err != nil {
		return false
	}
	return time.Since(info.ModTime()) > ChunkStaleAfter
}

func (s *ChunkStaging) removeIfIdle() bool {
	if !s.idle() {
		return false
	}
	identity := s.identity
	if !s.idle() || s.identity != identity {
		return false
	}
	return s.Remove() == nil
}

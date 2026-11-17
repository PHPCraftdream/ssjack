package transferremote

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlink"
)

// maxReadBlock bounds the dd block size of a range read (the largest chunk
// size of the link profile).
const maxReadBlock = 64 << 20

// ChunkRemote is the remote command layer of the chunked resumable mode
// (docs/FILE-TRANSFER.md, "Chunked resumable mode"). Every method runs one
// fixed command template in a fresh session; nothing here decides strategy.
// Methods that touch a staging directory take the destination's parent and
// the staging key (see StagingKey); the directory name is derived from it.
//
// New returns a value that also implements ChunkRemote; NewChunk returns it
// directly. Chunked methods fail closed with ClassUnsupportedRemote when the
// probed capabilities lack what they need (see ChunkCaps).
type ChunkRemote interface {
	Remote

	// ChunkCaps returns the probed chunked-mode capabilities; before Probe it
	// is the GNU-compatible default.
	ChunkCaps() ChunkCaps

	// EnsureStaging creates the marked staging directory (mode 0700, no
	// clobber) or verifies an existing one. A foreign object yields
	// StagingForeign and is left untouched.
	EnsureStaging(ctx context.Context, parent, key string) (StagingState, error)
	// UploadPart stores exactly part.Len bytes read from src as
	// part-<off>-<len>. The part counts only when PartResult.Stored is true.
	UploadPart(ctx context.Context, parent, key string, part transferlink.Range, src io.Reader) (PartResult, error)
	// ListStaging lists the staging directory of a file of fileSize bytes and
	// builds the coverage; it removes stale temporary files remotely, among them
	// every leftover assembled.<rnd>.tmp (counted in StagingListing.StaleAssembled),
	// so the caller's disk preflight after the listing sees the space free.
	ListStaging(ctx context.Context, parent, key string, fileSize int64) (StagingListing, error)
	// RemoveStagingEntries removes ignored part entries named by a listing.
	RemoveStagingEntries(ctx context.Context, parent, key string, names []string) error
	// AssembleStaging concatenates the parts, which must tile [0, size)
	// exactly, into a random-named file in the staging directory and returns
	// its path, size and SHA-256 computed with the selected hash command.
	AssembleStaging(ctx context.Context, parent, key string, parts []transferlink.Range, size int64, executable bool) (Assembled, error)
	// RemoveChunkStaging removes the staging directory after the adoption
	// checks; an absent directory is success.
	RemoveChunkStaging(ctx context.Context, parent, key string) error
	// CollectStaging removes at most 16 stale staging directories of the
	// parent, never the one for excludeKey (empty for none). It returns how
	// many were removed. Callers ignore its error.
	CollectStaging(ctx context.Context, parent, excludeKey string) (int, error)
	// DiskAvailable returns the bytes available on the filesystem of parent;
	// ok is false when the result is unavailable or unparsable (skip the
	// check).
	DiskAvailable(ctx context.Context, parent string) (avail int64, ok bool, err error)

	// StatSource returns the size and whole-second mtime of a regular file.
	StatSource(ctx context.Context, path string) (SourceStat, error)
	// ReadRange streams part of a regular file into dst and returns the byte
	// count. grid is the current chunk size S and fileSize the remote size;
	// dd is used when part.Off is a multiple of grid and the part is a whole
	// block or the tail of the file, else tail/head. A count different from
	// part.Len without a transport error is ClassIntegrity.
	ReadRange(ctx context.Context, path string, part transferlink.Range, grid, fileSize int64, dst io.Writer) (int64, error)
}

// Assembled describes the file produced by AssembleStaging.
type Assembled struct {
	// Path is the remote path of the assembled file, ready for PublishFile.
	Path   string
	Size   int64
	SHA256 [32]byte
}

var _ ChunkRemote = (*remoteRunner)(nil)

// NewChunk returns the Remote of New as a ChunkRemote.
func NewChunk(run remote.StreamRunner, target string, limits transfercore.Limits) ChunkRemote {
	return &remoteRunner{run: run, target: target, limits: limits, created: map[string]struct{}{}}
}

// StagingKey derives the staging key: the first 32 hex digits of the SHA-256
// over the fields, each prefixed with its length as an 8-byte big-endian
// integer. Callers pass (target, remote path, local root-relative path, size,
// mtime) as strings; integers in decimal.
func StagingKey(fields ...string) string {
	h := sha256.New()
	for _, f := range fields {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(f)))
		h.Write(n[:])
		h.Write([]byte(f))
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// validStageKey reports whether key is 32 lowercase hex digits.
func validStageKey(key string) bool {
	if len(key) != 32 {
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

// chunkStageName is the staging directory name for a key.
func chunkStageName(key string) string { return stagingPrefix + key }

// IsStageForeign reports whether err is a remote exit of ExitStageForeign.
func IsStageForeign(err error) bool { return exitCodeIs(err, ExitStageForeign) }

// IsStageMissing reports whether err is a remote exit of ExitStageMissing.
func IsStageMissing(err error) bool { return exitCodeIs(err, ExitStageMissing) }

// IsPartMissing reports whether err is a remote exit of ExitPartMissing.
func IsPartMissing(err error) bool { return exitCodeIs(err, ExitPartMissing) }

func exitCodeIs(err error, code int) bool {
	var e *transfercore.Error
	return errors.As(err, &e) && e.ExitCode == code
}

func (r *remoteRunner) ChunkCaps() ChunkCaps {
	caps := r.capabilities().chunk
	if caps.Read == "" {
		caps.Read = ReadNone
	}
	if caps.Mtime == "" {
		caps.Mtime = MtimeNone
	}
	return caps
}

func unsupportedChunk() error {
	return classed(transfercore.ClassUnsupportedRemote, msgUnsupported, exitUnsupported)
}

func invalidChunkArgument() error {
	return transfercore.Fail(transfercore.ClassInternal, "invalid chunk transfer argument")
}

// stageCommand builds a staging template: the quoted prologue, the shared
// functions and key checks, then body. vars are extra quoted assignments.
func (r *remoteRunner) stageCommand(parent, key string, vars [][2]string, body string) (string, error) {
	if err := r.ready(); err != nil {
		return "", err
	}
	if !r.ChunkCaps().Own {
		return "", unsupportedChunk()
	}
	if err := checkRemotePath(parent, r.limits); err != nil {
		return "", err
	}
	if !validStageKey(key) {
		return "", classed(transfercore.ClassRefusedPath, msgRefused, -1)
	}
	var b strings.Builder
	b.WriteString("set -eu\n")
	fmt.Fprintf(&b, "parent=%s\nname=%s\nkey=%s\n", shellQuote(parent), shellQuote(chunkStageName(key)), shellQuote(key))
	for _, v := range vars {
		fmt.Fprintf(&b, "%s=%s\n", v[0], shellQuote(v[1]))
	}
	b.WriteString(stageFuncs)
	b.WriteString(stageHeader)
	b.WriteString(body)
	return b.String(), nil
}

func (r *remoteRunner) EnsureStaging(ctx context.Context, parent, key string) (StagingState, error) {
	command, err := r.stageCommand(parent, key, nil, stageEnsureBody)
	if err != nil {
		return 0, err
	}
	out, err := r.runListed(ctx, command, 256)
	if err != nil {
		return 0, err
	}
	return parseStageEnsure(out)
}

func (r *remoteRunner) UploadPart(ctx context.Context, parent, key string, part transferlink.Range, src io.Reader) (PartResult, error) {
	if _, err := transferlink.PartName(part); err != nil {
		return PartResult{}, invalidChunkArgument()
	}
	rnd, err := newRandomSuffix()
	if err != nil {
		return PartResult{}, err
	}
	command, err := r.stageCommand(parent, key, [][2]string{
		{"off", strconv.FormatInt(part.Off, 10)},
		{"len", strconv.FormatInt(part.Len, 10)},
		{"rnd", rnd},
	}, partUploadBody)
	if err != nil {
		return PartResult{}, err
	}
	command = publicationTemplate(command, r.capabilities())
	var stdin io.Reader = strings.NewReader("")
	if src != nil {
		stdin = io.LimitReader(src, part.Len)
	}
	out, err := r.runFed(ctx, command, stdin, 256)
	if err != nil {
		return PartResult{}, err
	}
	return parsePartResult(out, part.Len)
}

// runFed runs a command with stdin and a bounded stdout, like runListed.
func (r *remoteRunner) runFed(ctx context.Context, command string, stdin io.Reader, bound int64) ([]byte, error) {
	var buf bytes.Buffer
	b := &boundedWriter{w: &buf, remaining: bound}
	err := r.execute(ctx, command, stdin, b)
	if b.overflow {
		return nil, classed(transfercore.ClassLimit, msgLimit, 0)
	}
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (r *remoteRunner) ListStaging(ctx context.Context, parent, key string, fileSize int64) (StagingListing, error) {
	maxParts := MaxListedParts(r.limits)
	command, err := r.stageCommand(parent, key, [][2]string{{"max", strconv.Itoa(maxParts)}}, listBody)
	if err != nil {
		return StagingListing{}, err
	}
	out, err := r.runListed(ctx, command, listingBytesBound(maxParts))
	if err != nil {
		return StagingListing{}, err
	}
	return parseStagingListing(out, fileSize, maxParts)
}

func (r *remoteRunner) RemoveStagingEntries(ctx context.Context, parent, key string, names []string) error {
	if len(names) == 0 {
		return nil
	}
	if len(names) > MaxListedParts(r.limits) {
		return invalidChunkArgument()
	}
	for _, n := range names {
		if !safePartName(n) {
			return invalidChunkArgument()
		}
	}
	command, err := r.stageCommand(parent, key, nil, removeEntriesBody)
	if err != nil {
		return err
	}
	return r.execute(ctx, command, strings.NewReader(strings.Join(names, "\n")+"\n"), io.Discard)
}

func (r *remoteRunner) AssembleStaging(ctx context.Context, parent, key string, parts []transferlink.Range, size int64, executable bool) (Assembled, error) {
	if size < 0 || size > r.limits.MaxBytes || len(parts) > MaxListedParts(r.limits) {
		return Assembled{}, classed(transfercore.ClassLimit, msgLimit, 0)
	}
	if err := transferlink.ValidateTiling(size, parts); err != nil {
		return Assembled{}, invalidChunkArgument()
	}
	ordered := append([]transferlink.Range(nil), parts...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Off < ordered[j].Off })
	names := make([]string, len(ordered))
	for i, p := range ordered {
		name, err := transferlink.PartName(p)
		if err != nil {
			return Assembled{}, invalidChunkArgument()
		}
		names[i] = name
	}
	rnd, err := newRandomSuffix()
	if err != nil {
		return Assembled{}, err
	}
	body := assembleBody
	if executable {
		body += assembleExecSuffix
	}
	body += assembleCheckBody + statHashCommand(r.capabilities().hash) + assembleDoneBody
	command, err := r.stageCommand(parent, key, [][2]string{
		{"rnd", rnd},
		{"size", strconv.FormatInt(size, 10)},
	}, body)
	if err != nil {
		return Assembled{}, err
	}
	path := parent + "/" + chunkStageName(key) + "/assembled." + rnd + ".tmp"
	stdin := strings.NewReader(strings.Join(names, "\n") + "\n")
	if len(names) == 0 {
		stdin = strings.NewReader("")
	}
	out, err := r.runFed(ctx, command, stdin, 8192)
	if err != nil {
		return Assembled{}, err
	}
	got, hash, err := parseStatOutput(out, path)
	if err != nil {
		return Assembled{}, err
	}
	if got != size {
		return Assembled{}, listingError(transfercore.ClassIntegrity, msgChunkMalformed)
	}
	return Assembled{Path: path, Size: got, SHA256: hash}, nil
}

func (r *remoteRunner) RemoveChunkStaging(ctx context.Context, parent, key string) error {
	command, err := r.stageCommand(parent, key, nil, removeStagingBody)
	if err != nil {
		return err
	}
	return r.execute(ctx, command, nil, io.Discard)
}

func (r *remoteRunner) CollectStaging(ctx context.Context, parent, excludeKey string) (int, error) {
	if err := r.ready(); err != nil {
		return 0, err
	}
	if !r.ChunkCaps().Own {
		return 0, unsupportedChunk()
	}
	if err := checkRemotePath(parent, r.limits); err != nil {
		return 0, err
	}
	excl := ""
	if excludeKey != "" {
		if !validStageKey(excludeKey) {
			return 0, classed(transfercore.ClassRefusedPath, msgRefused, -1)
		}
		excl = chunkStageName(excludeKey)
	}
	command := fmt.Sprintf("set -eu\nparent=%s\nexcl=%s\n", shellQuote(parent), shellQuote(excl)) + stageFuncs + gcBody
	out, err := r.runListed(ctx, command, 256)
	if err != nil {
		return 0, err
	}
	return parseGCResult(out)
}

func (r *remoteRunner) DiskAvailable(ctx context.Context, parent string) (int64, bool, error) {
	if err := r.ready(); err != nil {
		return 0, false, err
	}
	if err := checkRemotePath(parent, r.limits); err != nil {
		return 0, false, err
	}
	command := fmt.Sprintf("set -eu\nparent=%s\n", shellQuote(parent)) + diskBody
	out, err := r.runListed(ctx, command, 4096)
	if err != nil {
		return 0, false, err
	}
	avail, ok := parseDF(out)
	return avail, ok, nil
}

func (r *remoteRunner) StatSource(ctx context.Context, path string) (SourceStat, error) {
	if err := r.ready(); err != nil {
		return SourceStat{}, err
	}
	if err := checkRemotePath(path, r.limits); err != nil {
		return SourceStat{}, err
	}
	var flavour string
	switch r.ChunkCaps().Mtime {
	case MtimeGNU:
		flavour = statSourceGNU
	case MtimeBSD:
		flavour = statSourceBSD
	default:
		return SourceStat{}, unsupportedChunk()
	}
	command := fmt.Sprintf("set -eu\npath=%s\n", shellQuote(path)) + statSourceBody + flavour
	out, err := r.runListed(ctx, command, 256)
	if err != nil {
		return SourceStat{}, err
	}
	return parseSourceStat(out)
}

func (r *remoteRunner) ReadRange(ctx context.Context, path string, part transferlink.Range, grid, fileSize int64, dst io.Writer) (int64, error) {
	if err := r.ready(); err != nil {
		return 0, err
	}
	if err := checkRemotePath(path, r.limits); err != nil {
		return 0, err
	}
	if _, err := transferlink.PartName(part); err != nil || fileSize < 0 || part.End() > fileSize || dst == nil {
		return 0, invalidChunkArgument()
	}
	mode := r.ChunkCaps().Read
	if mode != ReadDD && mode != ReadTail {
		return 0, unsupportedChunk()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "set -eu\npath=%s\n", shellQuote(path))
	b.WriteString(readRangeBody)
	onGrid := grid > 0 && grid <= maxReadBlock && part.Off%grid == 0 &&
		(part.Len == grid || (part.Len < grid && part.End() == fileSize))
	if mode == ReadDD && onGrid {
		fmt.Fprintf(&b, "bs=%s\nskip=%s\n", shellQuote(strconv.FormatInt(grid, 10)), shellQuote(strconv.FormatInt(part.Off/grid, 10)))
		b.WriteString(readRangeDD)
	} else {
		fmt.Fprintf(&b, "start=%s\nlen=%s\n", shellQuote(strconv.FormatInt(part.Off+1, 10)), shellQuote(strconv.FormatInt(part.Len, 10)))
		b.WriteString(readRangeTail)
	}
	cw := &countingWriter{w: dst}
	err := r.execute(ctx, b.String(), nil, cw)
	n := cw.n.Load()
	if err == nil && n != part.Len {
		return n, listingError(transfercore.ClassIntegrity, msgChunkRange)
	}
	return n, err
}

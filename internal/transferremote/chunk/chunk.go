// Package chunk holds the chunked resumable mode of the remote protocol:
// staging, part upload, listing, assembly, collection, range reads, and the
// command templates and strict parsers behind them.
package chunk

import (
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

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlink"
	"github.com/PHPCraftdream/ssjack/internal/transferremote/core"
)

// maxReadBlock bounds the dd block size of a range read (the largest chunk
// size of the link profile).
const maxReadBlock = 64 << 20

// Assembled describes the file produced by AssembleStaging.
type Assembled struct {
	// Path is the remote path of the assembled file, ready for PublishFile.
	Path   string
	Size   int64
	SHA256 [32]byte
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
func chunkStageName(key string) string { return core.StagingPrefix + key }

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

func (r *ChunkOps) ChunkCaps() core.ChunkCaps {
	caps := r.Capabilities().Chunk
	if caps.Read == "" {
		caps.Read = core.ReadNone
	}
	if caps.Mtime == "" {
		caps.Mtime = core.MtimeNone
	}
	return caps
}

func unsupportedChunk() error {
	return core.Classed(transfercore.ClassUnsupportedRemote, core.MsgUnsupported, core.ExitUnsupported)
}

func invalidChunkArgument() error {
	return transfercore.Fail(transfercore.ClassInternal, "invalid chunk transfer argument")
}

// stageCommand builds a staging template: the quoted prologue, the shared
// functions and key checks, then body. vars are extra quoted assignments.
func (r *ChunkOps) stageCommand(parent, key string, vars [][2]string, body string) (string, error) {
	if err := r.Ready(); err != nil {
		return "", err
	}
	if !r.ChunkCaps().Own {
		return "", unsupportedChunk()
	}
	if err := core.CheckRemotePath(parent, r.Limits); err != nil {
		return "", err
	}
	if !validStageKey(key) {
		return "", core.Classed(transfercore.ClassRefusedPath, core.MsgRefused, -1)
	}
	var b strings.Builder
	b.WriteString("set -eu\n")
	fmt.Fprintf(&b, "parent=%s\nname=%s\nkey=%s\n", core.ShellQuote(parent), core.ShellQuote(chunkStageName(key)), core.ShellQuote(key))
	for _, v := range vars {
		fmt.Fprintf(&b, "%s=%s\n", v[0], core.ShellQuote(v[1]))
	}
	b.WriteString(stageFuncs)
	b.WriteString(stageHeader)
	b.WriteString(body)
	return b.String(), nil
}

func (r *ChunkOps) EnsureStaging(ctx context.Context, parent, key string) (StagingState, error) {
	command, err := r.stageCommand(parent, key, nil, stageEnsureBody)
	if err != nil {
		return 0, err
	}
	out, err := r.RunListed(ctx, command, 256)
	if err != nil {
		return 0, err
	}
	return parseStageEnsure(out)
}

func (r *ChunkOps) UploadPart(ctx context.Context, parent, key string, part transferlink.Range, src io.Reader) (PartResult, error) {
	if _, err := transferlink.PartName(part); err != nil {
		return PartResult{}, invalidChunkArgument()
	}
	rnd, err := core.NewRandomSuffix()
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
	command = core.PublicationTemplate(command, r.Capabilities())
	var stdin io.Reader = strings.NewReader("")
	if src != nil {
		stdin = io.LimitReader(src, part.Len)
	}
	out, err := r.RunFed(ctx, command, stdin, 256)
	if err != nil {
		return PartResult{}, err
	}
	return parsePartResult(out, part.Len)
}

func (r *ChunkOps) ListStaging(ctx context.Context, parent, key string, fileSize int64) (StagingListing, error) {
	maxParts := MaxListedParts(r.Limits)
	command, err := r.stageCommand(parent, key, [][2]string{{"max", strconv.Itoa(maxParts)}}, listBody)
	if err != nil {
		return StagingListing{}, err
	}
	out, err := r.RunListed(ctx, command, listingBytesBound(maxParts))
	if err != nil {
		return StagingListing{}, err
	}
	return parseStagingListing(out, fileSize, maxParts)
}

func (r *ChunkOps) RemoveStagingEntries(ctx context.Context, parent, key string, names []string) error {
	if len(names) == 0 {
		return nil
	}
	if len(names) > MaxListedParts(r.Limits) {
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
	return r.Execute(ctx, command, strings.NewReader(strings.Join(names, "\n")+"\n"), io.Discard)
}

func (r *ChunkOps) AssembleStaging(ctx context.Context, parent, key string, parts []transferlink.Range, size int64, executable bool) (Assembled, error) {
	if size < 0 || size > r.Limits.MaxBytes || len(parts) > MaxListedParts(r.Limits) {
		return Assembled{}, core.Classed(transfercore.ClassLimit, core.MsgLimit, 0)
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
	rnd, err := core.NewRandomSuffix()
	if err != nil {
		return Assembled{}, err
	}
	body := assembleBody
	if executable {
		body += assembleExecSuffix
	}
	body += assembleCheckBody + core.StatHashCommand(r.Capabilities().Hash) + assembleDoneBody
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
	out, err := r.RunFed(ctx, command, stdin, 8192)
	if err != nil {
		return Assembled{}, err
	}
	got, hash, err := core.ParseStatOutput(out, path)
	if err != nil {
		return Assembled{}, err
	}
	if got != size {
		return Assembled{}, core.ListingError(transfercore.ClassIntegrity, msgChunkMalformed)
	}
	return Assembled{Path: path, Size: got, SHA256: hash}, nil
}

func (r *ChunkOps) RemoveChunkStaging(ctx context.Context, parent, key string) error {
	command, err := r.stageCommand(parent, key, nil, removeStagingBody)
	if err != nil {
		return err
	}
	return r.Execute(ctx, command, nil, io.Discard)
}

func (r *ChunkOps) CollectStaging(ctx context.Context, parent, excludeKey string) (int, error) {
	if err := r.Ready(); err != nil {
		return 0, err
	}
	if !r.ChunkCaps().Own {
		return 0, unsupportedChunk()
	}
	if err := core.CheckRemotePath(parent, r.Limits); err != nil {
		return 0, err
	}
	excl := ""
	if excludeKey != "" {
		if !validStageKey(excludeKey) {
			return 0, core.Classed(transfercore.ClassRefusedPath, core.MsgRefused, -1)
		}
		excl = chunkStageName(excludeKey)
	}
	command := fmt.Sprintf("set -eu\nparent=%s\nexcl=%s\n", core.ShellQuote(parent), core.ShellQuote(excl)) + stageFuncs + gcBody
	out, err := r.RunListed(ctx, command, 256)
	if err != nil {
		return 0, err
	}
	return parseGCResult(out)
}

func (r *ChunkOps) DiskAvailable(ctx context.Context, parent string) (int64, bool, error) {
	if err := r.Ready(); err != nil {
		return 0, false, err
	}
	if err := core.CheckRemotePath(parent, r.Limits); err != nil {
		return 0, false, err
	}
	command := fmt.Sprintf("set -eu\nparent=%s\n", core.ShellQuote(parent)) + diskBody
	out, err := r.RunListed(ctx, command, 4096)
	if err != nil {
		return 0, false, err
	}
	avail, ok := parseDF(out)
	return avail, ok, nil
}

func (r *ChunkOps) StatSource(ctx context.Context, path string) (SourceStat, error) {
	if err := r.Ready(); err != nil {
		return SourceStat{}, err
	}
	if err := core.CheckRemotePath(path, r.Limits); err != nil {
		return SourceStat{}, err
	}
	var flavour string
	switch r.ChunkCaps().Mtime {
	case core.MtimeGNU:
		flavour = statSourceGNU
	case core.MtimeBSD:
		flavour = statSourceBSD
	default:
		return SourceStat{}, unsupportedChunk()
	}
	command := fmt.Sprintf("set -eu\npath=%s\n", core.ShellQuote(path)) + statSourceBody + flavour
	out, err := r.RunListed(ctx, command, 256)
	if err != nil {
		return SourceStat{}, err
	}
	return parseSourceStat(out)
}

func (r *ChunkOps) ReadRange(ctx context.Context, path string, part transferlink.Range, grid, fileSize int64, dst io.Writer) (int64, error) {
	if err := r.Ready(); err != nil {
		return 0, err
	}
	if err := core.CheckRemotePath(path, r.Limits); err != nil {
		return 0, err
	}
	if _, err := transferlink.PartName(part); err != nil || fileSize < 0 || part.End() > fileSize || dst == nil {
		return 0, invalidChunkArgument()
	}
	mode := r.ChunkCaps().Read
	if mode != core.ReadDD && mode != core.ReadTail {
		return 0, unsupportedChunk()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "set -eu\npath=%s\n", core.ShellQuote(path))
	b.WriteString(readRangeBody)
	onGrid := grid > 0 && grid <= maxReadBlock && part.Off%grid == 0 &&
		(part.Len == grid || (part.Len < grid && part.End() == fileSize))
	if mode == core.ReadDD && onGrid {
		fmt.Fprintf(&b, "bs=%s\nskip=%s\n", core.ShellQuote(strconv.FormatInt(grid, 10)), core.ShellQuote(strconv.FormatInt(part.Off/grid, 10)))
		b.WriteString(readRangeDD)
	} else {
		fmt.Fprintf(&b, "start=%s\nlen=%s\n", core.ShellQuote(strconv.FormatInt(part.Off+1, 10)), core.ShellQuote(strconv.FormatInt(part.Len, 10)))
		b.WriteString(readRangeTail)
	}
	cw := core.NewCountingWriter(dst)
	err := r.Execute(ctx, b.String(), nil, cw)
	n := cw.Count()
	if err == nil && n != part.Len {
		return n, core.ListingError(transfercore.ClassIntegrity, msgChunkRange)
	}
	return n, err
}

// ChunkOps runs the chunked-mode operations of a remote target.
type ChunkOps struct{ *core.Runner }

// New returns the ChunkOps of a runner.
func New(r *core.Runner) *ChunkOps { return &ChunkOps{r} }

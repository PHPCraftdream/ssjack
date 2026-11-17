// Package transfercore holds the contracts shared by the local and remote
// halves of the file transfer engine (docs/FILE-TRANSFER.md).
package transfercore

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Class is the only failure detail a model-facing result may carry.
type Class string

const (
	ClassRefusedPath       Class = "refused_path"
	ClassExists            Class = "exists"
	ClassLimit             Class = "limit"
	ClassUnsupportedRemote Class = "unsupported_remote"
	ClassIntegrity         Class = "integrity"
	ClassRemoteFailed      Class = "remote_failed"
	// ClassLinkUnstable: the chunked mode gave up after repeated attempts
	// without progress; the staging is kept and a retry resumes.
	ClassLinkUnstable Class = "link_unstable"
	ClassCancelled    Class = "cancelled"
	ClassInternal     Class = "internal"
)

// MsgLinkUnstable is the fixed, content-free message of ClassLinkUnstable.
const MsgLinkUnstable = "transfer link was too unstable to finish; a retry can resume"

// Error carries a Class and a fixed, content-free message.
type Error struct {
	Class    Class
	Message  string
	ExitCode int
}

func (e *Error) Error() string { return e.Message }

// Fail builds an *Error. The message must not contain paths or file content.
func Fail(class Class, message string) *Error { return &Error{Class: class, Message: message} }

// ClassOf maps any error to a Class: unknown errors are internal, context
// cancellation is cancelled.
func ClassOf(err error) Class {
	var e *Error
	if errors.As(err, &e) {
		return e.Class
	}
	if errors.Is(err, context.Canceled) {
		return ClassCancelled
	}
	return ClassInternal
}

// Limits bound one transfer.
type Limits struct {
	MaxBytes     int64
	MaxEntries   int
	MaxPathBytes int
	MaxDepth     int
}

func DefaultLimits() Limits {
	return Limits{MaxBytes: 2 << 30, MaxEntries: 100000, MaxPathBytes: 1024, MaxDepth: 64}
}

func (l Limits) Validate() error {
	if l.MaxBytes <= 0 || l.MaxEntries <= 0 || l.MaxPathBytes <= 0 || l.MaxDepth <= 0 {
		return errors.New("transfer limits must be positive")
	}
	return nil
}

// Entry is one regular file of a manifest. Path is relative, slash-separated.
type Entry struct {
	Path   string
	Size   int64
	SHA256 [32]byte
}

// Manifest describes a directory tree of regular files and directories.
type Manifest struct {
	Dirs  []string
	Files []Entry
}

// Normalize sorts entries so equal trees produce equal manifests.
func (m *Manifest) Normalize() {
	sort.Strings(m.Dirs)
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
}

// Totals returns file count, directory count and total file bytes.
func (m Manifest) Totals() (files, dirs int, bytes int64) {
	for _, f := range m.Files {
		bytes += f.Size
	}
	return len(m.Files), len(m.Dirs), bytes
}

// CheckLimits fails with ClassLimit when the tree exceeds l.
func (m Manifest) CheckLimits(l Limits) error {
	files, dirs, bytes := m.Totals()
	if files+dirs > l.MaxEntries || bytes > l.MaxBytes {
		return Fail(ClassLimit, "transfer exceeds the configured limits")
	}
	return nil
}

// Digest is a canonical SHA-256 over the normalized manifest.
func (m Manifest) Digest() [32]byte {
	c := Manifest{Dirs: append([]string(nil), m.Dirs...), Files: append([]Entry(nil), m.Files...)}
	c.Normalize()
	h := sha256.New()
	for _, d := range c.Dirs {
		fmt.Fprintf(h, "D\x00%s\n", d)
	}
	for _, f := range c.Files {
		fmt.Fprintf(h, "F\x00%s\x00%s\x00%x\n", f.Path, strconv.FormatInt(f.Size, 10), f.SHA256)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ValidateRelPath checks a slash-separated relative path used inside a root,
// a remote tree or an archive entry. It does not apply OS-specific local
// rules; transferlocal adds those.
func ValidateRelPath(p string, l Limits) error {
	if p == "" || len(p) > l.MaxPathBytes {
		return Fail(ClassRefusedPath, "path is empty or too long")
	}
	if strings.HasPrefix(p, "/") || strings.Contains(p, "\\") {
		return Fail(ClassRefusedPath, "path must be relative and slash-separated")
	}
	parts := strings.Split(p, "/")
	if len(parts) > l.MaxDepth {
		return Fail(ClassRefusedPath, "path is too deep")
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return Fail(ClassRefusedPath, "path contains an empty, current or parent component")
		}
		for _, r := range part {
			if r < 0x20 || r == 0x7f {
				return Fail(ClassRefusedPath, "path contains a control character")
			}
		}
	}
	return nil
}

// ValidateRemotePath checks an absolute POSIX path given for the remote side.
func ValidateRemotePath(p string, l Limits) error {
	if !strings.HasPrefix(p, "/") || p == "/" {
		return Fail(ClassRefusedPath, "remote path must be absolute and not the root")
	}
	return ValidateRelPath(strings.TrimPrefix(p, "/"), l)
}

var forbiddenLocalComponents = map[string]struct{}{
	".git": {}, ".hg": {}, ".svn": {}, ".ssh": {}, ".claude": {}, ".vscode": {}, ".husky": {}, ".github": {},
}

// ForbiddenLocalComponent reports whether a local download destination or an
// extracted entry may not contain this path component (case-insensitive).
func ForbiddenLocalComponent(name string) bool {
	_, bad := forbiddenLocalComponents[strings.ToLower(name)]
	return bad
}

// Phase names for status reporting.
const (
	PhasePreflight = "preflight"
	PhaseTransfer  = "transfer"
	PhaseVerify    = "verify"
	PhasePublish   = "publish"
	PhaseCleanup   = "cleanup"
)

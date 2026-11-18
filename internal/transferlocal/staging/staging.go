// Package staging owns the job staging directory of one transfer and its
// atomic publication to the destination.
package staging

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal/osfs"
	"github.com/PHPCraftdream/ssjack/internal/transferlocal/pathsafe"
)

// Kind selects what Publish puts at the destination.
type Kind int

const (
	KindFile Kind = iota
	KindDir
)

// PayloadName is the fixed inner name of a staged single file.
const PayloadName = "payload"

// Staging is one job-owned staging directory inside the destination's parent.
type Staging struct {
	parent    string // absolute destination parent directory
	name      string // staging base name, pathsafe.StagingPrefix + 12 hex chars
	path      string // absolute staging directory path
	destRel   string // destination path relative to parent, slash-separated
	overwrite bool
	identity  string // pathIdentity recorded at creation
	published bool
	aborted   bool
}

// NewStaging creates a private exclusive staging directory in dir; parents
// are never created implicitly.
func NewStaging(destRel string, dir string, overwrite bool) (*Staging, error) {
	if err := pathsafe.ValidateLocalRelPath(destRel, transfercore.DefaultLimits()); err != nil {
		return nil, err
	}
	if pathsafe.ForbiddenRelPath(destRel) {
		return nil, pathsafe.Refused("destination contains a forbidden control directory")
	}
	if !filepath.IsAbs(dir) {
		return nil, transfercore.Fail(transfercore.ClassRefusedPath, "staging parent directory must be absolute")
	}
	if err := pathsafe.VerifyRealDirTree(dir); err != nil {
		return nil, err
	}
	destParentRel, _ := pathsafe.SplitRelName(destRel)
	if destParentRel != "" {
		if err := pathsafe.VerifyRealDirTree(filepath.Join(dir, filepath.FromSlash(destParentRel))); err != nil {
			return nil, err
		}
	}
	destAbs := filepath.Join(dir, filepath.FromSlash(destRel))
	if !overwrite {
		info, err := osfs.StatPath(destAbs)
		if err != nil {
			return nil, pathsafe.Refused("destination cannot be inspected")
		}
		if info.Exist {
			return nil, transfercore.Fail(transfercore.ClassExists, "destination already exists")
		}
	}
	name, err := newStagingName()
	if err != nil {
		return nil, transfercore.Fail(transfercore.ClassInternal, "staging directory could not be created")
	}
	for attempt := 0; attempt < 5; attempt++ {
		err := osfs.CreatePrivateDir(filepath.Join(dir, name))
		if err == nil {
			break
		}
		if attempt == 4 {
			return nil, transfercore.Fail(transfercore.ClassInternal, "staging directory could not be created")
		}
		if err == osfs.ErrDestinationExists {
			if name, err = newStagingName(); err != nil {
				return nil, transfercore.Fail(transfercore.ClassInternal, "staging directory could not be created")
			}
			continue
		}
		return nil, transfercore.Fail(transfercore.ClassInternal, "staging directory could not be created")
	}
	stagingPath := filepath.Join(dir, name)
	identity, err := osfs.PathIdentity(stagingPath)
	info, statErr := osfs.StatPath(stagingPath)
	if err != nil || statErr != nil || !info.Dir {
		_ = os.RemoveAll(stagingPath)
		return nil, transfercore.Fail(transfercore.ClassInternal, "staging directory could not be created")
	}
	return &Staging{
		parent:    dir,
		name:      name,
		path:      stagingPath,
		destRel:   destRel,
		overwrite: overwrite,
		identity:  identity,
	}, nil
}

// newStagingName returns pathsafe.StagingPrefix plus a random hex suffix.
func newStagingName() (string, error) {
	suffix, err := pathsafe.RandomHex(stagingNameDigits)
	if err != nil {
		return "", err
	}
	return pathsafe.StagingPrefix + suffix, nil
}

// stagingNameDigits is the hex digit count of the random staging suffix.
const stagingNameDigits = 12

// Path returns the absolute staging directory path.
func (s *Staging) Path() string { return s.path }

// DestRel returns the destination path relative to the parent directory.
func (s *Staging) DestRel() string { return s.destRel }

// Adopt returns the Staging of an existing staging directory parent/name
// whose identity the caller already verified; destRel is the destination
// name inside parent.
func Adopt(parent, name, destRel string, overwrite bool, identity string) *Staging {
	return &Staging{
		parent: parent, name: name, path: filepath.Join(parent, name), destRel: destRel,
		overwrite: overwrite, identity: identity,
	}
}

// Writable reports whether the staging is still open and its directory is the
// object this job created.
func (s *Staging) Writable() error {
	if s.aborted || s.published {
		return transfercore.Fail(transfercore.ClassInternal, "staging already finished")
	}
	info, err := osfs.StatPath(s.path)
	if err != nil || !info.Exist || !info.Dir {
		return transfercore.Fail(transfercore.ClassInternal, "staging is not a directory")
	}
	if identity, err := osfs.PathIdentity(s.path); err != nil || identity != s.identity {
		return transfercore.Fail(transfercore.ClassInternal, "staging identity changed")
	}
	return nil
}

// verifyStagingName reports whether name matches the staging pattern this
// package creates; it gates every removal.
func verifyStagingName(name string) bool {
	if !strings.HasPrefix(name, pathsafe.StagingPrefix) {
		return false
	}
	suffix := name[len(pathsafe.StagingPrefix):]
	if len(suffix) != 12 {
		return false
	}
	for _, r := range suffix {
		if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

// CreatePayload opens the exclusive 0600 payload file inside the staging dir.
func (s *Staging) CreatePayload() (*os.File, error) {
	if s.aborted || s.published {
		return nil, transfercore.Fail(transfercore.ClassInternal, "staging already finished")
	}
	file, err := osfs.CreateExclusiveFile(filepath.Join(s.path, PayloadName), 0600)
	if err == osfs.ErrDestinationExists {
		return nil, transfercore.Fail(transfercore.ClassInternal, "staging payload already exists")
	}
	if err != nil {
		return nil, transfercore.Fail(transfercore.ClassInternal, "staging payload could not be created")
	}
	return file, nil
}

// prepare re-verifies the staging and destination parent state before any
// publication step; it is the shared guard of publish.go.
func (s *Staging) prepare() (string, error) {
	if s.aborted {
		return "", transfercore.Fail(transfercore.ClassInternal, "staging was already aborted")
	}
	if s.published {
		return "", transfercore.Fail(transfercore.ClassInternal, "staging was already published")
	}
	info, err := osfs.StatPath(s.path)
	if err != nil || !info.Exist || !info.Dir {
		return "", transfercore.Fail(transfercore.ClassInternal, "staging is not a directory")
	}
	identity, err := osfs.PathIdentity(s.path)
	if err != nil || identity != s.identity {
		return "", transfercore.Fail(transfercore.ClassInternal, "staging identity changed")
	}
	pinfo, err := osfs.StatPath(s.parent)
	if err != nil || !pinfo.Exist || !pinfo.Dir || pinfo.Reparse {
		return "", transfercore.Fail(transfercore.ClassInternal, "destination parent changed")
	}
	return filepath.Join(s.parent, filepath.FromSlash(s.destRel)), nil
}

// Publish atomically moves the staged content to the destination.
func (s *Staging) Publish(kind Kind) error {
	destAbs, err := s.prepare()
	if err != nil {
		return err
	}
	if kind == KindFile {
		err = s.publishFile(destAbs)
	} else {
		err = s.publishDir(destAbs)
	}
	if err != nil {
		return err
	}
	// Publication already happened; cleanup and directory sync are
	// best-effort.
	s.published = true
	_ = removeTree(s.path)
	_ = osfs.SyncDirectory(s.parent)
	return nil
}

// Abort removes the staging directory this job created; it is idempotent and
// never touches a published destination.
func (s *Staging) Abort() error {
	if s.aborted || s.published {
		return nil
	}
	if !verifyStagingName(s.name) || s.path != filepath.Join(s.parent, s.name) {
		return transfercore.Fail(transfercore.ClassInternal, "staging name is invalid")
	}
	info, err := osfs.StatPath(s.path)
	if err != nil {
		return transfercore.Fail(transfercore.ClassInternal, "staging could not be removed")
	}
	if !info.Exist {
		s.aborted = true
		return nil
	}
	if !info.Dir || info.Reparse {
		return transfercore.Fail(transfercore.ClassInternal, "staging was replaced by unrelated content")
	}
	current, err := osfs.PathIdentity(s.path)
	if err != nil {
		return transfercore.Fail(transfercore.ClassInternal, "staging could not be removed")
	}
	if current != s.identity {
		return transfercore.Fail(transfercore.ClassInternal, "staging was replaced by unrelated content")
	}
	if err := removeTree(s.path); err != nil {
		return transfercore.Fail(transfercore.ClassInternal, "staging could not be removed")
	}
	s.aborted = true
	return nil
}

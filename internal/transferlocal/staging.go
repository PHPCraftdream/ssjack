package transferlocal

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

// Kind selects what Publish puts at the destination.
type Kind int

const (
	KindFile Kind = iota
	KindDir
)

// payloadName is the fixed inner name of a staged single file.
const payloadName = "payload"

// Staging is one job-owned staging directory inside the destination's parent.
type Staging struct {
	parent    string // absolute destination parent directory
	name      string // staging base name, stagingPrefix + 12 hex chars
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
	if err := validateLocalRelPath(destRel, transfercore.DefaultLimits()); err != nil {
		return nil, err
	}
	if forbiddenRelPath(destRel) {
		return nil, refusedPath("destination contains a forbidden control directory")
	}
	if !filepath.IsAbs(dir) {
		return nil, transfercore.Fail(transfercore.ClassRefusedPath, "staging parent directory must be absolute")
	}
	if err := verifyRealDirTree(dir); err != nil {
		return nil, err
	}
	destParentRel, _ := splitRelName(destRel)
	if destParentRel != "" {
		if err := verifyRealDirTree(filepath.Join(dir, filepath.FromSlash(destParentRel))); err != nil {
			return nil, err
		}
	}
	destAbs := filepath.Join(dir, filepath.FromSlash(destRel))
	if !overwrite {
		info, err := statPath(destAbs)
		if err != nil {
			return nil, refusedPath("destination cannot be inspected")
		}
		if info.exist {
			return nil, transfercore.Fail(transfercore.ClassExists, "destination already exists")
		}
	}
	name, err := newStagingName()
	if err != nil {
		return nil, transfercore.Fail(transfercore.ClassInternal, "staging directory could not be created")
	}
	for attempt := 0; attempt < 5; attempt++ {
		err := createPrivateDir(filepath.Join(dir, name))
		if err == nil {
			break
		}
		if attempt == 4 {
			return nil, transfercore.Fail(transfercore.ClassInternal, "staging directory could not be created")
		}
		if err == errDestinationExists {
			if name, err = newStagingName(); err != nil {
				return nil, transfercore.Fail(transfercore.ClassInternal, "staging directory could not be created")
			}
			continue
		}
		return nil, transfercore.Fail(transfercore.ClassInternal, "staging directory could not be created")
	}
	stagingPath := filepath.Join(dir, name)
	identity, err := pathIdentity(stagingPath)
	info, statErr := statPath(stagingPath)
	if err != nil || statErr != nil || !info.dir {
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

// newStagingName returns stagingPrefix plus a random hex suffix.
func newStagingName() (string, error) {
	suffix, err := randomHex(stagingNameDigits)
	if err != nil {
		return "", err
	}
	return stagingPrefix + suffix, nil
}

// stagingNameDigits is the hex digit count of the random staging suffix.
const stagingNameDigits = 12

// Path returns the absolute staging directory path.
func (s *Staging) Path() string { return s.path }

// DestRel returns the destination path relative to the parent directory.
func (s *Staging) DestRel() string { return s.destRel }

// randomHex returns digits lowercase hex characters from the CSPRNG.
func randomHex(digits int) (string, error) {
	raw := make([]byte, (digits+1)/2)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw)[:digits], nil
}

// verifyStagingName reports whether name matches the staging pattern this
// package creates; it gates every removal.
func verifyStagingName(name string) bool {
	if !strings.HasPrefix(name, stagingPrefix) {
		return false
	}
	suffix := name[len(stagingPrefix):]
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
	file, err := createExclusiveFile(filepath.Join(s.path, payloadName), 0600)
	if err == errDestinationExists {
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
	info, err := statPath(s.path)
	if err != nil || !info.exist || !info.dir {
		return "", transfercore.Fail(transfercore.ClassInternal, "staging is not a directory")
	}
	identity, err := pathIdentity(s.path)
	if err != nil || identity != s.identity {
		return "", transfercore.Fail(transfercore.ClassInternal, "staging identity changed")
	}
	pinfo, err := statPath(s.parent)
	if err != nil || !pinfo.exist || !pinfo.dir || pinfo.reparse {
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
	_ = syncDirectory(s.parent)
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
	info, err := statPath(s.path)
	if err != nil {
		return transfercore.Fail(transfercore.ClassInternal, "staging could not be removed")
	}
	if !info.exist {
		s.aborted = true
		return nil
	}
	if !info.dir || info.reparse {
		return transfercore.Fail(transfercore.ClassInternal, "staging was replaced by unrelated content")
	}
	current, err := pathIdentity(s.path)
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

package recoveryjournal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/PHPCraftdream/ssjack/internal/recovery"
	"io"
	"os"
	"path/filepath"
	"time"
)

var ErrUnavailable = errors.New("durable recovery journal unavailable")
var errJournalTooLarge = errors.New("journal exceeds size limit")

const maxJournal = 64 * 1024
const maxEntries = 7

type record struct {
	Intent  recovery.Intent    `json:"intent"`
	Blocked []recovery.Binding `json:"blocked"`
}
type document struct {
	Version int      `json:"version"`
	Records []record `json:"records"`
	Digest  string   `json:"digest"`
}
type Journal struct {
	root     string
	wait     time.Duration
	mu       chan struct{}
	poisoned bool
	io       diskIO
	last     document
}

func Initialize(root string, wait time.Duration) (*Journal, error) {
	return initialize(root, wait, systemIO())
}

func initialize(root string, wait time.Duration, disk diskIO) (*Journal, error) {
	if !supported() || root == "" || !filepath.IsAbs(root) || wait <= 0 || wait > 30*time.Second {
		return nil, ErrUnavailable
	}
	if err := os.Mkdir(root, 0700); err != nil {
		return nil, ErrUnavailable
	}
	j := &Journal{root: root, wait: wait, mu: make(chan struct{}, 1), io: disk}
	if j.io.syncDir(filepath.Dir(root)) != nil {
		j.poisoned = true
		return nil, ErrUnavailable
	}
	if err := j.publish(document{Version: 1, Records: []record{}}); err != nil {
		return nil, err
	}
	return j, nil
}
func (j *Journal) path() string { return filepath.Join(j.root, "journal.json") }
func digest(d document) string {
	d.Digest = ""
	b, _ := json.Marshal(d)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func validDoc(d document) bool {
	if d.Version != 1 || len(d.Records) > maxEntries {
		return false
	}
	originalInv, originalRes := map[string]bool{}, map[string]bool{}
	blockedInv, blockedRes := map[string]bool{}, map[string]bool{}
	for _, r := range d.Records {
		b := r.Intent.Binding
		if !recovery.ValidBinding(b) || r.Intent.Phase < recovery.Prepared || r.Intent.Phase > recovery.Quarantined || (r.Intent.Phase == recovery.Quarantined) != (len(r.Blocked) > 0) || (r.Intent.Phase == recovery.Quarantined && len(r.Blocked) > 2) {
			return false
		}
		if originalInv[b.Invocation] || originalRes[b.Resource] {
			return false
		}
		originalInv[b.Invocation], originalRes[b.Resource] = true, true
		seen := map[recovery.Binding]bool{}
		if len(r.Blocked) > 0 {
			foundSelf := false
			for _, x := range r.Blocked {
				if !recovery.ValidBinding(x) || seen[x] {
					return false
				}
				seen[x] = true
				if x == b {
					foundSelf = true
				}
				blockedInv[x.Invocation], blockedRes[x.Resource] = true, true
			}
			if !foundSelf {
				return false
			}
		}
	}
	for _, r := range d.Records {
		b := r.Intent.Binding
		if blockedInv[b.Invocation] || blockedRes[b.Resource] {
			if r.Intent.Phase != recovery.Quarantined {
				return false
			}
		}
	}
	return true
}
func readBounded(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxJournal+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxJournal {
		return nil, errJournalTooLarge
	}
	return b, nil
}

func (j *Journal) load() (document, error) {
	if j.poisoned {
		return document{}, ErrUnavailable
	}
	if _, err := os.Lstat(j.pendingPath()); err == nil || !errors.Is(err, os.ErrNotExist) {
		j.poisoned = true
		return document{}, ErrUnavailable
	}
	if _, err := os.Lstat(j.newPath()); err == nil || !errors.Is(err, os.ErrNotExist) {
		j.poisoned = true
		return document{}, ErrUnavailable
	}
	st, e := os.Lstat(j.path())
	if e != nil || !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 {
		j.poisoned = true
		return document{}, ErrUnavailable
	}
	f, e := os.Open(j.path())
	if e != nil {
		j.poisoned = true
		return document{}, ErrUnavailable
	}
	b, e := readBounded(f)
	c := f.Close()
	if e != nil || c != nil {
		j.poisoned = true
		return document{}, ErrUnavailable
	}
	var d document
	if json.Unmarshal(b, &d) != nil || !validDoc(d) || d.Digest != digest(d) {
		j.poisoned = true
		return document{}, ErrUnavailable
	}
	want, _ := json.Marshal(d)
	if string(want) != string(b) || (j.last.Version != 0 && string(mustJSON(d)) != string(mustJSON(j.last))) {
		j.poisoned = true
		return document{}, ErrUnavailable
	}
	return d, nil
}
func mustJSON(d document) []byte { b, _ := json.Marshal(d); return b }
func (j *Journal) publish(d document) error {
	return j.publishDocument(d)
}

func (j *Journal) lock(ctx context.Context) error {
	t := time.NewTimer(j.wait)
	defer t.Stop()
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	select {
	case j.mu <- struct{}{}:
		if ctx.Err() != nil {
			j.unlock()
			return ErrUnavailable
		}
		return nil
	case <-ctx.Done():
		return ErrUnavailable
	case <-t.C:
		return ErrUnavailable
	}
}
func (j *Journal) unlock() { <-j.mu }
func (j *Journal) mutate(ctx context.Context, fn func(*document) error) error {
	if e := j.lock(ctx); e != nil {
		return e
	}
	defer j.unlock()
	d, e := j.load()
	if e != nil {
		return e
	}
	if e = fn(&d); e != nil {
		return e
	}
	return j.publish(d)
}
func (j *Journal) LoadIntent(ctx context.Context, id string) (recovery.Intent, error) {
	if e := j.lock(ctx); e != nil {
		return recovery.Intent{}, e
	}
	defer j.unlock()
	d, e := j.load()
	if e != nil {
		return recovery.Intent{}, e
	}
	var found recovery.Intent
	foundIntent := false
	for _, r := range d.Records {
		for _, b := range r.Blocked {
			if b.Invocation == id {
				return recovery.Intent{}, recovery.ErrQuarantined
			}
		}
		if r.Intent.Binding.Invocation == id {
			found, foundIntent = r.Intent, true
		}
	}
	if foundIntent {
		return found, nil
	}
	return recovery.Intent{}, recovery.ErrNotFound
}
func conflicts(r record, b recovery.Binding) bool {
	for _, x := range r.Blocked {
		if x.Invocation == b.Invocation || x.Resource == b.Resource {
			return true
		}
	}
	return false
}
func (j *Journal) PutIntent(ctx context.Context, i recovery.Intent) error {
	if i.Phase != recovery.Prepared {
		return recovery.ErrConflict
	}
	if !recovery.ValidBinding(i.Binding) {
		return recovery.ErrConflict
	}
	return j.mutate(ctx, func(d *document) error {
		for _, r := range d.Records {
			if conflicts(r, i.Binding) {
				return recovery.ErrQuarantined
			}
		}
		for _, r := range d.Records {
			if r.Intent.Binding == i.Binding && r.Intent.Phase == recovery.Prepared && len(r.Blocked) == 0 {
				return nil
			}
			if r.Intent.Binding.Invocation == i.Binding.Invocation || r.Intent.Binding.Resource == i.Binding.Resource {
				return recovery.ErrConflict
			}
		}
		if len(d.Records) >= maxEntries {
			return ErrUnavailable
		}
		d.Records = append(d.Records, record{Intent: i})
		return nil
	})
}
func (j *Journal) SetPhase(ctx context.Context, id string, p recovery.Phase) error {
	if p != recovery.Committed {
		return recovery.ErrConflict
	}
	return j.mutate(ctx, func(d *document) error {
		idx := -1
		for n := range d.Records {
			if d.Records[n].Intent.Binding.Invocation == id {
				idx = n
				break
			}
		}
		if idx < 0 {
			return recovery.ErrNotFound
		}
		target := &d.Records[idx]
		for _, r := range d.Records {
			if conflicts(r, target.Intent.Binding) {
				return recovery.ErrQuarantined
			}
		}
		if target.Intent.Phase == p {
			return nil
		}
		if target.Intent.Phase != recovery.Prepared {
			return recovery.ErrConflict
		}
		target.Intent.Phase = p
		return nil
	})
}

package approvals

import (
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/vault"
)

type vaultOps interface {
	ListApplicationApprovals() ([]vault.Approval, error)
	ApproveApplication(vault.Approval, string) error
	RevokeApplication(string) error
}

type Mutation struct {
	Kind       string
	Name, Path string
	Hash       string
	Replaces   string
}

type Controller struct {
	entries             []Entry
	records             []vault.Approval
	cursor              int
	rejections          map[string]bool
	vault               vaultOps
	snapshot            func() error
	sessionSnapshotDone bool
	workingDir, message string
	armed               string
	pending             Mutation
	pendingOK           bool
}

func New(v *vault.Vault, workingDir string, snapshot func() error) *Controller {
	c := &Controller{cursor: -1, rejections: make(map[string]bool), workingDir: workingDir, snapshot: snapshot}
	if v != nil {
		c.vault = v
	}
	return c
}

func (c *Controller) Entries() []Entry { return append([]Entry(nil), c.entries...) }
func (c *Controller) Cursor() int      { return c.cursor }
func (c *Controller) Message() string  { return c.message }
func (c *Controller) SetRecords(records []vault.Approval) {
	c.records = append([]vault.Approval(nil), records...)
}
func (c *Controller) ArmedAction() string       { return c.armed }
func (c *Controller) ClearMessage()             { c.message = "" }
func (c *Controller) Pending() (Mutation, bool) { return c.pending, c.pendingOK }

func (c *Controller) SnapshotBeforeFirstWrite() error {
	if c.sessionSnapshotDone {
		return nil
	}
	if c.snapshot == nil {
		c.sessionSnapshotDone = true
		return nil
	}
	if c.snapshot() != nil {
		return c.fail("snapshot_failed")
	}
	c.sessionSnapshotDone = true
	return nil
}

func (c *Controller) Refresh() {
	var records []vault.Approval
	if c.vault != nil {
		records, _ = c.vault.ListApplicationApprovals()
	} else {
		records = append([]vault.Approval(nil), c.records...)
	}
	c.entries = List(c.workingDir, records)
	for i := range c.entries {
		if c.entries[i].Record.Name != "" {
			delete(c.rejections, filepath.Clean(c.entries[i].Record.Path))
			continue
		}
		if c.entries[i].candidate != nil && c.rejections[filepath.Clean(c.entries[i].candidate.CanonicalPath)] {
			c.entries[i].Status = StatusRejected
		}
	}
	if c.pendingOK {
		if index := c.pinnedEntryIndex(); index < 0 {
			c.clearPin()
			c.message = "review_stale"
		} else {
			c.cursor = index
			if c.pending.Kind == "approve" && c.entries[index].candidate != nil {
				c.pending.Path = c.entries[index].candidate.CanonicalPath
			}
		}
	}
	if c.cursor >= len(c.entries) {
		c.cursor = -1
	}
}

func (c *Controller) pinMatches() bool { return c.pinnedEntryIndex() >= 0 }

func (c *Controller) pinnedEntryIndex() int {
	for i, e := range c.entries {
		if c.pending.Kind == "revoke" && e.candidate == nil {
			if filepath.Clean(e.Record.Path) == filepath.Clean(c.pending.Path) &&
				(e.Status == StatusApproved || e.Status == StatusChanged) &&
				e.Record.Name == c.pending.Name && e.Record.Hash == c.pending.Replaces {
				return i
			}
			continue
		}
		if e.candidate == nil {
			continue
		}
		if c.pending.Kind == "approve" || c.pending.Kind == "reject" {
			if e.candidate.Name != c.pending.Name {
				continue
			}
		} else if filepath.Clean(e.candidate.CanonicalPath) != filepath.Clean(c.pending.Path) {
			continue
		}
		if hex.EncodeToString(e.candidate.Fingerprint[:]) != c.pending.Hash {
			continue
		}
		switch c.pending.Kind {
		case "approve":
			if e.Status != StatusCandidate && e.Status != StatusChanged {
				continue
			}
			return i
		case "revoke":
			if (e.Status == StatusApproved || e.Status == StatusChanged) && e.Record.Name == c.pending.Name && e.Record.Hash == c.pending.Replaces {
				return i
			}
			continue
		case "reject":
			if e.Status != StatusCandidate || e.candidate.Name != c.pending.Name {
				continue
			}
			return i
		}
		return -1
	}
	return -1
}

func (c *Controller) Select(i int) {
	if i < 0 || i >= len(c.entries) {
		c.cursor = -1
	} else {
		c.cursor = i
	}
	c.clearPin()
}
func (c *Controller) Arm() {
	if e := c.selected(); e != nil {
		c.makeApprovePin(e)
	}
}
func (c *Controller) makeApprovePin(e *Entry) {
	if e.candidate == nil || (e.Status != StatusCandidate && e.Status != StatusChanged) {
		c.clearPin()
		c.fail("not_approvable")
		return
	}
	replaces := ""
	if e.Status == StatusChanged {
		replaces = e.Record.Hash
	}
	c.arm(Mutation{Kind: "approve", Name: e.candidate.Name, Path: e.candidate.CanonicalPath, Hash: hex.EncodeToString(e.candidate.Fingerprint[:]), Replaces: replaces})
}
func (c *Controller) arm(m Mutation) {
	c.pending, c.pendingOK, c.armed = m, true, m.Kind
	c.message = "confirmation_required"
}
func (c *Controller) clearPin() { c.pending = Mutation{}; c.pendingOK = false; c.armed = "" }

func (c *Controller) ConfirmApprove() error {
	if !c.pendingOK && c.armed == "approve" {
		if e := c.selected(); e != nil {
			c.makeApprovePin(e)
		}
	}
	if !c.pendingOK || c.pending.Kind != "approve" {
		return c.fail("confirmation_required")
	}
	return c.runPending(c.vault)
}
func (c *Controller) Reject() {
	if e := c.selected(); e != nil {
		if e.Record.Name != "" || e.Status == StatusApproved {
			c.clearPin()
			c.fail("reject_approved")
			return
		}
		if e.candidate == nil {
			c.clearPin()
			c.fail("not_rejectable")
			return
		}
		c.arm(Mutation{Kind: "reject", Name: e.candidate.Name, Path: e.candidate.CanonicalPath, Hash: hex.EncodeToString(e.candidate.Fingerprint[:])})
	}
}
func (c *Controller) RejectConfirm() error {
	if !c.pendingOK && c.armed == "reject" {
		c.Reject()
	}
	if !c.pendingOK || c.pending.Kind != "reject" {
		return c.fail("confirmation_required")
	}
	if !c.pinMatches() {
		c.clearPin()
		return c.fail("review_stale")
	}
	c.rejections[filepath.Clean(c.pending.Path)] = true
	c.Complete(nil)
	return nil
}
func (c *Controller) Revoke() {
	if e := c.selected(); e != nil {
		if e.Record.Name == "" || (e.Status != StatusApproved && e.Status != StatusChanged) {
			c.clearPin()
			c.fail("not_revokeable")
			return
		}
		path, hash := e.Record.Path, e.Record.Hash
		if e.candidate != nil {
			path = e.candidate.CanonicalPath
			hash = hex.EncodeToString(e.candidate.Fingerprint[:])
		}
		c.arm(Mutation{Kind: "revoke", Name: e.Record.Name, Path: path, Hash: hash, Replaces: e.Record.Hash})
	}
}
func (c *Controller) RevokeConfirm() error {
	if !c.pendingOK && c.armed == "revoke" {
		if e := c.selected(); e != nil {
			c.Revoke()
		}
	}
	if !c.pendingOK || c.pending.Kind != "revoke" {
		return c.fail("confirmation_required")
	}
	return c.runPending(c.vault)
}
func (c *Controller) runPending(ops vaultOps) error {
	if !c.pinMatches() {
		c.clearPin()
		return c.fail("review_stale")
	}
	if ops == nil {
		return c.fail("vault_unavailable")
	}
	if err := c.SnapshotBeforeFirstWrite(); err != nil {
		c.clearPin()
		return err
	}
	err := ApplyVerified(ops, c.pending)
	c.Complete(err)
	return err
}
func (c *Controller) Complete(err error) {
	kind := c.pending.Kind
	c.clearPin()
	if err != nil {
		c.sessionSnapshotDone = false
		c.message = err.Error()
		return
	}
	if kind == "reject" {
		c.message = "rejected"
		c.Refresh()
		return
	}
	if kind == "approve" {
		c.message = "approved"
	} else if kind == "revoke" {
		c.message = "revoked"
	}
	c.Refresh()
}

// VerifyRevoke refuses unless the currently stored record still equals the reviewed pin.
func VerifyRevoke(ops vaultOps, m Mutation) error {
	if m.Kind == "approve" {
		return nil
	}
	if m.Kind != "revoke" {
		return errors.New("mutation_invalid")
	}
	if ops == nil {
		return errors.New("revoke_stale")
	}
	records, err := ops.ListApplicationApprovals()
	if err != nil {
		return errors.New("revoke_stale")
	}
	for _, record := range records {
		if record.Name != m.Name {
			continue
		}
		if filepath.Clean(record.Path) != filepath.Clean(m.Path) || record.Hash != m.Replaces {
			return errors.New("revoke_stale")
		}
		return nil
	}
	return errors.New("revoke_stale")
}

// ApplyVerified verifies revocations against the live record, then applies.
func ApplyVerified(ops vaultOps, m Mutation) error {
	if m.Kind == "approve" {
		return ApplyMutation(ops, m)
	}
	if m.Kind != "revoke" {
		return errors.New("mutation_invalid")
	}
	if err := VerifyRevoke(ops, m); err != nil {
		return err
	}
	if err := ops.RevokeApplication(m.Name); err != nil {
		return errors.New("revoke_failed")
	}
	return nil
}

func ApplyMutation(ops vaultOps, m Mutation) error {
	if m.Kind == "approve" {
		if vault.ValidateApprovalName(m.Name) != nil {
			return errors.New("name_invalid")
		}
		if err := validPath(m.Path); err != nil {
			if len(m.Path) > 512 {
				return errors.New("path_limit_exceeded")
			}
			return errors.New("path_invalid")
		}
		if ops == nil {
			return errors.New("vault_unavailable")
		}
		if err := ops.ApproveApplication(vault.Approval{Name: m.Name, Path: m.Path, Hash: m.Hash}, m.Replaces); err != nil {
			return errors.New(mapVaultError(err))
		}
		return nil
	}
	if m.Kind == "revoke" {
		if ops == nil {
			return errors.New("revoke_failed")
		}
		if err := ops.RevokeApplication(m.Name); err != nil {
			return errors.New("revoke_failed")
		}
		return nil
	}
	return errors.New("mutation_invalid")
}
func (c *Controller) Cancel() { c.clearPin(); c.message = "cancelled" }
func (c *Controller) Confirm(input string) error {
	if input == "" || input != "confirm" {
		c.Cancel()
		return errors.New("cancelled")
	}
	return c.ConfirmApprove()
}
func (c *Controller) selected() *Entry {
	if c.cursor < 0 || c.cursor >= len(c.entries) {
		return nil
	}
	return &c.entries[c.cursor]
}
func (c *Controller) fail(message string) error { c.message = message; return errors.New(message) }
func validPath(p string) error {
	if p == "" || len(p) > 512 {
		return errors.New("path_invalid")
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x20 || p[i] == 0x7f {
			return errors.New("path_invalid")
		}
	}
	if !filepath.IsAbs(p) || p != filepath.Clean(p) {
		return errors.New("path_invalid")
	}
	return nil
}
func mapVaultError(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "too many application approvals"):
		return "approval_limit_reached"
	case strings.Contains(s, "512 bytes"):
		return "path_limit_exceeded"
	case strings.Contains(s, "replaced approval does not match"), strings.Contains(s, "approval does not exist"):
		return "approval_changed_retry"
	case strings.Contains(s, "already exists"):
		return "approval_exists"
	default:
		return "approval_failed"
	}
}

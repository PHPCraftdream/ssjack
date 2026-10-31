package appstorecrypto

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchortls"
	"github.com/PHPCraftdream/ssjack/internal/appstorebudget"
	"github.com/PHPCraftdream/ssjack/internal/appstoreentry"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstoreheader"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/appstoresink"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
)

var ErrDelivery = errors.New("confidential delivery denied")

type pinnedSnapshotState struct {
	mu       sync.Mutex
	file     *os.File
	revision appstorefile.Revision
	expected ExpectedSnapshot
	checked  SnapshotCheck
}
type pinnedSnapshot struct{ state *pinnedSnapshotState }

// Private until an authenticated enrollment path can own consumer configuration.
func (m *Master) deliverCurrent(ctx context.Context, directory *appstorefile.Directory, anchor interface {
	Read(context.Context) (appstoreanchorreply.Reply, error)
}, reference appstoreref.Ref, consumer *appstoresink.Consumer, checks ...func() error) (appstoresink.Result, error) {
	if ctx == nil || directory == nil || anchor == nil || consumer == nil {
		return appstoresink.Result{}, ErrSnapshot
	}
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		for _, fn := range checks {
			if fn != nil {
				if err := fn(); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := check(); err != nil {
		return appstoresink.Result{}, err
	}
	binding := consumer.Binding()
	if err := check(); err != nil {
		return appstoresink.Result{}, err
	}
	if directory.StoreID() != reference.StoreID() {
		return appstoresink.Result{}, ErrSnapshot
	}
	if err := consumer.Check(reference, binding.EncodedHash); err != nil {
		return appstoresink.Result{}, err
	}
	release, err := appstorebudget.TryAcquire(reference.StoreID())
	if err != nil {
		return appstoresink.Result{}, ErrBusy
	}
	defer release()
	tx, err := directory.Lock()
	if err != nil {
		return appstoresink.Result{}, err
	}
	defer tx.Close()
	reply, err := anchor.Read(ctx)
	if err != nil {
		return appstoresink.Result{}, err
	}
	state, present := reply.State()
	if !reply.SignatureValid() || reply.Outcome() != appstoreanchorreply.ReadState || !present || state.StoreID() != reference.StoreID() || state.CommittedSnapshotID() != reference.SnapshotID() || state.CommittedFileHash() != binding.EncodedHash {
		return appstoresink.Result{}, ErrSnapshot
	}
	if err := check(); err != nil {
		return appstoresink.Result{}, err
	}
	pointer, err := tx.ReadPointer()
	if err != nil {
		return appstoresink.Result{}, err
	}
	var wanted [64]byte
	snapshot, encoded, transaction := state.CommittedSnapshotID(), state.CommittedFileHash(), state.CommittedTransactionID()
	copy(wanted[:16], snapshot[:])
	copy(wanted[16:48], encoded[:])
	copy(wanted[48:], transaction[:])
	if pointer != wanted {
		return appstoresink.Result{}, ErrWriterPointerLag
	}
	spool, err := m.pinSnapshot(ctx, tx, ExpectedSnapshot{StoreID: state.StoreID(), SnapshotID: snapshot, EncodedHash: encoded})
	if err != nil {
		return appstoresink.Result{}, err
	}
	defer spool.close()
	entry, err := appstoreref.FindMetadata(reference, spool.state.checked.Catalog())
	if err != nil {
		return appstoresink.Result{}, err
	}
	if err = spool.recheck(ctx); err != nil {
		return appstoresink.Result{}, err
	}
	if err := check(); err != nil {
		return appstoresink.Result{}, err
	}
	if err = consumer.Check(reference, encoded); err != nil {
		return appstoresink.Result{}, err
	}
	if err := check(); err != nil {
		return appstoresink.Result{}, err
	}
	// Preserve the signed anchor snapshot and writer pointer through full verification.
	fresh, err := anchor.Read(ctx)
	if err != nil {
		return appstoresink.Result{}, err
	}
	freshState, freshPresent := fresh.State()
	if !fresh.SignatureValid() || fresh.Outcome() != appstoreanchorreply.ReadState || !freshPresent || !freshState.Valid() || freshState.Hash() != state.Hash() {
		return appstoresink.Result{}, ErrSnapshot
	}
	freshPointer, err := tx.ReadPointer()
	if err != nil || freshPointer != wanted {
		return appstoresink.Result{}, ErrWriterPointerLag
	}
	session, err := consumer.Begin(ctx, reference, encoded, entry.Length())
	if err != nil {
		return appstoresink.Result{}, err
	}
	defer session.Close()
	result, err := m.streamPinnedObject(ctx, spool, entry, session, check)
	if err != nil {
		return result, err
	}
	if err = spool.recheck(ctx); err != nil {
		return result, err
	}
	if err := check(); err != nil {
		return result, err
	}
	if err := consumer.Check(reference, encoded); err != nil {
		return result, err
	}
	if err := check(); err != nil {
		return result, err
	}
	return session.Finish()
}

func (m *Master) pinSnapshot(ctx context.Context, tx *appstorefile.Transaction, expected ExpectedSnapshot) (*pinnedSnapshot, error) {
	if ctx == nil || tx == nil || expected.StoreID == ([16]byte{}) || expected.SnapshotID == ([16]byte{}) || expected.EncodedHash == ([32]byte{}) {
		return nil, ErrSnapshot
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	source, err := tx.OpenSnapshot(expected.SnapshotID)
	if err != nil {
		return nil, err
	}
	defer source.Close()
	before, err := appstorefile.Stat(source)
	if err != nil {
		return nil, err
	}
	var raw [appstoreheader.Size]byte
	if err = snapshotRead(ctx, source, raw[:]); err != nil {
		return nil, err
	}
	h, err := appstoreheader.Parse(raw[:])
	if err != nil || h.StoreID() != expected.StoreID || h.SnapshotID() != expected.SnapshotID || before.Size != int64(h.EncodedSize()) || !m.Matches(h) {
		return nil, ErrSnapshot
	}
	if _, err = source.Seek(0, io.SeekStart); err != nil {
		return nil, ErrSnapshotRead
	}
	spool, err := tx.Temporary()
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = spool.Close()
		}
	}()
	buffer := make([]byte, 32768)
	defer clear(buffer)
	hash := sha256.New()
	for left := h.EncodedSize(); left > 0; {
		n := uint64(len(buffer))
		if n > left {
			n = left
		}
		if err = snapshotRead(ctx, source, buffer[:n]); err != nil {
			return nil, err
		}
		if written, e := spool.Write(buffer[:n]); e != nil || written != int(n) {
			return nil, ErrSnapshotRead
		}
		_, _ = hash.Write(buffer[:n])
		left -= n
	}
	if err = snapshotEOF(ctx, source); err != nil {
		return nil, err
	}
	after, err := appstorefile.Stat(source)
	if err != nil || before != after {
		return nil, ErrSnapshot
	}
	var encoded [32]byte
	copy(encoded[:], hash.Sum(nil))
	if encoded != expected.EncodedHash {
		return nil, ErrSnapshot
	}
	revision, err := appstorefile.StatTemporary(spool)
	if err != nil || revision.Size != before.Size {
		return nil, ErrSnapshot
	}
	if _, err = spool.Seek(0, io.SeekStart); err != nil {
		return nil, ErrSnapshotRead
	}
	check, err := m.checkSnapshot(ctx, spool, expected)
	if err != nil {
		return nil, err
	}
	p := &pinnedSnapshot{state: &pinnedSnapshotState{file: spool, revision: revision, expected: expected, checked: check}}
	if err = p.recheck(ctx); err != nil {
		return nil, err
	}
	keep = true
	return p, nil
}
func (p *pinnedSnapshot) recheck(ctx context.Context) error {
	if p == nil || p.state == nil || ctx == nil {
		return ErrSnapshot
	}
	s := p.state
	if !s.mu.TryLock() {
		return ErrBusy
	}
	defer s.mu.Unlock()
	if s.file == nil || !s.checked.Valid() {
		return ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	before, err := appstorefile.StatTemporary(s.file)
	if err != nil || before != s.revision {
		return ErrSnapshot
	}
	if _, err = s.file.Seek(0, io.SeekStart); err != nil {
		return ErrSnapshotRead
	}
	buffer := make([]byte, 32768)
	defer clear(buffer)
	hash := sha256.New()
	for left := uint64(s.revision.Size); left > 0; {
		n := uint64(len(buffer))
		if n > left {
			n = left
		}
		if err = snapshotRead(ctx, s.file, buffer[:n]); err != nil {
			return err
		}
		_, _ = hash.Write(buffer[:n])
		left -= n
	}
	if err = snapshotEOF(ctx, s.file); err != nil {
		return err
	}
	after, err := appstorefile.StatTemporary(s.file)
	if err != nil || before != after {
		return ErrSnapshot
	}
	var got [32]byte
	copy(got[:], hash.Sum(nil))
	if got != s.expected.EncodedHash {
		return ErrSnapshot
	}
	if _, err = s.file.Seek(0, io.SeekStart); err != nil {
		return ErrSnapshotRead
	}
	return ctx.Err()
}
func (p *pinnedSnapshot) close() error {
	if p == nil || p.state == nil {
		return nil
	}
	s := p.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	s.checked = SnapshotCheck{}
	return err
}

type DeliveryStatus uint8

const (
	DeliveryWithheld DeliveryStatus = iota + 1
	DeliveryReceived
	DeliveryUnknown
)

type DeliveryOutcome struct{ Status DeliveryStatus }
type DeliveryPlan struct{ state *deliveryPlanState }
type deliveryPlanState struct {
	owner   *DeliveryCapability
	binding OperationBinding
	used    bool
}
type OperationBinding struct {
	SessionID, PlanID, Digest string
	ObservedRevision          string
	Policy                    string
	Deadline                  time.Time
}
type DeliveryCapability struct {
	mu              sync.Mutex
	operationMu     sync.Mutex
	operationCancel context.CancelFunc
	boundSession    string
	tuples          map[string]bool
	installation    *Installation
	ref             appstoreref.Ref
	grant           declarativeauthority.DeliveryGrant
	store           *appstoreentry.Store
	directory       *appstorefile.Directory
	anchor          *appstoreanchortls.Writer
	used            map[string]bool
	closed          bool
}

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func canonicalID(s string) bool {
	id, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(id) == 16 && base64.RawURLEncoding.EncodeToString(id) == s
}

func (c *DeliveryCapability) Metadata() (declarativeauthority.DeliveryGrant, appstoreref.Ref) {
	if c == nil {
		return declarativeauthority.DeliveryGrant{}, appstoreref.Ref{}
	}
	return c.grant, c.ref
}
func (c *DeliveryCapability) Check(ctx context.Context) error {
	if ctx == nil || c == nil {
		return ErrDelivery
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || ctx.Err() != nil || c.installation == nil || c.installation.master == nil || c.installation.master.Closed() {
		return ErrDelivery
	}
	if g := c.grant; !digestPattern.MatchString(g.DriverCodeSHA256) || !digestPattern.MatchString(g.ConsumerSHA256) || !digestPattern.MatchString(g.EncodedHash) {
		return ErrDelivery
	}
	if dig, e := declarativeauthority.DeliveryDriverDigest(); e != nil || dig != c.grant.DriverCodeSHA256 {
		return ErrDelivery
	}
	if dig, e := declarativeauthority.DeliveryCodeDigest(); e != nil || dig != c.grant.ConsumerSHA256 {
		return ErrDelivery
	}
	if !c.grant.Active(time.Now()) || c.grant.RecipientUID != os.Geteuid() {
		return ErrDelivery
	}
	placeholder, err := appstoreplaceholder.Encode(c.ref)
	if err != nil {
		return ErrDelivery
	}
	s, err := declarativeauthority.LoadDelivery(string(placeholder), os.Geteuid(), time.Now())
	clear(placeholder)
	if err != nil {
		return ErrDelivery
	}
	g := s.Grants()
	if len(g) != 1 || g[0] != c.grant {
		return ErrDelivery
	}
	if err := c.store.VerifyUnchanged(c.installation.encodedHash); err != nil {
		return ErrDelivery
	}
	dev, ino, err := c.store.Identity()
	if err != nil || dev != c.grant.DirectoryDev || ino != c.grant.DirectoryIno || !c.installation.DirectoryMatches(dev, ino) {
		return ErrDelivery
	}
	return ctx.Err()
}
func (c *DeliveryCapability) Prepare(ctx context.Context, operation OperationBinding) *DeliveryPlan {
	if c == nil || ctx == nil || !canonicalID(operation.SessionID) || !canonicalID(operation.PlanID) || !digestPattern.MatchString(operation.Digest) || len(operation.ObservedRevision) == 0 || len(operation.ObservedRevision) > 128 || operation.Policy != declarativeauthority.DeliveryPolicyRevision || operation.Deadline.IsZero() || operation.Deadline.Location() == nil {
		return nil
	}
	if !operation.Deadline.After(time.Now()) || operation.Deadline.After(time.Now().Add(time.Minute)) || c.Check(ctx) != nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || (c.boundSession != "" && c.boundSession != operation.SessionID) || len(c.tuples) >= 128 || c.tuples[operation.PlanID] {
		return nil
	}
	c.boundSession = operation.SessionID
	c.tuples[operation.PlanID] = true
	return &DeliveryPlan{state: &deliveryPlanState{owner: c, binding: operation}}
}
func (c *DeliveryCapability) Deliver(ctx context.Context, plan *DeliveryPlan, operationID string, lease *declarativeauthority.TargetLease) DeliveryOutcome {
	if c == nil || ctx == nil || plan == nil || plan.state == nil || lease == nil || !canonicalID(operationID) {
		return DeliveryOutcome{DeliveryWithheld}
	}
	state := plan.state
	if state.owner != c {
		return DeliveryOutcome{DeliveryWithheld}
	}
	operation := state.binding
	if !c.operationMu.TryLock() {
		return DeliveryOutcome{DeliveryWithheld}
	}
	defer c.operationMu.Unlock()
	if !operation.Deadline.After(time.Now()) || operation.Deadline.After(time.Now().Add(time.Minute)) {
		return DeliveryOutcome{DeliveryWithheld}
	}
	deadlineCtx, cancel := context.WithDeadline(ctx, operation.Deadline)
	defer cancel()
	c.mu.Lock()
	if c.closed || state.used || c.used[operationID] || len(c.used) >= 128 || c.boundSession != operation.SessionID {
		c.mu.Unlock()
		return DeliveryOutcome{DeliveryWithheld}
	}
	state.used = true
	c.used[operationID] = true
	c.operationCancel = cancel
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.operationCancel = nil; c.mu.Unlock() }()
	ctx = deadlineCtx
	if lease.CheckReference(ctx, operation.ObservedRevision, operationID, operation.Digest, c.grant.Ref) != nil {
		return DeliveryOutcome{DeliveryWithheld}
	}
	if err := c.Check(ctx); err != nil {
		return DeliveryOutcome{DeliveryWithheld}
	}
	grantExpiry, err := time.Parse(time.RFC3339, c.grant.ExpiresAt)
	if err != nil {
		return DeliveryOutcome{DeliveryWithheld}
	}
	expires := grantExpiry
	if !operation.Deadline.IsZero() && operation.Deadline.Before(expires) {
		expires = operation.Deadline
	}
	if expires.After(time.Now().Add(24 * time.Hour)) {
		expires = time.Now().Add(24 * time.Hour)
	}
	if !expires.After(time.Now()) {
		return DeliveryOutcome{DeliveryWithheld}
	}
	consumerHash, err := hex.DecodeString(c.grant.ConsumerSHA256)
	if err != nil || len(consumerHash) != 32 {
		return DeliveryOutcome{DeliveryWithheld}
	}
	var artifact [32]byte
	copy(artifact[:], consumerHash)
	fixed := func(s string) [32]byte { return sha256.Sum256([]byte(s)) }
	sinkBinding := appstoresink.Binding{Reference: c.ref, EncodedHash: mustDigest(c.grant.EncodedHash), ArtifactHash: artifact, Target: fixed(c.grant.Target), Purpose: fixed(c.grant.Purpose), Revision: fixed(c.grant.PolicyRevision), ExpiresAt: expires}
	program, err := os.Open(declarativeauthority.ConsumerPath)
	if err != nil {
		return DeliveryOutcome{DeliveryWithheld}
	}
	defer program.Close()
	consumer, err := appstoresink.New(appstoresink.Config{Program: program, Binding: sinkBinding})
	if err != nil {
		return DeliveryOutcome{DeliveryWithheld}
	}
	defer consumer.Close()
	result, err := c.installation.master.deliverCurrent(ctx, c.directory, c.anchor, c.ref, consumer, func() error { return c.Check(ctx) }, func() error {
		return lease.CheckReference(ctx, operation.ObservedRevision, operationID, operation.Digest, c.grant.Ref)
	})
	if err == nil && result.Complete {
		return DeliveryOutcome{DeliveryReceived}
	}
	if result.MayHaveDelivered || result.Bytes > 0 {
		return DeliveryOutcome{DeliveryUnknown}
	}
	if err != nil {
		return DeliveryOutcome{DeliveryWithheld}
	}
	return DeliveryOutcome{DeliveryUnknown}
}
func mustDigest(s string) [32]byte {
	var d [32]byte
	b, e := hex.DecodeString(s)
	if e == nil && len(b) == 32 {
		copy(d[:], b)
	}
	return d
}
func (c *DeliveryCapability) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	if c.operationCancel != nil {
		c.operationCancel()
	}
	c.mu.Unlock()
	c.operationMu.Lock()
	defer c.operationMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.anchor != nil {
		_ = c.anchor.Close()
	}
	if c.directory != nil {
		_ = c.directory.Close()
	}
	if c.store != nil {
		return c.store.Close()
	}
	return nil
}

func NewDeliveryCapability(ctx context.Context, installation *Installation, ref appstoreref.Ref) (*DeliveryCapability, error) {
	if ctx == nil || installation == nil || installation.master == nil || installation.master.Closed() || !ref.Valid() {
		return nil, ErrDelivery
	}
	placeholder, _ := appstoreplaceholder.Encode(ref)
	grants, err := declarativeauthority.LoadDelivery(string(placeholder), os.Geteuid(), time.Now())
	clear(placeholder)
	if err != nil {
		return nil, ErrDelivery
	}
	list := grants.Grants()
	if len(list) != 1 {
		return nil, ErrDelivery
	}
	g := list[0]
	if hex.EncodeToString(installation.encodedHash[:]) != g.InstallationSHA256 || g.RecipientUID != os.Geteuid() || g.Ref == "" || g.EncodedHash == "" || g.DirectoryDev == 0 || g.DirectoryIno == 0 || g.StorePath == "" || g.Target != declarativeauthority.DeliveryTarget || g.Purpose != declarativeauthority.DeliveryPurpose || g.PolicyRevision != declarativeauthority.DeliveryPolicyRevision || g.DesiredSchemaID == "" || g.ProjectionSchemaID == "" {
		return nil, ErrDelivery
	}
	if dig, e := declarativeauthority.DeliveryDriverDigest(); e != nil || dig != g.DriverCodeSHA256 {
		return nil, ErrDelivery
	}
	if dig, e := declarativeauthority.DeliveryCodeDigest(); e != nil || dig != g.ConsumerSHA256 {
		return nil, ErrDelivery
	}
	store, err := appstoreentry.Open(g.StorePath)
	if err != nil {
		return nil, ErrDelivery
	}
	fail := func() (*DeliveryCapability, error) { _ = store.Close(); return nil, ErrDelivery }
	encoded, actual, err := store.Load()
	if err != nil {
		return fail()
	}
	defer clear(encoded)
	if hex.EncodeToString(actual[:]) != g.InstallationSHA256 || actual != installation.encodedHash {
		return fail()
	}
	dev, ino, err := store.Identity()
	if err != nil || dev != g.DirectoryDev || ino != g.DirectoryIno || !installation.DirectoryMatches(dev, ino) || installation.Header().StoreID() != ref.StoreID() {
		return fail()
	}
	root, err := store.Root()
	if err != nil {
		return fail()
	}
	directory, err := appstorefile.Open(root, installation.Header().StoreID())
	_ = root.Close()
	if err != nil {
		return fail()
	}
	anchor, err := installation.binding.transport()
	if err != nil {
		_ = directory.Close()
		return fail()
	}
	c := &DeliveryCapability{installation: installation, ref: ref, grant: g, store: store, directory: directory, anchor: anchor, used: make(map[string]bool), tuples: make(map[string]bool)}
	if err = c.Check(ctx); err != nil {
		_ = c.Close()
		return nil, ErrDelivery
	}
	return c, nil
}

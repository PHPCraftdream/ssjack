// Package delivery pins verified snapshots and releases single objects to fixed native consumers.
package delivery

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchortls"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/snapshotstore"
	"github.com/PHPCraftdream/ssjack/internal/appstoreentry"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/appstoresink"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
)

var ErrDelivery = errors.New("confidential delivery denied")

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
	text    *textSelection
}
type OperationBinding struct {
	SessionID, PlanID, Digest string
	ObservedRevision          string
	Policy                    string
	Deadline                  time.Time
}
type DeliveryCapability struct {
	mu                sync.Mutex
	operationMu       sync.Mutex
	operationCancel   context.CancelFunc
	boundSession      string
	tuples            map[string]bool
	installation      *snapshotstore.Installation
	ref               appstoreref.Ref
	grant             declarativeauthority.DeliveryGrant
	store             *appstoreentry.Store
	directory         *appstorefile.Directory
	anchor            *appstoreanchortls.Writer
	used              map[string]bool
	pendingSelections map[*deliveryPlanState]struct{}
	textBinding       TextBinding
	closed            bool
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
	if c.closed || ctx.Err() != nil || c.installation == nil || snapshotstore.MasterOf(c.installation) == nil || snapshotstore.MasterOf(c.installation).Closed() {
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
	if err := c.store.VerifyUnchanged(snapshotstore.EncodedHashOf(c.installation)); err != nil {
		return ErrDelivery
	}
	dev, ino, err := c.store.Identity()
	if err != nil || dev != c.grant.DirectoryDev || ino != c.grant.DirectoryIno || !c.installation.DirectoryMatches(dev, ino) {
		return ErrDelivery
	}
	return ctx.Err()
}
func (c *DeliveryCapability) Prepare(ctx context.Context, operation OperationBinding) *DeliveryPlan {
	return c.prepare(ctx, operation, nil)
}

func (c *DeliveryCapability) prepare(ctx context.Context, operation OperationBinding, text *textSelection) *DeliveryPlan {
	if text != nil && !digestPattern.MatchString(operation.Digest) {
		return nil
	}
	if text != nil {
		if len(text.input) > 32<<10 {
			return nil
		}
		text = &textSelection{input: append([]byte(nil), text.input...), reverse: text.reverse}
	}
	if c == nil || ctx == nil || !canonicalID(operation.SessionID) || !canonicalID(operation.PlanID) || !digestPattern.MatchString(operation.Digest) || len(operation.ObservedRevision) == 0 || len(operation.ObservedRevision) > 128 || operation.Policy != declarativeauthority.DeliveryPolicyRevision || operation.Deadline.IsZero() || operation.Deadline.Location() == nil {
		if text != nil {
			clear(text.input)
		}
		return nil
	}
	if !operation.Deadline.After(time.Now()) || operation.Deadline.After(time.Now().Add(time.Minute)) || c.Check(ctx) != nil {
		if text != nil {
			clear(text.input)
		}
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || (c.boundSession != "" && c.boundSession != operation.SessionID) || len(c.tuples) >= 128 || len(c.pendingSelections) >= 128 || c.tuples[operation.PlanID] {
		if text != nil {
			clear(text.input)
		}
		return nil
	}
	c.boundSession = operation.SessionID
	c.tuples[operation.PlanID] = true
	state := &deliveryPlanState{owner: c, binding: operation, text: text}
	if text != nil {
		c.pendingSelections[state] = struct{}{}
	}
	return &DeliveryPlan{state: state}
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
		c.mu.Lock()
		if state.text != nil {
			clear(state.text.input)
			delete(c.pendingSelections, state)
			state.used = true
		}
		c.mu.Unlock()
		return DeliveryOutcome{DeliveryWithheld}
	}
	deadlineCtx, cancel := context.WithDeadline(ctx, operation.Deadline)
	defer cancel()
	c.mu.Lock()
	if c.closed || state.used || c.used[operationID] || len(c.used) >= 128 || c.boundSession != operation.SessionID {
		if state.text != nil {
			clear(state.text.input)
			delete(c.pendingSelections, state)
			state.used = true
		}
		c.mu.Unlock()
		return DeliveryOutcome{DeliveryWithheld}
	}
	state.used = true
	if state.text != nil {
		defer clear(state.text.input)
		delete(c.pendingSelections, state)
	}
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
	deliver := func() (appstoresink.Result, error) {
		checks := []func() error{func() error { return c.Check(ctx) }, func() error {
			return lease.CheckReference(ctx, operation.ObservedRevision, operationID, operation.Digest, c.grant.Ref)
		}}
		if state.text != nil {
			return deliverCurrentText(snapshotstore.MasterOf(c.installation), ctx, c.directory, c.anchor, c.ref, consumer, state.text, checks...)
		}
		return deliverCurrent(snapshotstore.MasterOf(c.installation), ctx, c.directory, c.anchor, c.ref, consumer, checks...)
	}
	result, err := deliver()
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
	clear(c.textBinding.key[:])
	c.textBinding.initialized = false
	if c.operationCancel != nil {
		c.operationCancel()
	}
	c.mu.Unlock()
	c.operationMu.Lock()
	defer c.operationMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	for state := range c.pendingSelections {
		if state != nil && state.text != nil {
			clear(state.text.input)
			state.text = nil
		}
	}
	c.pendingSelections = nil
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

func NewDeliveryCapability(ctx context.Context, installation *snapshotstore.Installation, ref appstoreref.Ref) (*DeliveryCapability, error) {
	if ctx == nil || installation == nil || snapshotstore.MasterOf(installation) == nil || snapshotstore.MasterOf(installation).Closed() || !ref.Valid() {
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
	installationHash := snapshotstore.EncodedHashOf(installation)
	if hex.EncodeToString(installationHash[:]) != g.InstallationSHA256 || g.RecipientUID != os.Geteuid() || g.Ref == "" || g.EncodedHash == "" || g.DirectoryDev == 0 || g.DirectoryIno == 0 || g.StorePath == "" || g.Target != declarativeauthority.DeliveryTarget || g.Purpose != declarativeauthority.DeliveryPurpose || g.PolicyRevision != declarativeauthority.DeliveryPolicyRevision || g.DesiredSchemaID == "" || g.ProjectionSchemaID == "" {
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
	if hex.EncodeToString(actual[:]) != g.InstallationSHA256 || actual != installationHash {
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
	anchor, err := snapshotstore.AnchorOf(installation)
	if err != nil {
		_ = directory.Close()
		return fail()
	}
	binding, err := NewTextBinding()
	if err != nil {
		_ = anchor.Close()
		_ = directory.Close()
		return fail()
	}
	c := &DeliveryCapability{installation: installation, ref: ref, grant: g, store: store, directory: directory, anchor: anchor, textBinding: binding, used: make(map[string]bool), tuples: make(map[string]bool), pendingSelections: make(map[*deliveryPlanState]struct{})}
	if err = c.Check(ctx); err != nil {
		_ = c.Close()
		return nil, ErrDelivery
	}
	return c, nil
}

// DigestPattern matches a lowercase hex SHA-256 digest.
var DigestPattern = digestPattern

// CanonicalID reports whether s is a canonical unpadded base64url 16-byte ID.
func CanonicalID(s string) bool { return canonicalID(s) }

// MustDigest decodes a hex SHA-256 digest, returning zero for malformed input.
func MustDigest(s string) [32]byte { return mustDigest(s) }

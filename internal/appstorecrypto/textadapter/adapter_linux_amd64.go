//go:build linux && amd64

package textadapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchortls"
	"github.com/PHPCraftdream/ssjack/internal/appstorebudget"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/delivery"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/masterkey"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/snapshotstore"
	"github.com/PHPCraftdream/ssjack/internal/appstoreentry"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/appstoretext"
	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
)

type TextAdapterRunner = func(context.Context, string, string, io.Reader, io.Writer, io.Writer) (int, error)

type TextAdapter struct {
	mu           sync.Mutex
	operationMu  sync.Mutex
	cancel       context.CancelFunc
	installation *snapshotstore.Installation
	grant        declarativeauthority.TextAdapterGrant
	store        *appstoreentry.Store
	directory    *appstorefile.Directory
	anchor       *appstoreanchortls.Writer
	runner       TextAdapterRunner
	binding      delivery.TextBinding
	used         bool
	closed       bool
	borrowed     bool
}

func (c *TextAdapter) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *TextAdapter) check(ctx context.Context) error {
	if c == nil || ctx == nil || ctx.Err() != nil || c.isClosed() || c.installation == nil || snapshotstore.MasterOf(c.installation) == nil || snapshotstore.MasterOf(c.installation).Closed() {
		return delivery.ErrDelivery
	}
	g, err := loadTextAdapterGrant(c.grant.Mode, c.grant.ID, os.Geteuid(), time.Now())
	if err != nil || !reflect.DeepEqual(g, c.grant) || g.Profile == "" || g.Revoked {
		return delivery.ErrDelivery
	}
	expires, err := time.Parse(time.RFC3339, g.ExpiresAt)
	installationHash := snapshotstore.EncodedHashOf(c.installation)
	if err != nil || !expires.After(time.Now()) || hex.EncodeToString(installationHash[:]) != g.InstallationSHA256 {
		return delivery.ErrDelivery
	}
	dev, ino, err := c.store.Identity()
	if err != nil || dev != g.DirectoryDev || ino != g.DirectoryIno || !c.installation.DirectoryMatches(dev, ino) {
		return delivery.ErrDelivery
	}
	if err = c.store.VerifyUnchanged(snapshotstore.EncodedHashOf(c.installation)); err != nil {
		return delivery.ErrDelivery
	}
	return ctx.Err()
}

func textOperationDigest(operationID, file string, grant declarativeauthority.TextAdapterGrant) (string, error) {
	metadata := struct {
		OperationID string                                `json:"operation_id"`
		File        string                                `json:"file"`
		Grant       declarativeauthority.TextAdapterGrant `json:"grant"`
	}{operationID, file, grant}
	raw, err := json.Marshal(metadata)
	if err != nil {
		return "", delivery.ErrDelivery
	}
	canonical, err := canonicaljson.Canonicalize(raw)
	if err != nil {
		return "", delivery.ErrDelivery
	}
	digest := sha256.Sum256(canonical)
	clear(canonical)
	return hex.EncodeToString(digest[:]), nil
}

func (c *TextAdapter) Hydrate(ctx context.Context, operationID, file string, selected []byte) delivery.DeliveryOutcome {
	withheld := delivery.DeliveryOutcome{Status: delivery.DeliveryWithheld}
	if c == nil || ctx == nil || ctx.Err() != nil || c.grant.Mode != "hydrate-v1" || !delivery.CanonicalID(operationID) || file != c.grant.File || len(selected) > 32<<10 || c.isClosed() {
		return withheld
	}
	if !c.operationMu.TryLock() {
		return withheld
	}
	defer c.operationMu.Unlock()
	c.mu.Lock()
	if c.closed || c.used {
		c.mu.Unlock()
		return withheld
	}
	c.used = true
	grant := c.grant
	c.mu.Unlock()
	selection := append([]byte(nil), selected...)
	defer clear(selection)
	expires, err := time.Parse(time.RFC3339, grant.ExpiresAt)
	if err != nil {
		return withheld
	}
	deadline := time.Now().Add(time.Minute)
	if expires.Before(deadline) {
		deadline = expires
	}
	opctx, cancel := context.WithDeadline(ctx, deadline)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		cancel()
		return withheld
	}
	c.cancel = cancel
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.cancel = nil
		c.mu.Unlock()
		cancel()
	}()
	base, err := textOperationDigest(operationID, file, grant)
	if err != nil {
		return withheld
	}
	bound := c.binding.Digest(base, selection, false)
	if !delivery.DigestPattern.MatchString(bound) || c.check(opctx) != nil {
		return withheld
	}
	refs := make([]appstoreref.Ref, 0, len(grant.References))
	for _, raw := range grant.References {
		reference, parseErr := appstoreplaceholder.Parse([]byte(raw))
		if parseErr != nil || !reference.Valid() {
			return withheld
		}
		refs = append(refs, reference)
	}
	if len(refs) == 0 || len(refs) > 16 {
		return withheld
	}
	tx, err := c.directory.Lock()
	if err != nil {
		return withheld
	}
	defer tx.Close()
	reply, err := c.anchor.Read(opctx)
	if err != nil {
		return withheld
	}
	state, present := reply.State()
	if !reply.SignatureValid() || reply.Outcome() != appstoreanchorreply.ReadState || !present || state.StoreID() != refs[0].StoreID() || state.CommittedSnapshotID() != refs[0].SnapshotID() || state.CommittedFileHash() != delivery.MustDigest(grant.EncodedHash) {
		return withheld
	}
	pointer, err := tx.ReadPointer()
	if err != nil {
		return withheld
	}
	var wanted [64]byte
	snapshot, encoded, transaction := state.CommittedSnapshotID(), state.CommittedFileHash(), state.CommittedTransactionID()
	copy(wanted[:16], snapshot[:])
	copy(wanted[16:48], encoded[:])
	copy(wanted[48:], transaction[:])
	if pointer != wanted || hex.EncodeToString(encoded[:]) != grant.EncodedHash || c.check(opctx) != nil {
		return withheld
	}
	spool, err := delivery.PinSnapshot(snapshotstore.MasterOf(c.installation), opctx, tx, masterkey.ExpectedSnapshot{StoreID: state.StoreID(), SnapshotID: snapshot, EncodedHash: encoded})
	if err != nil {
		return withheld
	}
	defer spool.Close()
	fresh, err := c.anchor.Read(opctx)
	if err != nil {
		return withheld
	}
	freshState, ok := fresh.State()
	freshPointer, pointerErr := tx.ReadPointer()
	if !fresh.SignatureValid() || fresh.Outcome() != appstoreanchorreply.ReadState || !ok || !freshState.Valid() || freshState.Hash() != state.Hash() || pointerErr != nil || freshPointer != wanted || c.check(opctx) != nil {
		return withheld
	}
	var aggregate uint64
	secrets := make([][]byte, 0, len(refs))
	defer func() {
		for _, secret := range secrets {
			clear(secret)
		}
	}()
	for _, reference := range refs {
		entry, findErr := appstoreref.FindMetadata(reference, spool.Catalog())
		if findErr != nil || entry.Length() > 1<<20 || aggregate+entry.Length() > 1<<20 {
			return withheld
		}
		secret := make([]byte, 0, int(entry.Length()))
		secrets = append(secrets, secret)
		got, streamErr := delivery.StreamPinned(snapshotstore.MasterOf(c.installation), opctx, spool, entry, delivery.Buffer{Data: &secret}, func() error {
			return c.check(opctx)
		})
		secrets[len(secrets)-1] = secret
		if streamErr != nil || got.Bytes != entry.Length() {
			return withheld
		}
		aggregate += got.Bytes
	}
	mappings := make([]appstoretext.Mapping, len(refs))
	for i := range refs {
		mappings[i] = appstoretext.Mapping{Reference: refs[i], Value: secrets[i]}
	}
	transformed, err := appstoretext.Replace(selection, mappings, false)
	if err != nil || len(transformed) > 1<<20 {
		clear(transformed)
		return withheld
	}
	defer clear(transformed)
	if spool.Recheck(opctx) != nil || c.check(opctx) != nil {
		return withheld
	}
	fresh, err = c.anchor.Read(opctx)
	if err != nil {
		return withheld
	}
	freshState, ok = fresh.State()
	freshPointer, pointerErr = tx.ReadPointer()
	if !fresh.SignatureValid() || fresh.Outcome() != appstoreanchorreply.ReadState || !ok || freshState.Hash() != state.Hash() || pointerErr != nil || freshPointer != wanted || c.check(opctx) != nil {
		return withheld
	}
	verifiedBound := c.binding.Digest(base, selection, false)
	if verifiedBound != bound {
		return withheld
	}
	return deliverTextAdapterOutput(opctx, c.runner, grant.Profile, grant.Command, transformed, func() error { return c.check(opctx) })
}

func deliverTextAdapterOutput(ctx context.Context, runner TextAdapterRunner, profile, command string, transformed []byte, check func() error) delivery.DeliveryOutcome {
	if ctx == nil || runner == nil || check == nil || ctx.Err() != nil || len(transformed) > 1<<20 || check() != nil {
		return delivery.DeliveryOutcome{Status: delivery.DeliveryWithheld}
	}
	input := bytes.NewReader(transformed)
	exit, err := runner(ctx, profile, command, input, io.Discard, io.Discard)
	if err != nil || exit != 0 || input.Len() != 0 || ctx.Err() != nil || check() != nil {
		return delivery.DeliveryOutcome{Status: delivery.DeliveryUnknown}
	}
	return delivery.DeliveryOutcome{Status: delivery.DeliveryReceived}
}

func (c *TextAdapter) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	if c.cancel != nil {
		c.cancel()
	}
	c.mu.Unlock()
	c.operationMu.Lock()
	defer c.operationMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.binding.Clear()
	if c.anchor != nil {
		_ = c.anchor.Close()
	}
	if !c.borrowed && c.directory != nil {
		_ = c.directory.Close()
	}
	if !c.borrowed && c.store != nil {
		return c.store.Close()
	}
	return nil
}

func NewTextAdapter(ctx context.Context, installation *snapshotstore.Installation, grantID, profile, credentialDigest string, runner TextAdapterRunner) (*TextAdapter, error) {
	return newTextAdapter(ctx, installation, grantID, profile, credentialDigest, runner, "hydrate-v1")
}

func NewReverseTextAdapter(ctx context.Context, installation *snapshotstore.Installation, grantID, profile, credentialDigest string, runner TextAdapterRunner) (*TextAdapter, error) {
	return newTextAdapter(ctx, installation, grantID, profile, credentialDigest, runner, "reverse-copy-v1")
}

func newTextAdapter(ctx context.Context, installation *snapshotstore.Installation, grantID, profile, credentialDigest string, runner TextAdapterRunner, expectedMode string) (*TextAdapter, error) {
	return newTextConsumer(ctx, installation, nil, nil, grantID, profile, credentialDigest, runner, expectedMode)
}

// NewBorrowedTextAdapter borrows keeper-owned handles; Close never releases them.
func NewBorrowedTextAdapter(ctx context.Context, installation *snapshotstore.Installation, store *appstoreentry.Store, directory *appstorefile.Directory, grantID, profile, credentialDigest string, runner TextAdapterRunner, mode string) (*TextAdapter, error) {
	if store == nil || directory == nil {
		return nil, delivery.ErrDelivery
	}
	return newTextConsumer(ctx, installation, store, directory, grantID, profile, credentialDigest, runner, mode)
}

func newTextConsumer(ctx context.Context, installation *snapshotstore.Installation, store *appstoreentry.Store, directory *appstorefile.Directory, grantID, profile, credentialDigest string, runner TextAdapterRunner, expectedMode string) (*TextAdapter, error) {
	if !validTextAdapterMode(expectedMode) || ctx == nil || installation == nil || snapshotstore.MasterOf(installation) == nil || snapshotstore.MasterOf(installation).Closed() || runner == nil || !delivery.DigestPattern.MatchString(credentialDigest) || os.Geteuid() <= 0 {
		return nil, delivery.ErrDelivery
	}
	installationHash := snapshotstore.EncodedHashOf(installation)
	g, err := loadTextAdapterGrant(expectedMode, grantID, os.Geteuid(), time.Now())
	if err != nil || g.Mode != expectedMode || g.Profile != profile || g.CredentialSHA256 != credentialDigest || hex.EncodeToString(installationHash[:]) != g.InstallationSHA256 || installation.Header().StoreID() == ([16]byte{}) || len(g.References) == 0 {
		return nil, delivery.ErrDelivery
	}
	borrowed := store != nil
	if !borrowed {
		store, err = appstoreentry.Open(g.StorePath)
		if err != nil {
			return nil, delivery.ErrDelivery
		}
	}
	fail := func() (*TextAdapter, error) {
		if !borrowed {
			_ = store.Close()
		}
		return nil, delivery.ErrDelivery
	}
	if !borrowed {
		encoded, actual, loadErr := store.Load()
		clear(encoded)
		if loadErr != nil || actual != installationHash {
			return fail()
		}
	}
	dev, ino, err := store.Identity()
	if err != nil || store.VerifyUnchanged(installationHash) != nil || dev != g.DirectoryDev || ino != g.DirectoryIno || !installation.DirectoryMatches(dev, ino) || installation.Header().StoreID() != mustTextStore(g) {
		return fail()
	}
	if !borrowed {
		root, rootErr := store.Root()
		if rootErr != nil {
			return fail()
		}
		directory, err = appstorefile.Open(root, installation.Header().StoreID())
		_ = root.Close()
		if err != nil {
			return fail()
		}
	}
	directoryDev, directoryIno, err := directory.Identity()
	if err != nil || directoryDev != dev || directoryIno != ino || directory.StoreID() != installation.Header().StoreID() {
		if !borrowed {
			_ = directory.Close()
		}
		return fail()
	}
	_, anchor, err := installation.Writer(directory)
	if err != nil {
		if !borrowed {
			_ = directory.Close()
		}
		return fail()
	}
	binding, err := delivery.NewTextBinding()
	if err != nil {
		_ = anchor.Close()
		if !borrowed {
			_ = directory.Close()
		}
		return fail()
	}
	adapter := &TextAdapter{installation: installation, grant: g, store: store, directory: directory, anchor: anchor, runner: runner, binding: binding, borrowed: borrowed}
	if adapter.check(ctx) != nil {
		_ = adapter.Close()
		return nil, delivery.ErrDelivery
	}
	return adapter, nil
}

func mustTextStore(g declarativeauthority.TextAdapterGrant) [16]byte {
	if len(g.References) == 0 {
		return [16]byte{}
	}
	r, err := appstoreplaceholder.Parse([]byte(g.References[0]))
	if err != nil {
		return [16]byte{}
	}
	return r.StoreID()
}

func NewBorrowedTextStreamAdapter(ctx context.Context, installation *snapshotstore.Installation, store *appstoreentry.Store, directory *appstorefile.Directory, grantID, profile, credentialDigest string, runner TextAdapterRunner, mode string) (*TextStreamAdapter, error) {
	if mode != "hydrate-stream-v2" && mode != "reverse-copy-stream-v2" {
		return nil, delivery.ErrDelivery
	}
	base, err := NewBorrowedTextAdapter(ctx, installation, store, directory, grantID, profile, credentialDigest, runner, mode)
	if err != nil {
		return nil, err
	}
	return &TextStreamAdapter{adapter: base}, nil
}

type textStreamSnapshot struct {
	adapter     *TextAdapter
	transaction *appstorefile.Transaction
	pinned      *delivery.PinnedSnapshot
	state       appstoreanchorstate.State
	mappings    []appstoretext.Mapping
	release     func()
}

func (c *TextAdapter) captureTextStream(ctx context.Context) (*textStreamSnapshot, error) {
	if c == nil || c.check(ctx) != nil {
		return nil, delivery.ErrDelivery
	}
	refs := make([]appstoreref.Ref, len(c.grant.References))
	if len(refs) == 0 || len(refs) > 16 {
		return nil, delivery.ErrDelivery
	}
	for i, encoded := range c.grant.References {
		ref, err := appstoreplaceholder.Parse([]byte(encoded))
		if err != nil {
			return nil, delivery.ErrDelivery
		}
		refs[i] = ref
	}
	selection := &textStreamSnapshot{adapter: c}
	complete := false
	defer func() {
		if !complete {
			selection.close()
		}
	}()
	var err error
	selection.release, err = appstorebudget.TryAcquire(refs[0].StoreID())
	if err != nil {
		return nil, delivery.ErrDelivery
	}
	selection.transaction, err = c.directory.Lock()
	if err != nil {
		return nil, delivery.ErrDelivery
	}
	reply, err := c.anchor.Read(ctx)
	if err != nil {
		return nil, delivery.ErrDelivery
	}
	state, present := reply.State()
	if !reply.SignatureValid() || reply.Outcome() != appstoreanchorreply.ReadState || !present || !state.Valid() || state.StoreID() != refs[0].StoreID() || state.CommittedSnapshotID() != refs[0].SnapshotID() || state.CommittedFileHash() != delivery.MustDigest(c.grant.EncodedHash) {
		return nil, delivery.ErrDelivery
	}
	selection.state = state
	pointer, err := selection.transaction.ReadPointer()
	if err != nil || pointer != snapshotstore.Pointer(state) {
		return nil, delivery.ErrDelivery
	}
	selection.pinned, err = delivery.PinSnapshot(snapshotstore.MasterOf(c.installation), ctx, selection.transaction, masterkey.ExpectedSnapshot{StoreID: state.StoreID(), SnapshotID: state.CommittedSnapshotID(), EncodedHash: state.CommittedFileHash()})
	if err != nil {
		return nil, delivery.ErrDelivery
	}
	var aggregate uint64
	for _, ref := range refs {
		entry, err := appstoreref.FindMetadata(ref, selection.pinned.Catalog())
		if err != nil || entry.Length() > 1<<20 || aggregate+entry.Length() > 1<<20 {
			return nil, delivery.ErrDelivery
		}
		value := make([]byte, 0, int(entry.Length()))
		got, err := delivery.StreamPinned(snapshotstore.MasterOf(c.installation), ctx, selection.pinned, entry, delivery.Buffer{Data: &value}, func() error { return c.check(ctx) })
		if err != nil || got.Bytes != entry.Length() || !utf8.Valid(value) || bytes.IndexByte(value, 0) >= 0 {
			clear(value)
			return nil, delivery.ErrDelivery
		}
		aggregate += got.Bytes
		selection.mappings = append(selection.mappings, appstoretext.Mapping{Reference: ref, Value: value})
	}
	probe, err := appstoretext.Replace(nil, selection.mappings, false)
	clear(probe)
	if err != nil || selection.check(ctx) != nil {
		return nil, delivery.ErrDelivery
	}
	complete = true
	return selection, nil
}

func (s *textStreamSnapshot) check(ctx context.Context) error {
	if s == nil || s.adapter == nil || s.transaction == nil || s.pinned == nil || s.adapter.check(ctx) != nil || s.pinned.Recheck(ctx) != nil {
		return delivery.ErrDelivery
	}
	reply, err := s.adapter.anchor.Read(ctx)
	if err != nil {
		return delivery.ErrDelivery
	}
	state, present := reply.State()
	pointer, pointerErr := s.transaction.ReadPointer()
	if !reply.SignatureValid() || reply.Outcome() != appstoreanchorreply.ReadState || !present || !state.Valid() || state.Hash() != s.state.Hash() || pointerErr != nil || pointer != snapshotstore.Pointer(s.state) || s.adapter.check(ctx) != nil {
		return delivery.ErrDelivery
	}
	return ctx.Err()
}

func (s *textStreamSnapshot) close() {
	if s == nil {
		return
	}
	for _, mapping := range s.mappings {
		clear(mapping.Value)
	}
	s.mappings = nil
	if s.pinned != nil {
		s.pinned.Close()
		s.pinned = nil
	}
	if s.transaction != nil {
		s.transaction.Close()
		s.transaction = nil
	}
	if s.release != nil {
		s.release()
		s.release = nil
	}
}

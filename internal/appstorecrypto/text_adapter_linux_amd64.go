//go:build linux && amd64

package appstorecrypto

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

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchortls"
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
	installation *Installation
	grant        declarativeauthority.TextAdapterGrant
	store        *appstoreentry.Store
	directory    *appstorefile.Directory
	anchor       *appstoreanchortls.Writer
	runner       TextAdapterRunner
	binding      textBinding
	used         bool
	closed       bool
}

func NewTextAdapter(ctx context.Context, installation *Installation, grantID, profile, credentialDigest string, runner TextAdapterRunner) (*TextAdapter, error) {
	return newTextAdapter(ctx, installation, grantID, profile, credentialDigest, runner, "hydrate-v1")
}

func NewReverseTextAdapter(ctx context.Context, installation *Installation, grantID, profile, credentialDigest string, runner TextAdapterRunner) (*TextAdapter, error) {
	return newTextAdapter(ctx, installation, grantID, profile, credentialDigest, runner, "reverse-copy-v1")
}

func newTextAdapter(ctx context.Context, installation *Installation, grantID, profile, credentialDigest string, runner TextAdapterRunner, expectedMode string) (*TextAdapter, error) {
	if (expectedMode != "hydrate-v1" && expectedMode != "reverse-copy-v1") || ctx == nil || installation == nil || installation.master == nil || installation.master.Closed() || runner == nil || !digestPattern.MatchString(credentialDigest) || os.Geteuid() <= 0 {
		return nil, ErrDelivery
	}
	g, err := declarativeauthority.LoadTextAdapter(grantID, os.Geteuid(), time.Now())
	if err != nil || g.Mode != expectedMode || g.Profile != profile || g.CredentialSHA256 != credentialDigest || hex.EncodeToString(installation.encodedHash[:]) != g.InstallationSHA256 || installation.Header().StoreID() == ([16]byte{}) || len(g.References) == 0 {
		return nil, ErrDelivery
	}
	store, err := appstoreentry.Open(g.StorePath)
	if err != nil {
		return nil, ErrDelivery
	}
	fail := func() (*TextAdapter, error) {
		_ = store.Close()
		return nil, ErrDelivery
	}
	encoded, actual, err := store.Load()
	if err != nil {
		return fail()
	}
	defer clear(encoded)
	dev, ino, err := store.Identity()
	if err != nil || actual != installation.encodedHash || dev != g.DirectoryDev || ino != g.DirectoryIno || !installation.DirectoryMatches(dev, ino) || installation.Header().StoreID() != mustTextStore(g) {
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
	_, anchor, err := installation.Writer(directory)
	if err != nil {
		_ = directory.Close()
		return fail()
	}
	binding, err := newTextBinding()
	if err != nil {
		_ = anchor.Close()
		_ = directory.Close()
		return fail()
	}
	adapter := &TextAdapter{installation: installation, grant: g, store: store, directory: directory, anchor: anchor, runner: runner, binding: binding}
	if adapter.check(ctx) != nil {
		_ = adapter.Close()
		return nil, ErrDelivery
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

func (c *TextAdapter) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *TextAdapter) check(ctx context.Context) error {
	if c == nil || ctx == nil || ctx.Err() != nil || c.isClosed() || c.installation == nil || c.installation.master == nil || c.installation.master.Closed() {
		return ErrDelivery
	}
	g, err := declarativeauthority.LoadTextAdapter(c.grant.ID, os.Geteuid(), time.Now())
	if err != nil || !reflect.DeepEqual(g, c.grant) || g.Profile == "" || g.Revoked {
		return ErrDelivery
	}
	expires, err := time.Parse(time.RFC3339, g.ExpiresAt)
	if err != nil || !expires.After(time.Now()) || hex.EncodeToString(c.installation.encodedHash[:]) != g.InstallationSHA256 {
		return ErrDelivery
	}
	dev, ino, err := c.store.Identity()
	if err != nil || dev != g.DirectoryDev || ino != g.DirectoryIno || !c.installation.DirectoryMatches(dev, ino) {
		return ErrDelivery
	}
	if err = c.store.VerifyUnchanged(c.installation.encodedHash); err != nil {
		return ErrDelivery
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
		return "", ErrDelivery
	}
	canonical, err := canonicaljson.Canonicalize(raw)
	if err != nil {
		return "", ErrDelivery
	}
	digest := sha256.Sum256(canonical)
	clear(canonical)
	return hex.EncodeToString(digest[:]), nil
}

func (c *TextAdapter) Hydrate(ctx context.Context, operationID, file string, selected []byte) DeliveryOutcome {
	withheld := DeliveryOutcome{DeliveryWithheld}
	if c == nil || ctx == nil || ctx.Err() != nil || c.grant.Mode != "hydrate-v1" || !canonicalID(operationID) || file != c.grant.File || len(selected) > 32<<10 || c.isClosed() {
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
	bound := c.binding.digest(base, selection, false)
	if !digestPattern.MatchString(bound) || c.check(opctx) != nil {
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
	if !reply.SignatureValid() || reply.Outcome() != appstoreanchorreply.ReadState || !present || state.StoreID() != refs[0].StoreID() || state.CommittedSnapshotID() != refs[0].SnapshotID() || state.CommittedFileHash() != mustDigest(grant.EncodedHash) {
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
	spool, err := c.installation.master.pinSnapshot(opctx, tx, ExpectedSnapshot{StoreID: state.StoreID(), SnapshotID: snapshot, EncodedHash: encoded})
	if err != nil {
		return withheld
	}
	defer spool.close()
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
		entry, findErr := appstoreref.FindMetadata(reference, spool.state.checked.Catalog())
		if findErr != nil || entry.Length() > 1<<20 || aggregate+entry.Length() > 1<<20 {
			return withheld
		}
		secret := make([]byte, 0, int(entry.Length()))
		secrets = append(secrets, secret)
		got, streamErr := c.installation.master.streamPinnedObjectToChecked(opctx, spool, entry, writerBuffer{data: &secret}, func() error {
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
	if spool.recheck(opctx) != nil || c.check(opctx) != nil {
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
	verifiedBound := c.binding.digest(base, selection, false)
	if verifiedBound != bound {
		return withheld
	}
	return deliverTextAdapterOutput(opctx, c.runner, grant.Profile, grant.Command, transformed, func() error { return c.check(opctx) })
}

func deliverTextAdapterOutput(ctx context.Context, runner TextAdapterRunner, profile, command string, transformed []byte, check func() error) DeliveryOutcome {
	if ctx == nil || runner == nil || check == nil || ctx.Err() != nil || len(transformed) > 1<<20 || check() != nil {
		return DeliveryOutcome{DeliveryWithheld}
	}
	input := bytes.NewReader(transformed)
	exit, err := runner(ctx, profile, command, input, io.Discard, io.Discard)
	if err != nil || exit != 0 || input.Len() != 0 || ctx.Err() != nil || check() != nil {
		return DeliveryOutcome{DeliveryUnknown}
	}
	return DeliveryOutcome{DeliveryReceived}
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
	clear(c.binding.key[:])
	c.binding.initialized = false
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

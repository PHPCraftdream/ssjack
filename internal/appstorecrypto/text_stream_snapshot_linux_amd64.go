//go:build linux && amd64

package appstorecrypto

import (
	"bytes"
	"context"
	"unicode/utf8"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
	"github.com/PHPCraftdream/ssjack/internal/appstorebudget"
	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/appstoretext"
)

type textStreamSnapshot struct {
	adapter     *TextAdapter
	transaction *appstorefile.Transaction
	pinned      *pinnedSnapshot
	state       appstoreanchorstate.State
	mappings    []appstoretext.Mapping
	release     func()
}

func (c *TextAdapter) captureTextStream(ctx context.Context) (*textStreamSnapshot, error) {
	if c == nil || c.check(ctx) != nil {
		return nil, ErrDelivery
	}
	refs := make([]appstoreref.Ref, len(c.grant.References))
	if len(refs) == 0 || len(refs) > 16 {
		return nil, ErrDelivery
	}
	for i, encoded := range c.grant.References {
		ref, err := appstoreplaceholder.Parse([]byte(encoded))
		if err != nil {
			return nil, ErrDelivery
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
		return nil, ErrDelivery
	}
	selection.transaction, err = c.directory.Lock()
	if err != nil {
		return nil, ErrDelivery
	}
	reply, err := c.anchor.Read(ctx)
	if err != nil {
		return nil, ErrDelivery
	}
	state, present := reply.State()
	if !reply.SignatureValid() || reply.Outcome() != appstoreanchorreply.ReadState || !present || !state.Valid() || state.StoreID() != refs[0].StoreID() || state.CommittedSnapshotID() != refs[0].SnapshotID() || state.CommittedFileHash() != mustDigest(c.grant.EncodedHash) {
		return nil, ErrDelivery
	}
	selection.state = state
	pointer, err := selection.transaction.ReadPointer()
	if err != nil || pointer != ownerPointer(state) {
		return nil, ErrDelivery
	}
	selection.pinned, err = c.installation.master.pinSnapshot(ctx, selection.transaction, ExpectedSnapshot{StoreID: state.StoreID(), SnapshotID: state.CommittedSnapshotID(), EncodedHash: state.CommittedFileHash()})
	if err != nil {
		return nil, ErrDelivery
	}
	var aggregate uint64
	for _, ref := range refs {
		entry, err := appstoreref.FindMetadata(ref, selection.pinned.state.checked.Catalog())
		if err != nil || entry.Length() > 1<<20 || aggregate+entry.Length() > 1<<20 {
			return nil, ErrDelivery
		}
		value := make([]byte, 0, int(entry.Length()))
		got, err := c.installation.master.streamPinnedObjectToChecked(ctx, selection.pinned, entry, writerBuffer{data: &value}, func() error { return c.check(ctx) })
		if err != nil || got.Bytes != entry.Length() || !utf8.Valid(value) || bytes.IndexByte(value, 0) >= 0 {
			clear(value)
			return nil, ErrDelivery
		}
		aggregate += got.Bytes
		selection.mappings = append(selection.mappings, appstoretext.Mapping{Reference: ref, Value: value})
	}
	probe, err := appstoretext.Replace(nil, selection.mappings, false)
	clear(probe)
	if err != nil || selection.check(ctx) != nil {
		return nil, ErrDelivery
	}
	complete = true
	return selection, nil
}

func (s *textStreamSnapshot) check(ctx context.Context) error {
	if s == nil || s.adapter == nil || s.transaction == nil || s.pinned == nil || s.adapter.check(ctx) != nil || s.pinned.recheck(ctx) != nil {
		return ErrDelivery
	}
	reply, err := s.adapter.anchor.Read(ctx)
	if err != nil {
		return ErrDelivery
	}
	state, present := reply.State()
	pointer, pointerErr := s.transaction.ReadPointer()
	if !reply.SignatureValid() || reply.Outcome() != appstoreanchorreply.ReadState || !present || !state.Valid() || state.Hash() != s.state.Hash() || pointerErr != nil || pointer != ownerPointer(s.state) || s.adapter.check(ctx) != nil {
		return ErrDelivery
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
		s.pinned.close()
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

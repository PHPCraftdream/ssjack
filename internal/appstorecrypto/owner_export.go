package appstorecrypto

import (
	"context"
	"sort"

	"github.com/PHPCraftdream/ssjack/internal/appstorebudget"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func (o *OwnerEditor) exportReferences(bindings map[string]vault.SecretBinding) (map[string]appstoreref.Ref, error) {
	if o.closed || o.blocked || o.dirty || o.writer == nil || !o.base.Valid() {
		return nil, ErrOwnerChanged
	}
	if len(bindings) == 0 || len(bindings) > MaxOwnerObjects {
		return nil, ErrRecord
	}
	references := make(map[string]appstoreref.Ref, len(bindings))
	for id, binding := range bindings {
		ref, err := appstoreplaceholder.Parse([]byte(binding.Ref))
		if err != nil {
			return nil, ErrRecord
		}
		object, exists := o.objects[ref.ObjectID()]
		if !exists || object.pending || object.reference != ref || ref.StoreID() != o.base.StoreID() || ref.SnapshotID() != o.base.CommittedSnapshotID() {
			return nil, ErrOwnerChanged
		}
		references[id] = ref
	}
	return references, nil
}

func (o *OwnerEditor) AppendOwnerExport(ctx context.Context, plan *vault.OwnerExportPlan) error {
	if plan == nil {
		return ErrRecord
	}
	complete := false
	defer func() {
		if !complete {
			plan.Close()
		}
	}()
	if o == nil || ctx == nil {
		return ErrRecord
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	references, err := o.exportReferences(plan.Bindings())
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(references))
	for id := range references {
		ids = append(ids, id)
	}
	release, err := appstorebudget.TryAcquire(o.base.StoreID())
	if err != nil {
		return err
	}
	defer release()
	tx, err := o.writer.state.directory.Lock()
	if err != nil {
		return err
	}
	defer tx.Close()
	if err := o.writer.state.checkWriterHistory(ctx, tx, o.base, nil); err != nil {
		return err
	}
	if err := o.verifyState(ctx, tx, o.base); err != nil {
		return err
	}
	sort.Strings(ids)
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return err
		}
		ref := references[id]
		if err := plan.Add(id, ref, o.objects[ref.ObjectID()].value); err != nil {
			return err
		}
	}
	if err := o.verifyState(ctx, tx, o.base); err != nil {
		return err
	}
	complete = true
	return nil
}

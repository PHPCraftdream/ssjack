package nativeownercheck

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ktav-lang/golang/pure"

	"github.com/PHPCraftdream/ssjack/internal/ownerarchive"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func verifyImportPlanAdmission(t *testing.T, ctx context.Context) {
	t.Helper()
	password := []byte("synthetic native import plan password")
	defer clear(password)
	path := filepath.Join(t.TempDir(), "plans.ktav")
	v := vault.NewDirectory()
	defer v.Close()
	must(t, vault.CreateWithRecords(ctx, path, v, password))
	manager, err := ownerdb.Open(ctx, path, password)
	must(t, err)
	defer manager.Discard()
	before, err := manager.Snapshot()
	must(t, err)
	body, err := pure.EmitCanonical(map[string]any{"version": 2, "targets": map[string]any{}, "servers": map[string]any{}, "secrets": map[string]any{}})
	must(t, err)
	archive, err := ownerarchive.New([]byte(body))
	must(t, err)
	defer archive.Close()
	firstPath, secondPath := filepath.Join(t.TempDir(), "first.zip"), filepath.Join(t.TempDir(), "second.zip")
	// Final synthetic empty exports contain no credentials or application values.
	must(t, archive.WritePlaintext(ctx, firstPath, "EXPORT PLAINTEXT"))
	must(t, archive.WritePlaintext(ctx, secondPath, "EXPORT PLAINTEXT"))
	must(t, manager.InspectImportAt(before.Status.Database.Revision, firstPath, nil))
	must(t, manager.Flush(ctx))
	first, err := manager.Snapshot()
	must(t, err)
	if first.Import.Phase != ownerdb.ImportStaged || first.Import.PlanID == 0 || first.Status.Database.Revision != before.Status.Database.Revision {
		t.Fatal("first inspection lacked a RAM plan identity or changed the database")
	}
	must(t, manager.AbortImportPlanAt(first.Status.Database.Revision, first.Import.PlanID))
	must(t, manager.InspectImportAt(first.Status.Database.Revision, secondPath, nil))
	must(t, manager.Flush(ctx))
	second, err := manager.Snapshot()
	must(t, err)
	if second.Import.Phase != ownerdb.ImportStaged || second.Import.PlanID <= first.Import.PlanID || second.Status.Database.Revision != first.Status.Database.Revision {
		t.Fatal("replacement RAM plan reused its identity or changed the database revision")
	}
	for _, oldPlan := range []uint64{0, first.Import.PlanID} {
		for _, decision := range []func(uint64, uint64) error{manager.ConfirmImportPlanAt, manager.ResumeImportPlanAt, manager.AbortImportPlanAt} {
			if err := decision(second.Status.Database.Revision, oldPlan); !errors.Is(err, ownerdb.ErrPending) {
				t.Fatal("stale or absent plan identity was admitted at the current database revision")
			}
			after, err := manager.Snapshot()
			must(t, err)
			if !reflect.DeepEqual(after, second) {
				t.Fatal("stale plan decision changed the queue, preview or persistence state")
			}
		}
	}
	must(t, manager.ConfirmImportPlanAt(second.Status.Database.Revision, second.Import.PlanID))
	must(t, manager.Flush(ctx))
	completed, err := manager.Snapshot()
	must(t, err)
	if completed.Import.Phase != ownerdb.ImportComplete || completed.Import.PlanID != second.Import.PlanID {
		t.Fatal("current plan confirmation did not complete its exact plan")
	}
	must(t, manager.AbortImportPlanAt(completed.Status.Database.Revision, completed.Import.PlanID))
	cleared, err := manager.Snapshot()
	must(t, err)
	if cleared.Import.PlanID != 0 || cleared.Import.Phase != ownerdb.ImportIdle {
		t.Fatal("discarded RAM plan retained an active identity")
	}
	must(t, manager.Close(ctx))
}

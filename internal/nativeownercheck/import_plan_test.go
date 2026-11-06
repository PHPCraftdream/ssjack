package nativeownercheck

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"

	"github.com/ktav-lang/golang/pure"

	"github.com/PHPCraftdream/ssjack/internal/ownerarchive"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/ownerlocal"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func inspectPlanPreflight(t *testing.T, ctx context.Context, database, archive string) {
	t.Helper()
	opened, readErr := ownerarchive.ReadFile(ctx, archive, nil)
	parsed := false
	if readErr == nil {
		plan, parseErr := vault.ParseOwnerImport(opened)
		parsed = parseErr == nil
		if plan != nil {
			plan.Close()
		}
		opened.Close()
	}
	parent, openErr := os.Open(filepath.Dir(database))
	var syncErr error
	if openErr == nil {
		syncErr = parent.Sync()
		parent.Close()
	}
	var openCode, syncCode syscall.Errno
	errors.As(openErr, &openCode)
	errors.As(syncErr, &syncCode)
	t.Logf("import preflight archive_read=%t archive_parse=%t parent_open=%t parent_sync=%t open_errno=%d sync_errno=%d", readErr == nil, parsed, openErr == nil, openErr == nil && syncErr == nil, uint64(openCode), uint64(syncCode))
}

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
	t.Run("guard-admission", func(t *testing.T) { verifyGuardAdmission(t, ctx, path, manager) })
	encodedBefore, err := os.ReadFile(path)
	must(t, err)
	readonly, err := vault.Load(path, password)
	must(t, err)
	if err := vault.SaveUnlocked(ctx, path, readonly); !errors.Is(err, vault.ErrWriterRole) {
		readonly.Close()
		t.Fatal("standalone authenticated writer bypassed the live coordinator")
	}
	readonly.Close()
	if second, err := ownerdb.Open(ctx, path, password); !errors.Is(err, vault.ErrWriterRole) {
		if second != nil {
			second.Discard()
		}
		t.Fatal("second coordinator acquired the same database writer role")
	}
	encodedAfter, err := os.ReadFile(path)
	must(t, err)
	if !bytes.Equal(encodedBefore, encodedAfter) {
		t.Fatal("refused coordinator or standalone save changed the encrypted database")
	}
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
		t.Logf("inspection phase=%q plan=%d revision=%d expected=%d failed=%t", first.Import.Phase, first.Import.PlanID, first.Status.Database.Revision, before.Status.Database.Revision, first.Import.Err != nil)
		inspectPlanPreflight(t, ctx, path, firstPath)
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
	if err := manager.ReleaseImportPlan(completed.Import.PlanID); !errors.Is(err, ownerdb.ErrPending) {
		t.Fatal("helper cleanup discarded effectful import state")
	}
	retained, err := manager.Snapshot()
	must(t, err)
	if !reflect.DeepEqual(retained, completed) {
		t.Fatal("helper cleanup changed effectful import recovery state")
	}
	must(t, manager.AbortImportPlanAt(completed.Status.Database.Revision, completed.Import.PlanID))
	cleared, err := manager.Snapshot()
	must(t, err)
	if cleared.Import.PlanID != 0 || cleared.Import.Phase != ownerdb.ImportIdle {
		t.Fatal("discarded RAM plan retained an active identity")
	}
	t.Run("manager-rpc", func(t *testing.T) { verifyManagerRPC(t, ctx, path, password, firstPath, manager) })
	t.Run("owner-service", func(t *testing.T) { verifyOwnerService(t, ctx, path, manager) })
	t.Run("owner-control", func(t *testing.T) { verifyOwnerControl(t, ctx, path, password, manager) })
	must(t, manager.Close(ctx))
	listener, err := ownerlocal.Listen(path)
	if err != nil {
		t.Fatal("joined Manager close retained its writer endpoint")
	}
	must(t, listener.Close())
}

package ownertest

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func ordinarySSHLiveAcceptance(t *testing.T, parent context.Context) {
	t.Helper()
	f := newOrdinaryLiveFixture(t, parent)
	human, session, reader, stdin := liveHumanShell(t, f.ctx, f.helper, f.selected)
	defer human.Close()
	defer session.Close()
	old, err := f.jobs.Start(remote.StartInput{Target: f.credentials.Targets()[0], Command: "synthetic-live-hold", TimeoutSeconds: 60})
	if err != nil {
		t.Fatal("initial live SSH job was not admitted")
	}
	hold, err := f.server.WaitSyntheticHold(f.ctx)
	if err != nil || hold.Identity() != "old" {
		t.Fatal("held job did not authenticate as the original identity")
	}
	if err := liveEditAccount(f.ctx, f.helper, f.selected.ServerID, f.selected.Revision, []byte("synthetic ordinary live rejected password")); err != nil {
		t.Fatal("owner helper could not save the rejected replacement")
	}
	badRevision := f.helper.Backend().Status().Database.Revision
	probe, err := f.jobs.Start(remote.StartInput{Target: f.credentials.Targets()[0], Command: "synthetic-live-once", TimeoutSeconds: 30})
	if err != nil {
		t.Fatal("rejected replacement authentication probe was not admitted")
	}
	failed := liveReadJob(t, f.ctx, f.jobs, probe.JobID)
	if !failed.Done || failed.Error == "" {
		t.Fatal("fixture accepted the deliberately rejected credential")
	}
	if status := f.helper.Backend().Status().Database.SSH; status == nil || !status.AdoptedKnown || status.AdoptedRevision >= badRevision {
		t.Fatal("failed authentication was reported as adopted or prior authentication was not recorded")
	}
	if err := liveEditAccount(f.ctx, f.helper, f.selected.ServerID, badRevision, []byte(ordinaryLiveNewPassword)); err != nil {
		t.Fatal("owner helper could not save the valid replacement")
	}
	current := f.helper.Backend().Status().Database.Revision
	connections := f.server.AcceptedConnections()
	if err := liveEditAccount(f.ctx, f.helper, f.selected.ServerID, f.selected.Revision, []byte("synthetic stale credential")); !errors.Is(err, vault.ErrOwnerRevision) {
		t.Fatal("stale owner revision was not refused")
	}
	if f.server.AcceptedConnections() != connections || f.helper.Backend().Status().Database.Revision != current {
		t.Fatal("stale edit changed owner state or opened an SSH connection")
	}
	fresh, err := f.jobs.Start(remote.StartInput{Target: f.credentials.Targets()[0], Command: "synthetic-live-once", TimeoutSeconds: 30})
	if err != nil {
		t.Fatal("new live SSH job was not admitted")
	}
	result := liveReadJob(t, f.ctx, f.jobs, fresh.JobID)
	if !result.Done || result.Error != "" || !strings.Contains(string(result.Stdout), "SYNTHETIC-LIVE:new") {
		t.Fatal("new job did not use the confirmed replacement identity")
	}
	status := f.helper.Backend().Status().Database.SSH
	if status == nil || !status.DesiredKnown || status.DesiredRevision != current || !status.DeliveredKnown || status.DeliveredRevision != current || !status.AdoptedKnown || status.AdoptedRevision != current {
		t.Fatal("authenticated owner did not report the replacement as desired, delivered, and adopted")
	}
	stillHeld, err := f.jobs.Read(remote.ReadInput{JobID: old.JobID})
	if err != nil || stillHeld.Done || hold.Identity() != "old" || !hold.Alive() {
		t.Fatal("pre-edit job did not retain its original live SSH connection")
	}
	if _, err := io.WriteString(stdin, "human-after-edit\r"); err != nil {
		t.Fatal("human shell closed during credential replacement")
	}
	if line, err := reader.ReadString('\n'); err != nil || !strings.Contains(line, "ECHO:human-after-edit") {
		t.Fatal("captured human shell did not survive the credential replacement")
	}
	f.server.ReleaseSyntheticHolds()
	oldResult := liveReadJob(t, f.ctx, f.jobs, old.JobID)
	if !oldResult.Done || oldResult.Error != "" || !strings.Contains(string(oldResult.Stdout), "SYNTHETIC-LIVE:old") {
		t.Fatal("held original job did not complete on its original identity")
	}
	if !f.server.HasIdentityLabel("second|old") || !f.server.HasIdentityLabel("second|new") {
		t.Fatal("fixture did not observe both original and replacement identities")
	}
}

func liveReadJob(t *testing.T, ctx context.Context, jobs *remote.Manager, id string) remote.ReadOutput {
	t.Helper()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		result, err := jobs.Read(remote.ReadInput{JobID: id})
		if err != nil {
			t.Fatal(err)
		}
		if result.Done {
			return result
		}
		select {
		case <-ctx.Done():
			t.Fatal("synthetic SSH operation did not finish")
		case <-ticker.C:
		}
	}
}

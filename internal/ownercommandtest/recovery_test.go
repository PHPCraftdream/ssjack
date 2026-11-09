package ownercommands

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/ownercommand"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/ownertui"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func commandModel(t *testing.T, b *backend, args ...string) *ownertui.Model {
	t.Helper()
	request, err := ownercommand.Parse(args, "", "")
	if err != nil {
		t.Fatal(err)
	}
	m := ownertui.New(context.Background(), b)
	if err := m.ConfigureCommand(request); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestImportCommandRefusesPartialWrongConfirmationAndSupportsPreviewCancel(t *testing.T) {
	for _, mode := range []string{"complete", "partial", "wrong-confirmation", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			b := fixture(t)
			b.partial = mode == "partial"
			m := commandModel(t, b, "import", "--file", "synthetic.zip")
			apply(t, m, map[string]string{"Archive password": "synthetic-input-secret"})
			if b.archivePath != "synthetic.zip" || string(b.archivePassword) != "synthetic-input-secret" || strings.Join(b.calls, ",") != "inspect" || !strings.Contains(m.View().Content, "Import preview") {
				t.Fatal("inspection skipped the private password or preview boundary")
			}
			if mode == "cancel" {
				drain(m, key(m, 27))
				if !errors.Is(m.CommandResult(), ownercommand.ErrCancelled) || strings.Join(b.calls, ",") != "inspect,abort-import" {
					t.Fatal("preview cancellation applied the archive or reported success")
				}
				return
			}
			choose(t, m, "[Confirm import…]")
			confirmation := "IMPORT"
			if mode == "wrong-confirmation" {
				confirmation = "WRONG"
			}
			apply(t, m, map[string]string{"Confirmation": confirmation})
			if (mode == "complete") != (m.CommandResult() == nil) {
				t.Fatal("partial/wrong-confirmation import was reported complete")
			}
			if mode == "wrong-confirmation" && strings.Join(b.calls, ",") != "inspect" {
				t.Fatal("wrong confirmation published an import")
			}
		})
	}
}

func TestEveryPendingDecisionUsesTheSameMenuDispatch(t *testing.T) {
	for _, action := range []string{"retry-db", "reconcile", "resume-draft", "cancel-draft", "resume-import", "abort-import"} {
		t.Run(action, func(t *testing.T) {
			left, right := fixture(t), fixture(t)
			left.imports.Phase = ownerdb.ImportComplete
			command := commandModel(t, left, "pending", "--action", action)
			interactive := menu(t, right, "", "", "Pending change")
			apply(t, command, nil)
			apply(t, interactive, map[string]string{"Action": action})
			if command.CommandResult() != nil || strings.Join(left.calls, ",") != action || strings.Join(right.calls, ",") != action {
				t.Fatal("recovery command diverged from menu dispatch")
			}
		})
	}
}

func TestCommandSecretScopesNeverFallBackAndApprovalCannotBePrefilled(t *testing.T) {
	b := fixture(t)
	server := b.metadata.Servers[0].ID
	local := strings.Repeat("03", 16)
	b.metadata.Secrets[local] = vault.SecretBinding{Name: "token", ServerID: server, Ref: b.metadata.Secrets[strings.Repeat("02", 16)].Ref}
	for _, scope := range []string{"global", "server"} {
		args := []string{"edit-secret", "--scope", scope, "--secret", "token"}
		if scope == "server" {
			args = append(args, "--server", "production")
		}
		m := commandModel(t, b, args...)
		apply(t, m, map[string]string{"Value": "synthetic-input-secret"})
		change := b.changes[len(b.changes)-1]
		if (scope == "server") != (change.ServerID == server) {
			t.Fatal("secret selected a different scope")
		}
	}
	r, err := ownercommand.Parse([]string{"remove-secret", "--scope", "global", "--secret", "token"}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	r.Fields["Confirmation"] = "REMOVE"
	m := ownertui.New(context.Background(), b)
	if m.ConfigureCommand(r) == nil {
		t.Fatal("caller prefilled human approval")
	}
	if key(m, 13) != nil {
		t.Fatal("rejected prefill left an executable form")
	}
}

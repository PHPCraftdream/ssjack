//go:build linux && amd64

package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/connectedkit"
	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/testkit"
	"github.com/PHPCraftdream/ssjack/internal/apptransport"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
	"github.com/PHPCraftdream/ssjack/internal/remote"
)

func consumerStreamServer(t *testing.T, installation *appstorecrypto.Installation, grant declarativeauthority.TextAdapterGrant, runner remote.StreamRunner) apptransport.Bootstrap {
	t.Helper()
	construct := appstorecrypto.NewTextStreamAdapter
	if grant.Mode == "reverse-copy-stream-v2" {
		construct = appstorecrypto.NewReverseTextStreamAdapter
	}
	adapter, err := construct(context.Background(), installation, grant.ID, grant.Profile, grant.CredentialSHA256, runner)
	if err != nil {
		t.Fatal("construct registered stream conformance adapter:", err)
	}
	var server *apptransport.Server
	if grant.Mode == "reverse-copy-stream-v2" {
		server, err = apptransport.ListenWithReverseTextStreamAdapter(context.Background(), grant.Profile, runner, adapter)
	} else {
		server, err = apptransport.ListenWithTextStreamAdapter(context.Background(), grant.Profile, runner, adapter)
	}
	if err != nil {
		adapter.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close(); adapter.Close() })
	return server.Bootstrap()
}

func consumerStreamReferences(t *testing.T, cli consumerCLI, name string, refs []string) string {
	t.Helper()
	encoded, err := json.Marshal(refs)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cli.root, name)
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func consumerStreamChildRun(t *testing.T) {
	grantPipe, ack := os.NewFile(3, "stream-conformance-grants"), os.NewFile(4, "stream-conformance-approval")
	if grantPipe == nil || ack == nil {
		t.Fatal("missing stream conformance authority pipes")
	}
	defer grantPipe.Close()
	defer ack.Close()
	installation, base, refs := testkit.TextAdapterFixtureValues(t, [][]byte{[]byte(connectedkit.PairLongSecret), []byte(connectedkit.PairShortSecret)})
	target, runner, credential := connectedkit.NewPairTargetWithLimit(t, consumerProfile, 64<<20)
	base.Mode, base.Profile, base.Command, base.File, base.CredentialSHA256 = "hydrate-stream-v2", consumerProfile, "pair-write", target.Path, credential
	deploy := consumerGrant(base, "stream-deploy")
	backup := consumerGrant(base, "stream-backup")
	backup.Mode, backup.Command = "reverse-copy-stream-v2", "pair-read"
	restore := consumerGrant(base, "stream-restore")
	missing := consumerGrant(base, "stream-missing-version")
	missing.References[0] = consumerMissingRef(t, refs[0], false)
	if err := json.NewEncoder(grantPipe).Encode([]declarativeauthority.TextAdapterGrant{deploy, backup, restore, missing}); err != nil {
		t.Fatal(err)
	}
	var approved [1]byte
	if _, err := io.ReadFull(ack, approved[:]); err != nil || approved[0] != 1 {
		t.Fatal("stream conformance grants were not acknowledged")
	}
	grantPipe.Close()
	ack.Close()
	prefix := strings.Repeat("large streamed config\n", 70000)
	template := prefix + "first=" + refs[0] + "\nsecond=" + refs[1] + "\n"
	expected := prefix + "first=" + connectedkit.PairLongSecret + "\nsecond=" + connectedkit.PairShortSecret + "\n"
	if len(template) <= 1<<20 || len(expected) <= 1<<20 {
		t.Fatal("stream conformance does not exceed the old reverse text limit")
	}
	cli := newConsumerCLI(t, template)
	references := consumerStreamReferences(t, cli, "grant-refs.json", base.References)
	if !t.Run("large-deploy-and-no-v1-fallback", func(t *testing.T) {
		bootstrap := consumerStreamServer(t, installation, deploy, runner)
		cli.deploy(t, nil, "", false, "--file", target.Path, "--template", cli.templatePath, "--profile", base.Profile, "--stream-references", references)
		cli.deploy(t, &bootstrap, "", false, "--file", target.Path, "--template", cli.templatePath, "--profile", base.Profile)
		cli.deploy(t, &bootstrap, "", false, "--file", target.Path, "--template", cli.templatePath, "--profile", "wrong-profile", "--stream-references", references)
		wrong := consumerStreamReferences(t, cli, "wrong-refs.json", missing.References)
		cli.deploy(t, &bootstrap, "", false, "--file", target.Path, "--template", cli.templatePath, "--profile", base.Profile, "--stream-references", wrong)
		malformed := filepath.Join(cli.root, "malformed.txt")
		if err := os.WriteFile(malformed, []byte("invalid $ssjack marker"), 0o600); err != nil {
			t.Fatal(err)
		}
		cli.deploy(t, &bootstrap, "withheld", false, "--file", target.Path, "--template", malformed, "--profile", base.Profile, "--stream-references", references)
		if target.Accepted.Load() != 0 || target.Writes.Load() != 0 || target.Reads.Load() != 0 {
			t.Fatal("refused stream CLI operation contacted SSH")
		}
		cli.deploy(t, &bootstrap, "received", true, "--file", target.Path, "--template", cli.templatePath, "--profile", base.Profile, "--stream-references", references)
		consumerAssertFile(t, target.Path, expected)
		if target.Writes.Load() != 1 {
			t.Fatal("large streaming deploy did not use exactly one SSH write")
		}
	}) {
		return
	}
	if !t.Run("large-reference-only-backup", func(t *testing.T) {
		bootstrap := consumerStreamServer(t, installation, backup, runner)
		cli.backup(t, &bootstrap, "received", true, "--file", target.Path, "--output", cli.backupPath, "--profile", base.Profile, "--stream-references", references)
		consumerAssertFile(t, cli.backupPath, template)
		consumerAssertFile(t, target.Path, expected)
		if target.Reads.Load() != 1 || target.Writes.Load() != 1 {
			t.Fatal("stream backup rewrote the source or repeated SSH")
		}
	}) {
		return
	}
	if !t.Run("large-exact-version-restore", func(t *testing.T) {
		if err := os.WriteFile(target.Path, []byte("changed consumer state\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		bootstrap := consumerStreamServer(t, installation, restore, runner)
		cli.deploy(t, &bootstrap, "received", true, "--file", target.Path, "--template", cli.backupPath, "--profile", base.Profile, "--stream-references", references)
		consumerAssertFile(t, target.Path, expected)
		consumerAssertFile(t, cli.backupPath, template)
		if target.Writes.Load() != 2 {
			t.Fatal("stream restore did not use exactly one SSH write")
		}
	}) {
		return
	}
	if !t.Run("existing-stream-output-is-preserved", func(t *testing.T) {
		bootstrap := consumerStreamServer(t, installation, backup, runner)
		reads := target.Reads.Load()
		cli.backupExisting(t, &bootstrap, func() int { return int(target.Reads.Load() - reads) }, "--file", target.Path, "--output", cli.backupPath, "--profile", base.Profile, "--stream-references", references)
		consumerAssertFile(t, cli.backupPath, template)
		consumerAssertFile(t, target.Path, expected)
		if target.Writes.Load() != 2 {
			t.Fatal("existing-output refusal changed the source")
		}
	}) {
		return
	}
	if !t.Run("exact-missing-version-is-withheld", func(t *testing.T) {
		selected := filepath.Join(cli.root, "missing-version.txt")
		input := "first=" + missing.References[0] + "\nsecond=" + refs[1] + "\n"
		if err := os.WriteFile(selected, []byte(input), 0o600); err != nil {
			t.Fatal(err)
		}
		metadata := consumerStreamReferences(t, cli, "missing-version-refs.json", missing.References)
		before, reads := target.Accepted.Load(), target.Reads.Load()
		bootstrap := consumerStreamServer(t, installation, missing, runner)
		cli.deploy(t, &bootstrap, "withheld", false, "--file", target.Path, "--template", selected, "--profile", base.Profile, "--stream-references", metadata)
		if target.Accepted.Load() != before || target.Writes.Load() != 2 || target.Reads.Load() != reads {
			t.Fatal("missing exact stream version contacted SSH")
		}
		consumerAssertFile(t, target.Path, expected)
	}) {
		return
	}
	if data, err := os.ReadFile(cli.backupPath); err != nil || bytes.Contains(data, []byte(connectedkit.PairShortSecret)) {
		t.Fatal("stream backup disclosed selected values")
	}
	consumerAssertOperatorFiles(t, cli.root)
}

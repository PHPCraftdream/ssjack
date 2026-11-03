package ownertui

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

type fakeBackend struct {
	metadata    vault.DirectoryMetadata
	status      ownerdb.Status
	edits       int
	submissions int
	closes      int
	closeErr    error
	change      vault.OwnerChange
}

func (b *fakeBackend) Metadata() (vault.DirectoryMetadata, error) { return b.metadata, nil }
func (b *fakeBackend) Status() ownerdb.Status                     { return b.status }
func (b *fakeBackend) Edit(func(*vault.Vault) error) error        { b.edits++; return nil }
func (b *fakeBackend) Submit(change vault.OwnerChange) error {
	b.submissions++
	b.change = change
	b.change.Value = append([]byte(nil), change.Value...)
	return nil
}
func (b *fakeBackend) Link(string, []byte) error   { return nil }
func (b *fakeBackend) Reconcile() error            { return nil }
func (b *fakeBackend) ResumeDraft() error          { return nil }
func (b *fakeBackend) CancelDraft() error          { return nil }
func (b *fakeBackend) RetryDatabase() error        { return nil }
func (b *fakeBackend) Close(context.Context) error { b.closes++; return b.closeErr }

func testModel(b *fakeBackend) *Model {
	return &Model{ctx: context.Background(), backend: b, metadata: b.metadata, ready: true, height: 24}
}

func TestTeaModelCancelsWithoutBackendMutation(t *testing.T) {
	b := &fakeBackend{}
	m := testModel(b)
	m.openForm("add-secret")
	m.form.fields[1].value = []byte("synthetic-hidden")
	owned := m.form.fields[1].value
	m.Update(tea.KeyPressMsg{Code: 27})
	if m.form != nil || b.edits != 0 || b.submissions != 0 || m.at.screen != databaseScreen {
		t.Fatal("Escape did not cancel the form without effects")
	}
	for _, c := range owned {
		if c != 0 {
			t.Fatal("cancel retained secret bytes")
		}
	}
}

func TestTeaApplyOwnsInputUntilCommandCompletes(t *testing.T) {
	b := &fakeBackend{}
	m := testModel(b)
	m.openForm("add-secret")
	m.form.fields[0].value = []byte("token")
	m.form.fields[1].value = []byte("synthetic-hidden")
	owned := m.form.fields[1].value
	m.form.focus = len(m.form.fields)
	_, cmd := m.Update(tea.KeyPressMsg{Code: 13})
	if cmd == nil || b.submissions != 0 || !m.working || m.form != nil {
		t.Fatal("Apply executed synchronously or retained an editable form")
	}
	m.Update(cmd())
	if b.submissions != 1 || string(b.change.Value) != "synthetic-hidden" || m.working {
		t.Fatal("Apply lost input or did not complete")
	}
	for _, c := range owned {
		if c != 0 {
			t.Fatal("applied form retained secret bytes")
		}
	}
}

func TestTeaRenderNeverIncludesPrivateValuesOrRawError(t *testing.T) {
	b := &fakeBackend{status: ownerdb.Status{Err: errors.New("synthetic-error-secret")}}
	m := testModel(b)
	m.status = b.status
	m.openForm("add-secret")
	m.form.fields[1].value = []byte("synthetic-hidden")
	view := m.View().Content
	for _, private := range []string{"synthetic-hidden", "synthetic-error-secret"} {
		if strings.Contains(view, private) {
			t.Fatal("view exposed private data")
		}
	}
	if !strings.Contains(view, "ERROR") || !strings.Contains(view, "[Cancel]") {
		t.Fatal("view omitted actionable status or cancellation")
	}
}

func TestTeaCloseFailureDoesNotQuitOrDiscard(t *testing.T) {
	b := &fakeBackend{closeErr: errors.New("unsaved")}
	m := testModel(b)
	cmd := m.requestClose()
	_, next := m.Update(cmd())
	if next != nil || b.closes != 1 || m.working || !strings.Contains(m.message, "Exit stopped") {
		t.Fatal("failed persistence allowed exit")
	}
}

func TestDirectoryFormsPreserveAccountsAndRequireNewAuthMaterial(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	v := vault.New()
	defer v.Close()
	if err := v.UpgradeDirectory(); err != nil {
		t.Fatal(err)
	}
	m := testModel(&fakeBackend{})
	m.openForm("add-server")
	for i, text := range []string{"production", "localhost:22", "main", "first", "password", "synthetic-first", "both", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))} {
		m.form.fields[i].value = []byte(text)
	}
	if err := editDirectory(v, m.form); err != nil {
		t.Fatal(err)
	}
	m.back()
	id, err := v.ServerID("production")
	if err != nil {
		t.Fatal(err)
	}
	m.at = location{screen: serverScreen, server: id}
	m.openForm("add-account")
	for i, text := range []string{"second", "another", "password", "synthetic-second", "human"} {
		m.form.fields[i].value = []byte(text)
	}
	if err := editDirectory(v, m.form); err != nil {
		t.Fatal(err)
	}
	if err := editDirectory(v, m.form); err == nil {
		t.Fatal("add silently overwrote an account")
	}
	m.back()
	first, _ := v.AccountProfile(id, "main")
	second, _ := v.AccountProfile(id, "second")
	if first == second || string(v.Targets[first].Password) != "synthetic-first" || string(v.Targets[second].Password) != "synthetic-second" {
		t.Fatal("account form lost or shared another account's credentials")
	}
	m.at = location{screen: accountScreen, server: id, account: "second"}
	m.openForm("edit-account")
	for i, text := range []string{"second", "changed", "password", "", "human"} {
		m.form.fields[i].value = []byte(text)
	}
	if err := editDirectory(v, m.form); err != nil {
		t.Fatal(err)
	}
	if string(v.Targets[second].Password) != "synthetic-second" || v.Targets[second].User != "changed" {
		t.Fatal("blank credential did not preserve selected account")
	}
	m.form.fields[2].value = []byte("key")
	if err := editDirectory(v, m.form); err == nil {
		t.Fatal("authentication switch reused the wrong credential kind")
	}
	if err := editServer(v, id, "changed:2222", "invalid pin"); err == nil || v.Targets[first].Address != "localhost:22" || v.Targets[second].Address != "localhost:22" {
		t.Fatal("invalid server edit partially changed accounts")
	}
	if err := editServer(v, id, "changed:2222", ""); err != nil {
		t.Fatal(err)
	}
	if v.Targets[first].Address != "changed:2222" || v.Targets[second].Address != "changed:2222" || string(v.Targets[first].Password) != "synthetic-first" || string(v.Targets[second].Password) != "synthetic-second" {
		t.Fatal("server edit lost account metadata or credentials")
	}
	m.back()
}

func TestPasteUsesMaskedBoundedFormInput(t *testing.T) {
	m := testModel(&fakeBackend{})
	m.openForm("add-secret")
	m.form.focus = 1
	m.Update(tea.PasteMsg{Content: "synthetic-paste"})
	if string(m.form.fields[1].value) != "synthetic-paste" || strings.Contains(m.View().Content, "synthetic-paste") {
		t.Fatal("paste was lost or exposed")
	}
	m.Update(tea.PasteMsg{Content: "\x1b[31m"})
	if string(m.form.fields[1].value) != "synthetic-paste" {
		t.Fatal("paste accepted terminal control input")
	}
	m.back()
}

func TestTeaRefreshHasOneScheduledSuccessor(t *testing.T) {
	m := testModel(&fakeBackend{})
	_, cmd := m.Update(tickMsg{})
	if cmd == nil {
		t.Fatal("status refresh chain stopped")
	}
	_, next := m.Update(cmd())
	if next == nil {
		t.Fatal("refresh did not schedule its successor")
	}
	_, extra := m.Update(operationMsg{})
	if extra != nil {
		t.Fatal("operation completion started a duplicate polling chain")
	}
}

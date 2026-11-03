package ownerdb

import (
	"context"
	"encoding/hex"
	"errors"
	"runtime"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto"
	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

type ExportRequest struct {
	Selection             vault.ExportSelection
	Destination           string
	PlaintextConfirmation string
}

func (m *Manager) Export(request ExportRequest) error {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return errors.New("owner export requires a supported private-file runtime")
	}
	if request.Destination == "" || len(request.Destination) > 4096 || strings.ContainsAny(request.Destination, "\x00\r\n") || (request.PlaintextConfirmation != "" && request.PlaintextConfirmation != "EXPORT PLAINTEXT") {
		return errors.New("invalid owner export destination or plaintext confirmation")
	}
	if len(request.Selection.Servers) > 64 || (len(request.Selection.Servers) == 0 && !request.Selection.GlobalSecrets) {
		return errors.New("select an explicit bounded export scope")
	}
	owned := request
	owned.Selection.Servers = make(map[string][]string, len(request.Selection.Servers))
	for id, accounts := range request.Selection.Servers {
		if len(accounts) == 0 || len(accounts) > 64 {
			return errors.New("select explicit bounded export accounts")
		}
		owned.Selection.Servers[id] = append([]string(nil), accounts...)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.closing || m.busy || m.pending != nil || m.err != nil || m.db == nil || m.jobs == nil {
		return ErrPending
	}
	m.exportRequest, m.busy = &owned, true
	m.jobs <- ":export"
	m.signal()
	return nil
}

func (m *Manager) exportArchive(ctx context.Context, request ExportRequest) error {
	if err := syncDatabase(ctx, m.path, m.db); err != nil {
		return err
	}
	plan, err := m.db.PrepareOwnerExport(request.Selection)
	if err != nil {
		return err
	}
	defer plan.Close()
	if len(plan.Bindings()) != 0 {
		if m.link == nil {
			return errors.New("selected values require the linked owner store")
		}
		if m.resources == nil {
			m.resources, err = openResources(ctx, m.link)
			if err != nil {
				return err
			}
		}
		if m.resources.editor != nil {
			m.resources.editor.Close()
			m.resources.editor = nil
		}
		if err := m.resources.openEditor(ctx); err != nil {
			return err
		}
		defer func() { m.resources.editor.Close(); m.resources.editor = nil }()
		if err := m.resources.check(); err != nil {
			return err
		}
		if err := m.resources.editor.AppendOwnerExport(ctx, plan); err != nil {
			return err
		}
		if err := m.resources.check(); err != nil {
			return err
		}
	}
	if request.PlaintextConfirmation == "" {
		return plan.WriteEncrypted(ctx, request.Destination)
	}
	return plan.WritePlaintext(ctx, request.Destination, request.PlaintextConfirmation)
}

var errAliasOnly = errors.New("remove only the shared secret binding")

func (m *Manager) applyValue(change vault.OwnerChange) (string, error) {
	if change.Action == "add" {
		id, err := m.resources.editor.Add(change.MediaType, change.Value)
		return hex.EncodeToString(id[:]), err
	}
	previous, err := appstoreplaceholder.Parse([]byte(change.PreviousReference))
	if err != nil {
		return "", err
	}
	object := previous.ObjectID()
	found := false
	for _, metadata := range m.resources.editor.Objects() {
		if metadata.ObjectID == object {
			if metadata.Reference != previous || metadata.Pending {
				return "", appstorecrypto.ErrOwnerChanged
			}
			found = true
		}
	}
	if !found {
		return "", appstorecrypto.ErrOwnerChanged
	}
	metadata, err := m.db.Metadata()
	if err != nil {
		return "", err
	}
	shared := false
	for aliasID, alias := range metadata.Secrets {
		if aliasID == change.AliasID {
			continue
		}
		reference, err := appstoreplaceholder.Parse([]byte(alias.Ref))
		if err != nil {
			return "", err
		}
		if reference.StoreID() == previous.StoreID() && reference.ObjectID() == object {
			shared = true
		}
	}
	switch change.Action {
	case "update":
		if shared {
			id, err := m.resources.editor.Add(change.MediaType, change.Value)
			return hex.EncodeToString(id[:]), err
		}
		err = m.resources.editor.Update(object, change.Value)
	case "remove":
		if shared {
			return "", errAliasOnly
		}
		err = m.resources.editor.Remove(object)
	default:
		return "", errors.New("unsupported owner value change")
	}
	return hex.EncodeToString(object[:]), err
}

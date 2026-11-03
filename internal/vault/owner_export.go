package vault

import (
	"context"
	"errors"

	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
	"github.com/PHPCraftdream/ssjack/internal/ownerarchive"
)

type ExportSelection struct {
	Servers       map[string][]string
	GlobalSecrets bool
}

type OwnerExportPlan struct {
	source   *Session
	revision uint64
	archive  *ownerarchive.Archive
	bindings map[string]SecretBinding
	closed   bool
}

func (s *Session) PrepareOwnerExport(selection ExportSelection) (*OwnerExportPlan, error) {
	if s == nil {
		return nil, errors.New("owner export requires an authenticated session")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.closing || s.state == nil || s.state.Version != 2 || s.saveErr != nil || s.saved != s.revision || (s.state.OwnerStore != nil && s.state.OwnerStore.Pending != nil) {
		return nil, errors.New("save or reconcile the owner database before exporting")
	}
	if len(selection.Servers) == 0 && !selection.GlobalSecrets {
		return nil, errors.New("select an explicit owner export scope")
	}
	selected := &Vault{Version: 2, Targets: make(map[string]Target), Servers: make(map[string]Server), Secrets: make(map[string]SecretBinding)}
	defer selected.Close()
	for id, names := range selection.Servers {
		server, exists := s.state.Servers[id]
		if !exists || len(names) == 0 {
			return nil, errors.New("selected export server or account does not exist")
		}
		copy := Server{Name: server.Name, Accounts: make(map[string]string)}
		for _, name := range names {
			profile, exists := server.Accounts[name]
			if _, duplicate := copy.Accounts[name]; !exists || duplicate {
				return nil, errors.New("selected export account is missing or duplicated")
			}
			copy.Accounts[name] = profile
			selected.Targets[profile] = ownTarget(s.state.Targets[profile])
		}
		selected.Servers[id] = copy
	}
	for id, binding := range s.state.Secrets {
		_, server := selection.Servers[binding.ServerID]
		if server || (selection.GlobalSecrets && binding.ServerID == "") {
			selected.Secrets[id] = binding
		}
	}
	encoded, err := marshal(selected)
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	archive, err := ownerarchive.New(encoded)
	if err != nil {
		return nil, err
	}
	bindings := make(map[string]SecretBinding, len(selected.Secrets))
	for id, binding := range selected.Secrets {
		bindings[id] = binding
	}
	return &OwnerExportPlan{source: s, revision: s.revision, archive: archive, bindings: bindings}, nil
}

func (p *OwnerExportPlan) Bindings() map[string]SecretBinding {
	result := make(map[string]SecretBinding)
	if p == nil || p.closed {
		return result
	}
	for id, binding := range p.bindings {
		result[id] = binding
	}
	return result
}

func (p *OwnerExportPlan) Add(alias string, reference appstoreref.Ref, value []byte) error {
	if p == nil || p.closed || p.archive == nil {
		return ownerarchive.ErrArchive
	}
	return p.archive.Add(alias, reference, value)
}

func (p *OwnerExportPlan) WriteEncrypted(ctx context.Context, destination string) error {
	return p.write(ctx, destination, "", true)
}

func (p *OwnerExportPlan) WritePlaintext(ctx context.Context, destination, confirmation string) error {
	return p.write(ctx, destination, confirmation, false)
}

func (p *OwnerExportPlan) write(ctx context.Context, destination, confirmation string, encrypted bool) error {
	if p == nil || p.closed || p.source == nil || p.archive == nil {
		return ownerarchive.ErrArchive
	}
	s := p.source
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.closing || s.revision != p.revision || s.saved != p.revision || s.saveErr != nil {
		return errors.New("owner database changed after export selection")
	}
	if encrypted {
		if s.exportKey == nil {
			return errors.New("owner export requires the authenticated cached sealing key")
		}
		return p.archive.WriteEncrypted(ctx, destination, s.exportKey)
	}
	return p.archive.WritePlaintext(ctx, destination, confirmation)
}

func (p *OwnerExportPlan) Close() {
	if p == nil || p.closed {
		return
	}
	p.archive.Close()
	clear(p.bindings)
	p.closed = true
}

package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/mcpgrant"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/sshproxy"
	"github.com/PHPCraftdream/ssjack/internal/vault/internal/record"
)

func directoryID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	if id == ([16]byte{}) {
		return "", errors.New("invalid generated directory identity")
	}
	return hex.EncodeToString(id[:]), nil
}

func ValidDirectoryID(id string) bool {
	decoded, err := hex.DecodeString(id)
	return err == nil && len(decoded) == 16 && hex.EncodeToString(decoded) == id && !bytes.Equal(decoded, make([]byte, 16))
}

func (v *Vault) validateDirectory() error {
	if v.Servers == nil || v.Secrets == nil || len(v.Servers) > 64 || len(v.Secrets) > 128 {
		return errors.New("invalid vault directory bounds")
	}
	names, credentials := make(map[string]bool), make(map[string]bool)
	for id, server := range v.Servers {
		if !ValidDirectoryID(id) || record.ValidateName(server.Name) != nil || names[server.Name] || len(server.Accounts) == 0 || len(server.Accounts) > 64 {
			return errors.New("invalid or duplicate server")
		}
		names[server.Name] = true
		var first *Target
		for name, profile := range server.Accounts {
			target, exists := v.Targets[profile]
			if record.ValidateName(name) != nil || !exists || credentials[profile] {
				return errors.New("invalid or multiply assigned server account")
			}
			credentials[profile] = true
			if first != nil && (first.Address != target.Address || !sameHostKeys(first.HostKeys, target.HostKeys) || !sshproxy.Equal(first.Proxy, target.Proxy)) {
				return errors.New("server accounts must share address, verified host keys and proxy settings")
			}
			copy := target
			first = &copy
		}
	}
	if len(credentials) != len(v.Targets) {
		return errors.New("unassigned credential record")
	}
	scopedNames := make(map[string]bool)
	for id, secret := range v.Secrets {
		if !ValidDirectoryID(id) || record.ValidateName(secret.Name) != nil {
			return errors.New("invalid named secret")
		}
		if secret.ServerID != "" {
			if _, exists := v.Servers[secret.ServerID]; !exists {
				return errors.New("secret refers to an unknown server")
			}
		}
		key := secret.ServerID + "/" + secret.Name
		if scopedNames[key] {
			return errors.New("duplicate secret name in scope")
		}
		scopedNames[key] = true
		reference, err := appstoreplaceholder.Parse([]byte(secret.Ref))
		if err != nil {
			return errors.New("invalid named secret reference")
		}
		canonical, err := appstoreplaceholder.Encode(reference)
		if err != nil || string(canonical) != secret.Ref {
			return errors.New("named secret reference must be canonical")
		}
	}
	return nil
}

func sameHostKeys(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// NewDirectory creates an empty current-schema database.
func NewDirectory() *Vault {
	return &Vault{Version: 2, Targets: make(map[string]Target), Servers: make(map[string]Server), Secrets: make(map[string]SecretBinding)}
}

// InitializeDirectory installs the first account in an empty database.
func (v *Vault) InitializeDirectory(name string, target Target) error {
	if err := v.validate(); err != nil {
		return err
	}
	if len(v.Targets) != 0 || len(v.Servers) != 0 || len(v.Secrets) != 0 || v.OwnerStore != nil || v.RemoteMCP != nil {
		return errors.New("directory initialization requires an empty database")
	}
	id, err := directoryID()
	if err != nil {
		return err
	}
	candidate := NewDirectory()
	candidate.Targets[name] = record.OwnTarget(target)
	candidate.Servers[id] = Server{Name: name, Accounts: map[string]string{"main": name}}
	if err := candidate.validate(); err != nil {
		candidate.Close()
		return err
	}
	v.Version, v.Targets, v.Servers, v.Secrets = candidate.Version, candidate.Targets, candidate.Servers, candidate.Secrets
	return nil
}

func (v *Vault) ServerID(name string) (string, error) {
	if err := v.validate(); err != nil {
		return "", err
	}
	for id, server := range v.Servers {
		if server.Name == name {
			return id, nil
		}
	}
	return "", errors.New("server does not exist")
}

// AccountProfile returns a credential name, never credential bytes.
func (v *Vault) AccountProfile(serverID, account string) (string, error) {
	if err := v.validate(); err != nil {
		return "", err
	}
	server, exists := v.Servers[serverID]
	if !exists {
		return "", errors.New("server does not exist")
	}
	profile, exists := server.Accounts[account]
	if !exists {
		return "", errors.New("server account does not exist")
	}
	return profile, nil
}

// NamedReference uses an explicit scope; local names never shadow global names.
func (v *Vault) NamedReference(serverID, name string) (string, error) {
	if err := v.validate(); err != nil {
		return "", err
	}
	if serverID != "" {
		if _, exists := v.Servers[serverID]; !exists {
			return "", errors.New("server does not exist")
		}
	}
	for _, secret := range v.Secrets {
		if secret.ServerID == serverID && secret.Name == name {
			return secret.Ref, nil
		}
	}
	return "", errors.New("named secret does not exist in selected scope")
}

func (v *Vault) directoryCopy() (*Vault, error) {
	if err := v.validate(); err != nil {
		return nil, err
	}
	if v.Version != 2 {
		return nil, errors.New("directory payload schema v2 is required")
	}
	copy := &Vault{Version: 2, Targets: make(map[string]Target), Servers: make(map[string]Server), Secrets: make(map[string]SecretBinding), OwnerStore: v.OwnerStore}
	for name, target := range v.Targets {
		copy.Targets[name] = target
	}
	for id, server := range v.Servers {
		accounts := make(map[string]string)
		for name, profile := range server.Accounts {
			accounts[name] = profile
		}
		copy.Servers[id] = Server{Name: server.Name, Accounts: accounts}
	}
	for id, secret := range v.Secrets {
		copy.Secrets[id] = secret
	}
	return copy, nil
}

func (v *Vault) applyDirectory(copy *Vault) error {
	if err := copy.validate(); err != nil {
		return err
	}
	v.Targets, v.Servers, v.Secrets = copy.Targets, copy.Servers, copy.Secrets
	return nil
}

func (v *Vault) AddServer(name, account string, target Target) (string, error) {
	copy, err := v.directoryCopy()
	if err != nil {
		return "", err
	}
	id, err := directoryID()
	if err != nil {
		return "", err
	}
	profile, err := directoryID()
	if err != nil {
		return "", err
	}
	if _, exists := copy.Servers[id]; exists {
		return "", errors.New("server identity collision")
	}
	if _, exists := copy.Targets[profile]; exists {
		return "", errors.New("account identity collision")
	}
	owned := record.OwnTarget(target)
	copy.Targets[profile] = owned
	copy.Servers[id] = Server{Name: name, Accounts: map[string]string{account: profile}}
	if err := v.applyDirectory(copy); err != nil {
		clear(owned.PrivateKey)
		clear(owned.Password)
		owned.Proxy.Clear()
		return "", err
	}
	return id, nil
}

func (v *Vault) SetAccount(serverID, name string, target Target) error {
	copy, err := v.directoryCopy()
	if err != nil {
		return err
	}
	server, exists := copy.Servers[serverID]
	if !exists {
		return errors.New("server does not exist")
	}
	for _, selected := range server.Accounts {
		route := copy.Targets[selected].Proxy
		if target.Proxy != nil && !sshproxy.Equal(target.Proxy, route) {
			return errors.New("proxy settings belong to the server, not an SSH account")
		}
		target.Proxy = route
		break
	}
	profile, exists := server.Accounts[name]
	var previous Target
	if exists {
		previous = copy.Targets[profile]
	} else {
		profile, err = directoryID()
		if err != nil {
			return err
		}
		if _, collision := copy.Targets[profile]; collision {
			return errors.New("account identity collision")
		}
	}
	owned := record.OwnTarget(target)
	copy.Targets[profile], server.Accounts[name] = owned, profile
	if err := v.applyDirectory(copy); err != nil {
		clear(owned.PrivateKey)
		clear(owned.Password)
		owned.Proxy.Clear()
		return err
	}
	clear(previous.PrivateKey)
	clear(previous.Password)
	previous.Proxy.Clear()
	return nil
}

func (v *Vault) RenameServer(id, name string) error {
	copy, err := v.directoryCopy()
	if err != nil {
		return err
	}
	server, exists := copy.Servers[id]
	if !exists {
		return errors.New("server does not exist")
	}
	server.Name = name
	copy.Servers[id] = server
	return v.applyDirectory(copy)
}

func (v *Vault) RemoveSecretBinding(id string) error {
	if v.OwnerStore != nil && v.OwnerStore.Pending != nil {
		return errors.New("resolve the pending owner intent before removing secret bindings")
	}
	copy, err := v.directoryCopy()
	if err != nil {
		return err
	}
	if _, exists := copy.Secrets[id]; !exists {
		return errors.New("named secret does not exist")
	}
	delete(copy.Secrets, id)
	return v.applyDirectory(copy)
}

// BindSecret updates exact metadata only; value writes use the app-store lifecycle.
func (v *Vault) BindSecret(id string, secret SecretBinding) (string, error) {
	if v.OwnerStore != nil && v.OwnerStore.Pending != nil {
		return "", errors.New("resolve the pending owner intent before changing secret bindings")
	}
	copy, err := v.directoryCopy()
	if err != nil {
		return "", err
	}
	if id == "" {
		id, err = directoryID()
		if err != nil {
			return "", err
		}
		if _, collision := copy.Secrets[id]; collision {
			return "", errors.New("secret identity collision")
		}
	} else if _, exists := copy.Secrets[id]; !exists {
		return "", errors.New("named secret does not exist")
	}
	copy.Secrets[id] = secret
	if err := v.applyDirectory(copy); err != nil {
		return "", err
	}
	return id, nil
}

// SetServerProxy atomically updates every account. Nil explicitly selects direct.
func (v *Vault) SetServerProxy(serverID string, route *sshproxy.Config) error {
	if route != nil && (route.Type == "" || route.Validate() != nil) {
		return sshproxy.ErrConfig
	}
	candidate, err := v.directoryCopy()
	if err != nil {
		return err
	}
	server, exists := candidate.Servers[serverID]
	if !exists {
		return errors.New("server does not exist")
	}
	var previous, owned []*sshproxy.Config
	for _, profile := range server.Accounts {
		target := candidate.Targets[profile]
		previous = append(previous, target.Proxy)
		target.Proxy = sshproxy.Clone(route)
		owned = append(owned, target.Proxy)
		candidate.Targets[profile] = target
	}
	if err := v.applyDirectory(candidate); err != nil {
		for _, route := range owned {
			route.Clear()
		}
		return err
	}
	for _, route := range previous {
		route.Clear()
	}
	return nil
}

func (v *Vault) validateRemoteMCP() error {
	if err := v.RemoteMCP.Validate(); err != nil {
		return err
	}
	if v.RemoteMCP != nil {
		for profile := range v.RemoteMCP.Last {
			if _, exists := v.Targets[profile]; !exists {
				return mcpdirectory.ErrInvalid
			}
		}
	}
	return nil
}

// RememberRemoteMCP stores a preference, never a grant to access credentials.
func (v *Vault) RememberRemoteMCP(serverID, account string, selected []mcpdirectory.Binding) error {
	profile, err := v.AccountProfile(serverID, account)
	if err != nil {
		return err
	}
	if v.RemoteMCP == nil {
		if len(selected) != 0 {
			return mcpdirectory.ErrMissing
		}
		return nil
	}
	return v.RemoteMCP.Remember(profile, selected)
}
func (v *Vault) SuggestedRemoteMCP(serverID, account string) ([]mcpdirectory.Binding, error) {
	profile, err := v.AccountProfile(serverID, account)
	if err != nil {
		return nil, err
	}
	return v.RemoteMCP.Suggested(profile), nil
}

// RemoteMCPCapture privately captures enabled owner-confirmed MCP records from
// one authenticated unchanged vault before ownership adoption. The retained
// authentication must match the canonical payload and the current on-disk
// ciphertext both before the capture is assembled and again at its return
// boundary; a replaced or edited database revokes the newly owned copies and
// returns only the fixed refusal. The returned capture survives later Vault
// edits, adoption and close and performs no network effect, second unlock or
// per-operation KDF.
func (v *Vault) RemoteMCPCapture(ctx context.Context, path string, digest [32]byte, profile string, bindings []mcpdirectory.Binding) (*mcpgrant.Capture, error) {
	return v.remoteMCPCapture(ctx, path, digest, profile, bindings, nil)
}

// remoteMCPCapture is the admission core. The mutate seam exists only for
// deterministic tests of the across-construction window; production callers
// pass nil. It must never mutate the vault's memory state, which would break
// the authenticated canonical-payload comparison.
func (v *Vault) remoteMCPCapture(ctx context.Context, path string, digest [32]byte, profile string, bindings []mcpdirectory.Binding, mutate func()) (*mcpgrant.Capture, error) {
	if v == nil || ctx == nil || ctx.Err() != nil {
		return nil, mcpgrant.ErrGrant
	}
	if verifyVaultCapture(ctx, path, v) != nil {
		return nil, mcpgrant.ErrGrant
	}
	if digest == ([32]byte{}) || digest != v.revision {
		return nil, mcpgrant.ErrGrant
	}
	if v.OwnerStore != nil && v.OwnerStore.Pending != nil {
		return nil, mcpgrant.ErrGrant
	}
	if _, exists := v.Targets[profile]; !exists {
		return nil, mcpgrant.ErrGrant
	}
	if v.RemoteMCP == nil {
		return nil, mcpgrant.ErrGrant
	}
	records, err := ConfirmedMCPRecords(v.RemoteMCP, bindings)
	if err != nil {
		return nil, err
	}
	capture, err := mcpgrant.NewCapture(ctx, profile, 0, digest, records)
	if err != nil {
		return nil, err
	}
	// A fresh adoption session starts at revision zero; binding that revision
	// makes later database edits invalidate the choice instead of silently
	// adopting changed endpoints or credentials. The origin must still be the
	// authenticated current ciphertext once the owned copies exist.
	if mutate != nil {
		mutate()
	}
	if verifyVaultCapture(ctx, path, v) != nil {
		capture.Close(ctx)
		return nil, mcpgrant.ErrGrant
	}
	return capture, nil
}

// confirmedMCPRecords admits a concrete non-empty confirmed choice against the
// live directory: no duplicate accounts and every binding must still match the
// live enabled binding exactly.
func ConfirmedMCPRecords(directory *mcpdirectory.Directory, bindings []mcpdirectory.Binding) ([]mcpgrant.Record, error) {
	if directory == nil || len(bindings) == 0 || len(bindings) > mcpdirectory.MaxSelections {
		return nil, mcpgrant.ErrGrant
	}
	records := make([]mcpgrant.Record, 0, len(bindings))
	seen := make(map[string]struct{}, len(bindings))
	for _, binding := range bindings {
		if _, dup := seen[binding.AccountID]; dup {
			return nil, mcpgrant.ErrGrant
		}
		seen[binding.AccountID] = struct{}{}
		live, err := directory.CurrentBinding(binding.AccountID)
		if err != nil || live != binding {
			return nil, mcpgrant.ErrGrant
		}
		records = append(records, mcpgrant.Record{
			ServerID:  binding.ServerID,
			AccountID: binding.AccountID,
			Server:    directory.Servers[binding.ServerID],
			Account:   directory.Accounts[binding.AccountID],
		})
	}
	return records, nil
}

// LegacyOutputGuard captures authenticated version-1 credentials before Close.
// Version 2 requires the coordinator's confirmed linked-value admission instead.
func (v *Vault) LegacyOutputGuard(ctx context.Context, path string) (*outputguard.Snapshot, error) {
	if v == nil || ctx == nil || ctx.Err() != nil || v.Version != 1 || verifyVaultCapture(ctx, path, v) != nil {
		return nil, outputguard.ErrGuard
	}
	snapshot, err := CredentialGuard(v)
	if err != nil || ctx.Err() != nil {
		return nil, outputguard.ErrGuard
	}
	return snapshot, nil
}

func CredentialGuard(v *Vault) (*outputguard.Snapshot, error) {
	patterns := make([][]byte, 0)
	total := 0
	add := func(value []byte) bool {
		if len(value) == 0 {
			return true
		}
		if len(patterns) == outputguard.MaxPatterns || len(value) > outputguard.MaxPatternSize || len(value) > outputguard.MaxPatternBytes-total {
			return false
		}
		patterns = append(patterns, value)
		total += len(value)
		return true
	}
	for _, target := range v.Targets {
		if !add(target.Password) || !add(target.PrivateKey) || (target.Proxy != nil && !add(target.Proxy.Password)) {
			return nil, outputguard.ErrGuard
		}
	}
	if journal := v.Rotation; journal != nil && journal.Phase != RotationCancelled && journal.Phase != RotationArchived {
		var seen [][]byte
		for _, target := range v.Targets {
			if len(target.PrivateKey) != 0 {
				seen = append(seen, target.PrivateKey)
			}
		}
		for _, secret := range [][]byte{journal.Original.PrivateKey, journal.NewPrivate} {
			if len(secret) == 0 {
				continue
			}
			duplicate := false
			for _, existing := range seen {
				if bytes.Equal(existing, secret) {
					duplicate = true
					break
				}
			}
			if duplicate {
				continue
			}
			if !add(secret) {
				return nil, outputguard.ErrGuard
			}
			seen = append(seen, secret)
		}
	}
	if v.OwnerStore != nil && !add(v.OwnerStore.Master) {
		return nil, outputguard.ErrGuard
	}
	if v.RemoteMCP != nil {
		for _, account := range v.RemoteMCP.Accounts {
			if !add(account.Auth.Secret) {
				return nil, outputguard.ErrGuard
			}
			for _, header := range account.Headers {
				if !add(header.Value) {
					return nil, outputguard.ErrGuard
				}
			}
		}
	}
	return outputguard.New(patterns)
}

// StateProfile resolves an account to its credential name without validating.
func StateProfile(v *Vault, serverID, account string) (string, bool) {
	server, ok := v.Servers[serverID]
	if !ok {
		return "", false
	}
	profile, ok := server.Accounts[account]
	return profile, ok
}

package vault

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/sshproxy"
	"github.com/PHPCraftdream/ssjack/internal/sshstatus"
)

type AccountMetadata struct {
	Name           string
	Profile        string
	User           string
	Authentication string
	Usage          string
}

type ServerMetadata struct {
	ID           string
	Name         string
	Address      string
	Fingerprints []string
	Accounts     []AccountMetadata
	Proxy        sshproxy.Metadata
}

type OwnerStoreMetadata struct {
	Directory    string
	StoreID      string
	PendingID    string
	PendingPhase string
}

type DirectoryMetadata struct {
	Servers    []ServerMetadata
	Secrets    map[string]SecretBinding
	OwnerStore *OwnerStoreMetadata
	RemoteMCP  mcpdirectory.Metadata
}

// Metadata returns owned display data, never credentials or pending values.
func (s *Session) Metadata() (DirectoryMetadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.metadata()
}

func (s *Session) SetSSHStatus(status func() sshstatus.Status) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sshStatus = status
}

func (s *Session) sshSnapshot() *sshstatus.Status {
	if s.sshStatus == nil {
		return nil
	}
	status := s.sshStatus()
	return &status
}

// MetadataSnapshot binds display data and persistence evidence to one revision.
func (s *Session) MetadataSnapshot() (DirectoryMetadata, SessionStatus, [32]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	metadata, err := s.metadata()
	status := SessionStatus{Revision: s.revision, SavedRevision: s.saved, Pending: s.saved != s.revision, Err: s.saveErr, SSH: s.sshSnapshot()}
	var digest [32]byte
	if err == nil && s.saveErr == nil && s.saved == s.revision {
		digest = s.savedCipher
	}
	return metadata, status, digest, err
}

func (s *Session) metadata() (DirectoryMetadata, error) {
	if s.closed {
		return DirectoryMetadata{}, errors.New("database session is closed")
	}
	result := DirectoryMetadata{Servers: make([]ServerMetadata, 0, len(s.state.Servers)), Secrets: make(map[string]SecretBinding), RemoteMCP: s.state.RemoteMCP.Metadata()}
	for id, server := range s.state.Servers {
		metadata := ServerMetadata{ID: id, Name: server.Name}
		for name, profile := range server.Accounts {
			target := s.state.Targets[profile]
			metadata.Address = target.Address
			metadata.Proxy = target.Proxy.Metadata()
			if len(metadata.Fingerprints) == 0 {
				for _, encoded := range target.HostKeys {
					key, err := ParseHostKey([]byte(encoded))
					if err != nil {
						return DirectoryMetadata{}, err
					}
					metadata.Fingerprints = append(metadata.Fingerprints, ssh.FingerprintSHA256(key))
				}
				sort.Strings(metadata.Fingerprints)
			}
			authentication := "key"
			if len(target.Password) != 0 {
				authentication = "password"
			}
			metadata.Accounts = append(metadata.Accounts, AccountMetadata{Name: name, Profile: profile, User: target.User, Authentication: authentication, Usage: target.EffectiveUsage()})
		}
		sort.Slice(metadata.Accounts, func(i, j int) bool { return metadata.Accounts[i].Name < metadata.Accounts[j].Name })
		result.Servers = append(result.Servers, metadata)
	}
	sort.Slice(result.Servers, func(i, j int) bool { return result.Servers[i].Name < result.Servers[j].Name })
	for id, secret := range s.state.Secrets {
		result.Secrets[id] = secret
	}
	if owner := s.state.OwnerStore; owner != nil {
		result.OwnerStore = &OwnerStoreMetadata{Directory: owner.Directory, StoreID: owner.StoreID}
		if owner.Pending != nil {
			result.OwnerStore.PendingID = owner.Pending.ID
			result.OwnerStore.PendingPhase = owner.Pending.Phase
		}
	}
	return result, nil
}

func (s *Session) AgentSSHAt(expected uint64, digest [32]byte, profile string) (*ssh.ClientConfig, string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unavailable := errors.New("agent SSH configuration unavailable")
	if s.closed || s.closing || s.state == nil || s.state.Version != 2 || s.revision != expected || s.saved != expected || s.saveErr != nil || digest == ([32]byte{}) || digest != s.savedCipher || (s.state.OwnerStore != nil && s.state.OwnerStore.Pending != nil) {
		return nil, "", "", unavailable
	}
	var serverID, account string
	for id, server := range s.state.Servers {
		for name, selected := range server.Accounts {
			if selected == profile {
				if serverID != "" {
					return nil, "", "", unavailable
				}
				serverID, account = id, name
			}
		}
	}
	original, exists := s.state.Targets[profile]
	if serverID == "" || !exists {
		return nil, "", "", unavailable
	}
	target := ownTarget(original)
	defer clear(target.PrivateKey)
	defer clear(target.Password)
	defer target.Proxy.Clear()
	if target.Proxy != nil || target.RequireUsage("agent") != nil {
		return nil, "", "", unavailable
	}
	config, err := target.ClientConfig()
	if err != nil || config.User != target.User {
		return nil, "", "", unavailable
	}
	pins := make([]string, 0, len(target.HostKeys))
	for _, encoded := range target.HostKeys {
		key, err := ParseHostKey([]byte(encoded))
		if err != nil {
			return nil, "", "", unavailable
		}
		pins = append(pins, hex.EncodeToString(key.Marshal()))
	}
	sort.Strings(pins)
	policy := struct {
		HostKeys     []string `json:"host_keys"`
		KeyExchanges []string `json:"key_exchanges"`
		Ciphers      []string `json:"ciphers"`
		MACs         []string `json:"macs"`
	}{
		HostKeys:     append([]string{}, target.SSHPolicy.HostKeys...),
		KeyExchanges: append([]string{}, target.SSHPolicy.KeyExchanges...),
		Ciphers:      append([]string{}, target.SSHPolicy.Ciphers...),
		MACs:         append([]string{}, target.SSHPolicy.MACs...),
	}
	authentication := "key"
	if len(target.Password) != 0 {
		authentication = "password"
	}
	canonical, err := json.Marshal(struct {
		Profile        string   `json:"profile"`
		ServerID       string   `json:"server_id"`
		Account        string   `json:"account"`
		Address        string   `json:"address"`
		User           string   `json:"user"`
		Authentication string   `json:"authentication"`
		Usage          string   `json:"usage"`
		HostKeys       []string `json:"host_keys"`
		Policy         any      `json:"ssh_policy"`
	}{profile, serverID, account, target.Address, target.User, authentication, target.EffectiveUsage(), pins, policy})
	if err != nil {
		return nil, "", "", unavailable
	}
	scopeDigest := sha256.Sum256(canonical)
	scope := hex.EncodeToString(scopeDigest[:])
	return config, target.Address, scope, nil
}

// HumanSSH is the single narrow credential path for an owner-selected
// interactive connection: it yields a host-pin verified client configuration,
// never raw credential bytes, and only for human-permitted accounts.
func (s *Session) HumanSSH(serverID, account string) (*ssh.ClientConfig, string, error) {
	return s.humanSSH(nil, serverID, account)
}
func (s *Session) HumanSSHAt(expected uint64, serverID, account string) (*ssh.ClientConfig, string, error) {
	return s.humanSSH(&expected, serverID, account)
}
func (s *Session) humanSSH(expected *uint64, serverID, account string) (*ssh.ClientConfig, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if expected != nil && *expected != s.revision {
		return nil, "", ErrOwnerRevision
	}
	if s.closed {
		return nil, "", errors.New("database session is closed")
	}
	profile, err := s.state.AccountProfile(serverID, account)
	if err != nil {
		return nil, "", err
	}
	// The copy keeps later Apply or close zeroization away from the config, and
	// is itself cleared once the config holds its own derived material.
	target := ownTarget(s.state.Targets[profile])
	defer clear(target.PrivateKey)
	defer clear(target.Password)
	defer target.Proxy.Clear()
	if err := target.RequireUsage("human"); err != nil {
		return nil, "", err
	}
	config, err := target.ClientConfig()
	if err != nil {
		return nil, "", err
	}
	return config, target.Address, nil
}

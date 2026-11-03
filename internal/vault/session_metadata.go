package vault

import (
	"errors"
	"sort"

	"golang.org/x/crypto/ssh"
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
}

// Metadata returns owned display data, never credentials or pending values.
func (s *Session) Metadata() (DirectoryMetadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return DirectoryMetadata{}, errors.New("database session is closed")
	}
	result := DirectoryMetadata{Servers: make([]ServerMetadata, 0, len(s.state.Servers)), Secrets: make(map[string]SecretBinding)}
	for id, server := range s.state.Servers {
		metadata := ServerMetadata{ID: id, Name: server.Name}
		for name, profile := range server.Accounts {
			target := s.state.Targets[profile]
			metadata.Address = target.Address
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

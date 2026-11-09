package vault

import "github.com/PHPCraftdream/ssjack/internal/mcpdirectory"

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

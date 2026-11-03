package vault

import "errors"

func (v *Vault) directoryCopy() (*Vault, error) {
	if err := v.validate(); err != nil {
		return nil, err
	}
	if v.Version != 2 {
		return nil, errors.New("explicit directory migration is required")
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

func ownTarget(target Target) Target {
	target.PrivateKey = append([]byte(nil), target.PrivateKey...)
	target.Password = append([]byte(nil), target.Password...)
	target.HostKeys = append([]string(nil), target.HostKeys...)
	target.SSHPolicy.HostKeys = append([]string(nil), target.SSHPolicy.HostKeys...)
	target.SSHPolicy.KeyExchanges = append([]string(nil), target.SSHPolicy.KeyExchanges...)
	target.SSHPolicy.Ciphers = append([]string(nil), target.SSHPolicy.Ciphers...)
	target.SSHPolicy.MACs = append([]string(nil), target.SSHPolicy.MACs...)
	return target
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
	owned := ownTarget(target)
	copy.Targets[profile] = owned
	copy.Servers[id] = Server{Name: name, Accounts: map[string]string{account: profile}}
	if err := v.applyDirectory(copy); err != nil {
		clear(owned.PrivateKey)
		clear(owned.Password)
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
	owned := ownTarget(target)
	copy.Targets[profile], server.Accounts[name] = owned, profile
	if err := v.applyDirectory(copy); err != nil {
		clear(owned.PrivateKey)
		clear(owned.Password)
		return err
	}
	clear(previous.PrivateKey)
	clear(previous.Password)
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

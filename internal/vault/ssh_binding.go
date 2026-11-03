package vault

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
)

// PasswordCredentialIdentity binds exact selected credentials without publishing
// an offline password verifier. It requires the authenticated owner unlock.
func (v *Vault) PasswordCredentialIdentity(profile string) (string, error) {
	if err := v.validate(); err != nil {
		return "", err
	}
	target, exists := v.Targets[profile]
	if !exists || len(target.Password) == 0 {
		return "", errors.New("selected password credential does not exist")
	}
	canonical, err := passwordIdentityMetadata(profile, target)
	if err != nil {
		return "", err
	}
	binding, err := v.unlocked.SSHPasswordBinding(canonical, target.Password)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(binding[:]), nil
}

func passwordIdentityMetadata(profile string, target Target) ([]byte, error) {
	pins := make([]string, len(target.HostKeys))
	for i, encoded := range target.HostKeys {
		key, err := ParseHostKey([]byte(encoded))
		if err != nil {
			return nil, err
		}
		pins[i] = ssh.FingerprintSHA256(key)
	}
	sort.Strings(pins)
	identity := struct {
		Profile        string   `json:"profile"`
		Address        string   `json:"address"`
		User           string   `json:"user"`
		HostKeys       []string `json:"host_keys"`
		Authentication string   `json:"authentication"`
	}{profile, target.Address, target.User, pins, "password"}
	raw, err := json.Marshal(identity)
	if err != nil {
		return nil, errors.New("cannot encode password credential identity")
	}
	canonical, err := canonicaljson.Canonicalize(raw)
	if err != nil {
		return nil, errors.New("cannot canonicalize password credential identity")
	}
	return canonical, nil
}

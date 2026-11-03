package vault

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"

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
	pins := append([]string(nil), target.HostKeys...)
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
		return "", errors.New("cannot encode password credential identity")
	}
	canonical, err := canonicaljson.Canonicalize(raw)
	if err != nil {
		return "", errors.New("cannot canonicalize password credential identity")
	}
	binding, err := v.unlocked.SSHPasswordBinding(canonical, target.Password)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(binding[:]), nil
}

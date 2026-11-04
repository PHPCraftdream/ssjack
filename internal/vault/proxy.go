package vault

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
	"github.com/PHPCraftdream/ssjack/internal/sshproxy"
)

// ProxyCredentialIdentity never publishes an unkeyed proxy-password verifier.
func (v *Vault) ProxyCredentialIdentity(profile string) (string, error) {
	if err := v.validate(); err != nil {
		return "", err
	}
	target, exists := v.Targets[profile]
	if !exists || target.Proxy == nil {
		return "", errors.New("selected proxied credential does not exist")
	}
	pins := make([]string, 0, len(target.HostKeys))
	for _, encoded := range target.HostKeys {
		key, err := ParseHostKey([]byte(encoded))
		if err != nil {
			return "", errors.New("invalid selected SSH identity")
		}
		pins = append(pins, ssh.FingerprintSHA256(key))
	}
	sort.Strings(pins)
	kind, signer := "password", ""
	if len(target.Password) == 0 {
		key, err := ssh.ParsePrivateKey(target.PrivateKey)
		if err != nil {
			return "", errors.New("invalid selected SSH identity")
		}
		kind, signer = "key", ssh.FingerprintSHA256(key.PublicKey())
	}
	raw, err := json.Marshal(map[string]any{
		"format": "ssjack-ssh-proxy-identity-v1", "profile": profile,
		"address": target.Address, "user": target.User, "host_keys": pins,
		"authentication": kind, "signer": signer, "proxy_type": target.Proxy.Type,
		"proxy_address": target.Proxy.Address, "proxy_user": target.Proxy.Username,
	})
	if err != nil {
		return "", errors.New("cannot encode routed credential identity")
	}
	identity, err := canonicaljson.Canonicalize(raw)
	if err != nil {
		return "", errors.New("cannot canonicalize routed credential identity")
	}
	private := make([]byte, 0, 16+len(target.Password)+len(target.Proxy.Password))
	private = binary.BigEndian.AppendUint64(private, uint64(len(target.Password)))
	private = append(private, target.Password...)
	private = binary.BigEndian.AppendUint64(private, uint64(len(target.Proxy.Password)))
	private = append(private, target.Proxy.Password...)
	defer clear(private)
	binding, err := v.unlocked.SSHProxyBinding(identity, private)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(binding[:]), nil
}

func validateProxyFields(value any) error {
	fields, ok := value.(map[string]any)
	if !ok || (len(fields) != 2 && len(fields) != 4) {
		return sshproxy.ErrConfig
	}
	for field := range fields {
		switch field {
		case "type", "address", "username", "password":
		default:
			return sshproxy.ErrConfig
		}
	}
	if fields["type"] == nil || fields["address"] == nil {
		return sshproxy.ErrConfig
	}
	_, user := fields["username"]
	_, password := fields["password"]
	if user != password || (user && (fields["username"] == nil || fields["password"] == nil)) {
		return sshproxy.ErrConfig
	}
	return nil
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

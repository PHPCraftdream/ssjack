package vault

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/sshauth"
	"github.com/PHPCraftdream/ssjack/internal/sshproxy"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
)

type Target struct {
	Address    string           `json:"address"`
	User       string           `json:"user"`
	PrivateKey []byte           `json:"private_key"`
	Password   []byte           `json:"password,omitempty"`
	HostKeys   []string         `json:"host_keys"`
	Usage      string           `json:"usage,omitempty"`
	SSHPolicy  SSHPolicy        `json:"ssh_policy,omitempty"`
	Proxy      *sshproxy.Config `json:"proxy,omitempty"`
}

type Vault struct {
	Version     int                      `json:"version"`
	Targets     map[string]Target        `json:"targets"`
	Servers     map[string]Server        `json:"servers,omitempty"`
	Secrets     map[string]SecretBinding `json:"secrets,omitempty"`
	OwnerStore  *OwnerStore              `json:"owner_store,omitempty"`
	revision    [sha256.Size]byte
	payloadHash [sha256.Size]byte
	format      int
	unlocked    *keyfile.Unlocked
}

var targetName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

func New() *Vault {
	return &Vault{Version: 1, Targets: make(map[string]Target)}
}

func (v *Vault) Close() {
	v.unlocked.Close()
	v.unlocked = nil
	for name, target := range v.Targets {
		clear(target.PrivateKey)
		clear(target.Password)
		target.Proxy.Clear()
		delete(v.Targets, name)
	}
	clear(v.Servers)
	clear(v.Secrets)
	v.OwnerStore.clear()
	v.OwnerStore = nil
	clear(v.payloadHash[:])
}

func (v *Vault) ReplaceKey(name string, private []byte) error {
	target, exists := v.Targets[name]
	if !exists {
		return errors.New("credential record does not exist")
	}
	if len(private) == 0 || len(private) > keyfile.MaxPlaintext {
		return errors.New("invalid imported private key size")
	}
	updated := target
	updated.Password = nil
	updated.PrivateKey = append([]byte(nil), private...)
	if err := updated.Validate(); err != nil {
		clear(updated.PrivateKey)
		return err
	}
	clear(target.PrivateKey)
	clear(target.Password)
	v.Targets[name] = updated
	return nil
}

func (v *Vault) ReplaceHostKeys(name string, pins []string) error {
	target, exists := v.Targets[name]
	if !exists {
		return errors.New("credential record does not exist")
	}
	updated := target
	updated.HostKeys = append([]string(nil), pins...)
	if err := updated.Validate(); err != nil {
		return err
	}
	v.Targets[name] = updated
	return nil
}

func ValidateName(name string) error {
	if !targetName.MatchString(name) {
		return errors.New("target name must be 1 to 64 ASCII letters, digits, dots, underscores, or hyphens, starting with a letter or digit")
	}
	return nil
}

func ParseHostKey(data []byte) (ssh.PublicKey, error) {
	key, _, options, rest, err := ssh.ParseAuthorizedKey(data)
	if err != nil || len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("expected one bare OpenSSH server public key, not a known_hosts line")
	}
	if _, certificate := key.(*ssh.Certificate); certificate {
		return nil, errors.New("host certificates are not supported; supply a verified raw server public key")
	}
	return key, nil
}

func (t Target) Validate() error {
	if t.Proxy != nil && (t.Proxy.Type == "" || t.Proxy.Validate() != nil || sshproxy.ValidateTarget(t.Address) != nil) {
		return sshproxy.ErrConfig
	}
	if err := t.SSHPolicy.Validate(); err != nil {
		return err
	}
	if t.Usage != "" && t.Usage != "both" && t.Usage != "human" && t.Usage != "agent" {
		return errors.New("credential usage must be both, human, or agent")
	}
	host, port, err := net.SplitHostPort(t.Address)
	if err != nil || host == "" || port == "" || len(t.Address) > 1024 || strings.ContainsAny(t.Address, "\r\n\x00") {
		return errors.New("target address must use host:port form")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 || strings.Trim(port, "0123456789") != "" {
		return errors.New("SSH port must be a number from 1 to 65535")
	}
	if t.User == "" || len(t.User) > 256 || strings.ContainsAny(t.User, "\r\n\x00") {
		return errors.New("invalid SSH user")
	}
	if err := t.validateAuthentication(); err != nil {
		return err
	}
	if len(t.HostKeys) == 0 || len(t.HostKeys) > 8 {
		return errors.New("provide 1 to 8 verified server public keys")
	}
	seen := make(map[string]bool)
	for _, encoded := range t.HostKeys {
		if len(encoded) > 16384 {
			return errors.New("server public key is too large")
		}
		key, err := ParseHostKey([]byte(encoded))
		if err != nil {
			return err
		}
		identity := string(key.Marshal())
		if seen[identity] {
			return errors.New("duplicate server public key")
		}
		seen[identity] = true
	}
	return nil
}

func (t Target) EffectiveUsage() string {
	if t.Usage == "" {
		return "both"
	}
	return t.Usage
}

func (t Target) RequireUsage(mode string) error {
	if mode != "human" && mode != "agent" {
		return errors.New("unknown credential usage mode")
	}
	if usage := t.EffectiveUsage(); usage != "both" && usage != mode {
		return fmt.Errorf("credential record permits %s usage, not %s", usage, mode)
	}
	return nil
}

func (t Target) ClientConfig() (*ssh.ClientConfig, error) {
	if err := t.Validate(); err != nil {
		return nil, err
	}
	var authentication ssh.AuthMethod
	if len(t.Password) != 0 {
		authentication = sshauth.Password(t.Password)
	} else {
		signer, err := ssh.ParsePrivateKey(t.PrivateKey)
		if err != nil {
			return nil, err
		}
		authentication = sshauth.PublicKey(signer)
	}
	if t.Proxy != nil {
		var err error
		authentication, err = sshauth.WithProxy(authentication, t.Proxy)
		if err != nil {
			return nil, err
		}
	}
	var pins [][]byte
	for _, encoded := range t.HostKeys {
		key, err := ParseHostKey([]byte(encoded))
		if err != nil {
			return nil, err
		}
		pins = append(pins, key.Marshal())
	}
	supported := ssh.SupportedAlgorithms()
	selectAlgorithms := func(selected, defaults []string) []string {
		if len(selected) == 0 {
			selected = defaults
		}
		return append([]string(nil), selected...)
	}
	return &ssh.ClientConfig{
		Config:            ssh.Config{KeyExchanges: selectAlgorithms(t.SSHPolicy.KeyExchanges, supported.KeyExchanges), Ciphers: selectAlgorithms(t.SSHPolicy.Ciphers, supported.Ciphers), MACs: selectAlgorithms(t.SSHPolicy.MACs, supported.MACs)},
		HostKeyAlgorithms: selectAlgorithms(t.SSHPolicy.HostKeys, supported.HostKeys),
		User:              t.User,
		Auth:              []ssh.AuthMethod{authentication},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			for _, pin := range pins {
				if bytes.Equal(pin, key.Marshal()) {
					return nil
				}
			}
			return errors.New("SSH server key does not match the encrypted vault pins")
		},
	}, nil
}

func (v *Vault) validate() error {
	if (v.Version != 1 && v.Version != 2) || v.Targets == nil || len(v.Targets) > 64 {
		return errors.New("unsupported vault version or target count")
	}
	if v.Version == 1 && (v.Servers != nil || v.Secrets != nil || v.OwnerStore != nil) {
		return errors.New("version 1 cannot contain directory metadata")
	}
	if v.Version == 2 {
		if err := v.validateDirectory(); err != nil {
			return err
		}
		if err := v.validateOwnerStore(); err != nil {
			return err
		}
	}
	for name, target := range v.Targets {
		if v.Version == 1 && len(target.Password) != 0 {
			return errors.New("password authentication requires database version 2")
		}
		if v.Version == 1 && target.Proxy != nil {
			return errors.New("proxy settings require database version 2")
		}
		if err := ValidateName(name); err != nil {
			return err
		}
		if err := target.Validate(); err != nil {
			return fmt.Errorf("invalid target %q: %w", name, err)
		}
	}
	return nil
}

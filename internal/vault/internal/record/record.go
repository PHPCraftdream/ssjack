// Package record holds credential record types and their own validation.
package record

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
	"github.com/PHPCraftdream/ssjack/internal/sshauth"
	"github.com/PHPCraftdream/ssjack/internal/sshproxy"
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

var targetName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

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

func (t Target) validateAuthentication() error {
	if len(t.Password) != 0 {
		if len(t.PrivateKey) != 0 || len(t.Password) > 4096 {
			return errors.New("select exactly one bounded SSH password or private key")
		}
		return nil
	}
	if len(t.PrivateKey) == 0 || len(t.PrivateKey) > keyfile.MaxPlaintext {
		return errors.New("invalid private key size")
	}
	if _, err := ssh.ParsePrivateKey(t.PrivateKey); err != nil {
		return errors.New("vault private key must be an unencrypted in-memory SSH key")
	}
	return nil
}

// Server IDs survive renames; accounts refer to existing credential records.
type Server struct {
	Name     string            `json:"name"`
	Accounts map[string]string `json:"accounts"`
}

// SecretBinding names exact metadata, not secret values or access permissions.
type SecretBinding struct {
	Name     string `json:"name"`
	ServerID string `json:"server_id"`
	Ref      string `json:"ref"`
}

func OwnTarget(target Target) Target {
	target.Proxy = sshproxy.Clone(target.Proxy)
	target.PrivateKey = append([]byte(nil), target.PrivateKey...)
	target.Password = append([]byte(nil), target.Password...)
	target.HostKeys = append([]string(nil), target.HostKeys...)
	target.SSHPolicy.HostKeys = append([]string(nil), target.SSHPolicy.HostKeys...)
	target.SSHPolicy.KeyExchanges = append([]string(nil), target.SSHPolicy.KeyExchanges...)
	target.SSHPolicy.Ciphers = append([]string(nil), target.SSHPolicy.Ciphers...)
	target.SSHPolicy.MACs = append([]string(nil), target.SSHPolicy.MACs...)
	return target
}

// SameTarget compares every Target field; nil and empty lists are equal.
func SameTarget(a, b Target) bool {
	return a.Address == b.Address && a.User == b.User && a.Usage == b.Usage && sshproxy.Equal(a.Proxy, b.Proxy) &&
		bytes.Equal(a.PrivateKey, b.PrivateKey) && bytes.Equal(a.Password, b.Password) &&
		slices.Equal(a.HostKeys, b.HostKeys) && slices.Equal(a.SSHPolicy.HostKeys, b.SSHPolicy.HostKeys) &&
		slices.Equal(a.SSHPolicy.KeyExchanges, b.SSHPolicy.KeyExchanges) &&
		slices.Equal(a.SSHPolicy.Ciphers, b.SSHPolicy.Ciphers) && slices.Equal(a.SSHPolicy.MACs, b.SSHPolicy.MACs)
}

// VerifyOwnerImportDirectory proves the destination still holds exactly the

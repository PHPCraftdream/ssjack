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

	"github.com/ktav-lang/golang/pure"
	"golang.org/x/crypto/ssh"

	"storagehost/internal/keyfile"
)

type Target struct {
	Address    string   `json:"address"`
	User       string   `json:"user"`
	PrivateKey []byte   `json:"private_key"`
	HostKeys   []string `json:"host_keys"`
	Usage      string   `json:"usage,omitempty"`
}

type Vault struct {
	Version  int               `json:"version"`
	Targets  map[string]Target `json:"targets"`
	revision [sha256.Size]byte
}

var targetName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

func New() *Vault {
	return &Vault{Version: 1, Targets: make(map[string]Target)}
}

func (v *Vault) Close() {
	for name, target := range v.Targets {
		clear(target.PrivateKey)
		delete(v.Targets, name)
	}
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
	updated.PrivateKey = append([]byte(nil), private...)
	if err := updated.Validate(); err != nil {
		clear(updated.PrivateKey)
		return err
	}
	clear(target.PrivateKey)
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
	if len(t.PrivateKey) == 0 || len(t.PrivateKey) > keyfile.MaxPlaintext {
		return errors.New("invalid private key size")
	}
	if _, err := ssh.ParsePrivateKey(t.PrivateKey); err != nil {
		return errors.New("vault private key must be an unencrypted in-memory SSH key")
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
	signer, err := ssh.ParsePrivateKey(t.PrivateKey)
	if err != nil {
		return nil, err
	}
	var pins [][]byte
	for _, encoded := range t.HostKeys {
		key, err := ParseHostKey([]byte(encoded))
		if err != nil {
			return nil, err
		}
		pins = append(pins, key.Marshal())
	}
	return &ssh.ClientConfig{
		User: t.User,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
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
	if v.Version != 1 || v.Targets == nil || len(v.Targets) > 64 {
		return errors.New("unsupported vault version or target count")
	}
	for name, target := range v.Targets {
		if err := ValidateName(name); err != nil {
			return err
		}
		if err := target.Validate(); err != nil {
			return fmt.Errorf("invalid target %q: %w", name, err)
		}
	}
	return nil
}

func marshal(v *Vault) ([]byte, error) {
	if err := v.validate(); err != nil {
		return nil, err
	}
	records := make(map[string]any, len(v.Targets))
	for name, target := range v.Targets {
		record := map[string]any{"address": target.Address, "user": target.User, "private_key": target.PrivateKey, "host_keys": target.HostKeys}
		if target.Usage != "" {
			record["usage"] = target.Usage
		}
		records[name] = record
	}
	body, err := pure.EmitCanonical(map[string]any{"version": v.Version, "targets": records})
	if err != nil {
		return nil, err
	}
	if len(body) > keyfile.MaxPlaintext {
		return nil, errors.New("vault exceeds the 64 KiB plaintext limit")
	}
	return []byte(body), nil
}

func unmarshal(data []byte) (*Vault, error) {
	if len(data) > keyfile.MaxPlaintext {
		return nil, errors.New("vault exceeds the 64 KiB plaintext limit")
	}
	value, err := pure.LoadsStrict(string(data))
	if err != nil {
		return nil, errors.New("invalid vault Ktav")
	}
	root, ok := value.(map[string]any)
	if !ok || len(root) != 2 || root["version"] == nil {
		return nil, errors.New("invalid vault fields")
	}
	targets, ok := root["targets"].(map[string]any)
	if !ok || len(targets) > 64 {
		return nil, errors.New("invalid vault targets")
	}
	for _, value := range targets {
		target, ok := value.(map[string]any)
		if !ok || (len(target) != 4 && len(target) != 5) {
			return nil, errors.New("invalid vault target fields")
		}
		for field := range target {
			switch field {
			case "address", "user", "private_key", "host_keys", "usage":
			default:
				return nil, errors.New("unknown vault target field")
			}
		}
		for _, field := range []string{"address", "user", "private_key", "host_keys"} {
			if target[field] == nil {
				return nil, fmt.Errorf("missing vault target field %q", field)
			}
		}
	}
	var v Vault
	if err := pure.LoadsInto(string(data), &v); err != nil {
		v.Close()
		return nil, errors.New("invalid vault values")
	}
	if err := v.validate(); err != nil {
		v.Close()
		return nil, err
	}
	return &v, nil
}

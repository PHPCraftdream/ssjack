package record

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

type SSHPolicy struct {
	HostKeys     []string `json:"host_keys,omitempty"`
	KeyExchanges []string `json:"key_exchanges,omitempty"`
	Ciphers      []string `json:"ciphers,omitempty"`
	MACs         []string `json:"macs,omitempty"`
}

func (p SSHPolicy) Empty() bool {
	return len(p.HostKeys)+len(p.KeyExchanges)+len(p.Ciphers)+len(p.MACs) == 0
}

func validateAlgorithms(label string, selected, supported []string) error {
	if len(selected) > 32 {
		return errors.New("too many SSH algorithm preferences")
	}
	allowed := make(map[string]bool, len(supported))
	for _, algorithm := range supported {
		allowed[algorithm] = true
	}
	seen := make(map[string]bool)
	for _, algorithm := range selected {
		if !allowed[algorithm] || seen[algorithm] {
			return fmt.Errorf("unsupported, insecure, or duplicate %s algorithm", label)
		}
		seen[algorithm] = true
	}
	return nil
}

func (p SSHPolicy) Validate() error {
	supported := ssh.SupportedAlgorithms()
	for _, list := range []struct {
		name              string
		selected, allowed []string
	}{
		{"host key", p.HostKeys, supported.HostKeys},
		{"key exchange", p.KeyExchanges, supported.KeyExchanges},
		{"cipher", p.Ciphers, supported.Ciphers},
		{"MAC", p.MACs, supported.MACs},
	} {
		if err := validateAlgorithms(list.name, list.selected, list.allowed); err != nil {
			return err
		}
	}
	return nil
}

// Package sshproxy implements explicit SSH tunnels, never environment-selected routes.
package sshproxy

import (
	"bytes"
	"errors"
	"net"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	SOCKS5 = "socks5"
	HTTP   = "http"
)

var (
	ErrConfig = errors.New("invalid SSH proxy settings")
	ErrProxy  = errors.New("SSH proxy tunnel failed")
)

type Config struct {
	Type     string `json:"type"`
	Address  string `json:"address"`
	Username string `json:"username,omitempty"`
	Password []byte `json:"password,omitempty"`
}

func endpoint(address string) (string, uint16, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || len(address) > 1024 || host == "" || len(host) > 255 || len(port) > 5 {
		return "", 0, ErrConfig
	}
	for _, b := range []byte(host) {
		if b <= 32 || b >= 127 || strings.ContainsRune("/\\[]?#@%", rune(b)) {
			return "", 0, ErrConfig
		}
	}
	if strings.Contains(host, ":") && net.ParseIP(host) == nil {
		return "", 0, ErrConfig
	}
	if port == "" || strings.Trim(port, "0123456789") != "" {
		return "", 0, ErrConfig
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", 0, ErrConfig
	}
	return host, uint16(n), nil
}

// ValidateTarget enforces the address bytes the supported tunnel protocols carry.
func ValidateTarget(address string) error {
	_, _, err := endpoint(address)
	return err
}

// A zero config means direct; a stored optional proxy must be nonzero.
func (c Config) Validate() error {
	if c.Type == "" {
		if c.Address == "" && c.Username == "" && len(c.Password) == 0 {
			return nil
		}
		return ErrConfig
	}
	if c.Type != SOCKS5 && c.Type != HTTP {
		return ErrConfig
	}
	if _, _, err := endpoint(c.Address); err != nil {
		return ErrConfig
	}
	limit := 1024
	if c.Type == SOCKS5 {
		limit = 255
	}
	if !utf8.ValidString(c.Username) || len(c.Username) > 255 || len(c.Password) > limit || strings.ContainsAny(c.Username, "\x00\r\n") || (c.Type == HTTP && strings.Contains(c.Username, ":")) || bytes.ContainsAny(c.Password, "\x00\r\n") {
		return ErrConfig
	}
	if (c.Username == "") != (len(c.Password) == 0) {
		return ErrConfig
	}
	return nil
}

// Metadata omits authentication material; display never borrows password bytes.
type Metadata struct {
	Type, Address, Username string
	Authenticated           bool
}

func (c *Config) Metadata() Metadata {
	if c == nil {
		return Metadata{}
	}
	return Metadata{Type: c.Type, Address: c.Address, Username: c.Username, Authenticated: len(c.Password) != 0}
}

func Clone(c *Config) *Config {
	if c == nil {
		return nil
	}
	copy := *c
	copy.Password = append([]byte(nil), c.Password...)
	return &copy
}

func Equal(a, b *Config) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Type == b.Type && a.Address == b.Address && a.Username == b.Username && bytes.Equal(a.Password, b.Password)
}

func (c *Config) Clear() {
	if c != nil {
		clear(c.Password)
		c.Password = nil
	}
}

package mcpdirectory

import (
	"bytes"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

var namePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)
var headerPattern = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,128}$")

func validID(id string) bool {
	raw, err := hex.DecodeString(id)
	return err == nil && len(raw) == 16 && hex.EncodeToString(raw) == id && !bytes.Equal(raw, make([]byte, 16))
}
func validURL(value string) bool {
	if len(value) == 0 || len(value) > 2048 || strings.ContainsAny(value, "\x00\r\n\t ") {
		return false
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(u.Path, "\x00\r\n") {
		return false
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strings.Trim(port, "0123456789") != "" {
			return false
		}
	}
	if strings.Contains(u.Hostname(), ":") && net.ParseIP(u.Hostname()) == nil {
		return false
	}
	return u.String() == value
}
func validHeaderName(name string) bool {
	if !headerPattern.MatchString(name) || http.CanonicalHeaderKey(name) != name {
		return false
	}
	lower := strings.ToLower(name)
	if strings.HasPrefix(lower, "mcp-") || strings.HasPrefix(lower, "x-forwarded-") {
		return false
	}
	switch lower {
	case "authorization", "proxy-authorization", "cookie", "set-cookie", "host", "connection", "content-length", "content-type", "accept", "accept-encoding", "transfer-encoding", "trailer", "te", "upgrade", "origin", "forwarded", "user-agent":
		return false
	}
	return true
}
func validSecret(value []byte) bool {
	return len(value) > 0 && len(value) <= 8192 && utf8.Valid(value) && !bytes.ContainsAny(value, "\x00\r\n")
}
func validAccount(a Account) bool {
	if !validID(a.ServerID) || !namePattern.MatchString(a.Name) || a.Revision == 0 || len(a.Headers) > 4 {
		return false
	}
	switch a.Auth.Kind {
	case "none":
		if a.Auth.Username != "" || len(a.Auth.Secret) != 0 {
			return false
		}
	case "bearer":
		if a.Auth.Username != "" || !validSecret(a.Auth.Secret) {
			return false
		}
		for _, c := range a.Auth.Secret {
			if c < 33 || c > 126 {
				return false
			}
		}
	case "basic":
		if a.Auth.Username == "" || len(a.Auth.Username) > 256 || !utf8.ValidString(a.Auth.Username) || strings.ContainsAny(a.Auth.Username, ":\x00\r\n") || !validSecret(a.Auth.Secret) {
			return false
		}
	default:
		return false
	}
	seen := make(map[string]bool)
	for _, h := range a.Headers {
		if !validHeaderName(h.Name) || !validSecret(h.Value) || seen[h.Name] {
			return false
		}
		seen[h.Name] = true
	}
	return true
}

// ValidateAccount applies the stored-record contract without exposing values.
func ValidateAccount(account Account) error {
	if !validAccount(account) {
		return ErrInvalid
	}
	return nil
}

func (d *Directory) Validate() error {
	if d == nil {
		return nil
	}
	if d.Servers == nil || d.Accounts == nil || d.Last == nil || len(d.Servers) > MaxServers || len(d.Accounts) > MaxAccounts || len(d.Last) > 64 {
		return ErrInvalid
	}
	names := make(map[string]bool)
	for id, s := range d.Servers {
		if !validID(id) || !namePattern.MatchString(s.Name) || !validURL(s.URL) || s.Revision == 0 || names[s.Name] {
			return ErrInvalid
		}
		names[s.Name] = true
	}
	names = make(map[string]bool)
	for id, a := range d.Accounts {
		if !validID(id) || !validAccount(a) {
			return ErrInvalid
		}
		if _, ok := d.Servers[a.ServerID]; !ok {
			return ErrInvalid
		}
		key := a.ServerID + "/" + a.Name
		if names[key] {
			return ErrInvalid
		}
		names[key] = true
	}
	for context, selected := range d.Last {
		if !namePattern.MatchString(context) || len(selected) > MaxSelections {
			return ErrInvalid
		}
		seen := make(map[string]bool)
		for _, b := range selected {
			a, ok := d.Accounts[b.AccountID]
			if !ok || !validID(b.ServerID) || a.ServerID != b.ServerID || b.ServerRevision == 0 || b.AccountRevision == 0 || seen[b.AccountID] {
				return ErrInvalid
			}
			seen[b.AccountID] = true
		}
	}
	return nil
}

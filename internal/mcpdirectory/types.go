// Package mcpdirectory owns private remote MCP records, not model capabilities.
package mcpdirectory

import (
	"errors"
	"sort"
)

var ErrInvalid = errors.New("invalid remote MCP directory")
var ErrMissing = errors.New("remote MCP record does not exist")
var ErrChanged = errors.New("remote MCP selection changed")

const MaxServers = 32
const MaxAccounts = 64
const MaxSelections = 16

type Server struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	Enabled  bool   `json:"enabled"`
	Revision uint64 `json:"revision"`
}
type Header struct {
	Name  string `json:"name"`
	Value []byte `json:"value"`
}
type Authentication struct {
	Kind     string `json:"kind"`
	Username string `json:"username"`
	Secret   []byte `json:"secret"`
}
type Account struct {
	ServerID string         `json:"server_id"`
	Name     string         `json:"name"`
	Enabled  bool           `json:"enabled"`
	Revision uint64         `json:"revision"`
	Auth     Authentication `json:"auth"`
	Headers  []Header       `json:"headers"`
}
type Binding struct {
	ServerID        string `json:"server_id"`
	AccountID       string `json:"account_id"`
	ServerRevision  uint64 `json:"server_revision"`
	AccountRevision uint64 `json:"account_revision"`
}
type Directory struct {
	Servers  map[string]Server    `json:"servers"`
	Accounts map[string]Account   `json:"accounts"`
	Last     map[string][]Binding `json:"last"`
}

func New() *Directory {
	return &Directory{Servers: make(map[string]Server), Accounts: make(map[string]Account), Last: make(map[string][]Binding)}
}
func (a *Account) Clear() {
	clear(a.Auth.Secret)
	a.Auth.Secret = nil
	for i := range a.Headers {
		clear(a.Headers[i].Value)
		a.Headers[i].Value = nil
	}
	a.Headers = nil
}
func (d *Directory) Clear() {
	if d == nil {
		return
	}
	for id, account := range d.Accounts {
		account.Clear()
		delete(d.Accounts, id)
	}
	clear(d.Servers)
	clear(d.Last)
}
func ownAccount(a Account) Account {
	a.Auth.Secret = append([]byte{}, a.Auth.Secret...)
	headers := make([]Header, len(a.Headers))
	for i, h := range a.Headers {
		headers[i] = Header{Name: h.Name, Value: append([]byte{}, h.Value...)}
	}
	a.Headers = headers
	return a
}

type ServerMetadata struct {
	ID, Name, URL string
	Enabled       bool
	Revision      uint64
}
type AccountMetadata struct {
	ID, ServerID, Name, Authentication, Username string
	Enabled, CredentialSet                       bool
	Revision                                     uint64
	HeaderNames                                  []string
}
type Metadata struct {
	Servers  []ServerMetadata
	Accounts []AccountMetadata
	Last     map[string][]Binding
}

func (d *Directory) Metadata() Metadata {
	if d == nil {
		return Metadata{}
	}
	result := Metadata{Last: make(map[string][]Binding)}
	for id, s := range d.Servers {
		result.Servers = append(result.Servers, ServerMetadata{id, s.Name, s.URL, s.Enabled, s.Revision})
	}
	for id, a := range d.Accounts {
		m := AccountMetadata{ID: id, ServerID: a.ServerID, Name: a.Name, Authentication: a.Auth.Kind, Username: a.Auth.Username, Enabled: a.Enabled, CredentialSet: len(a.Auth.Secret) != 0 || len(a.Headers) != 0, Revision: a.Revision}
		for _, h := range a.Headers {
			m.HeaderNames = append(m.HeaderNames, h.Name)
		}
		sort.Strings(m.HeaderNames)
		result.Accounts = append(result.Accounts, m)
	}
	for context, selected := range d.Last {
		result.Last[context] = append([]Binding{}, selected...)
	}
	sort.Slice(result.Servers, func(i, j int) bool { return result.Servers[i].Name < result.Servers[j].Name })
	sort.Slice(result.Accounts, func(i, j int) bool {
		a, b := result.Accounts[i], result.Accounts[j]
		if a.ServerID != b.ServerID {
			return a.ServerID < b.ServerID
		}
		return a.Name < b.Name
	})
	return result
}

func (metadata Metadata) MatchesBindings(bindings []Binding) bool {
	servers, accounts := make(map[string]ServerMetadata, len(metadata.Servers)), make(map[string]AccountMetadata, len(metadata.Accounts))
	for _, server := range metadata.Servers {
		servers[server.ID] = server
	}
	for _, account := range metadata.Accounts {
		accounts[account.ID] = account
	}
	for _, binding := range bindings {
		server, serverOK := servers[binding.ServerID]
		account, accountOK := accounts[binding.AccountID]
		if !serverOK || !accountOK || account.ServerID != binding.ServerID || server.Revision != binding.ServerRevision || account.Revision != binding.AccountRevision {
			return false
		}
	}
	return true
}

// CurrentBinding is metadata, not authority to connect or obtain credentials.
func (d *Directory) CurrentBinding(accountID string) (Binding, error) {
	if d == nil {
		return Binding{}, ErrMissing
	}
	account, ok := d.Accounts[accountID]
	if !ok {
		return Binding{}, ErrMissing
	}
	server, ok := d.Servers[account.ServerID]
	if !ok || !server.Enabled || !account.Enabled {
		return Binding{}, ErrMissing
	}
	return Binding{account.ServerID, accountID, server.Revision, account.Revision}, nil
}

// Remember records an explicitly confirmed list, including an empty selection.
func (d *Directory) Remember(profile string, selected []Binding) error {
	if d == nil || d.Validate() != nil || !namePattern.MatchString(profile) || len(selected) > MaxSelections {
		return ErrInvalid
	}
	if _, exists := d.Last[profile]; !exists && len(d.Last) >= 64 {
		return ErrInvalid
	}
	seen := make(map[string]bool)
	for _, binding := range selected {
		current, err := d.CurrentBinding(binding.AccountID)
		if err != nil || current != binding {
			return ErrChanged
		}
		if seen[binding.AccountID] {
			return ErrInvalid
		}
		seen[binding.AccountID] = true
	}
	d.Last[profile] = append([]Binding{}, selected...)
	return nil
}

// Suggested drops unavailable or changed records; confirmation is still required.
func (d *Directory) Suggested(profile string) []Binding {
	selected := make([]Binding, 0)
	if d == nil {
		return selected
	}
	for _, previous := range d.Last[profile] {
		current, err := d.CurrentBinding(previous.AccountID)
		if err == nil && current == previous {
			selected = append(selected, previous)
		}
	}
	return selected
}

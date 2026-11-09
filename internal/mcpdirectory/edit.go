package mcpdirectory

import (
	"crypto/rand"
	"encoding/hex"
	"math"
)

func newID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	id := hex.EncodeToString(raw[:])
	if !validID(id) {
		return "", ErrInvalid
	}
	return id, nil
}
func (d *Directory) AddServer(name, endpoint string) (string, error) {
	if d == nil || d.Validate() != nil || len(d.Servers) >= MaxServers {
		return "", ErrInvalid
	}
	id, err := newID()
	if err != nil {
		return "", err
	}
	if _, exists := d.Servers[id]; exists {
		return "", ErrInvalid
	}
	if err := d.setServer(id, Server{Name: name, URL: endpoint, Enabled: true, Revision: 1}); err != nil {
		return "", err
	}
	return id, nil
}
func (d *Directory) EditServer(id, name, endpoint string, enabled bool) error {
	if d == nil || d.Validate() != nil {
		return ErrInvalid
	}
	previous, ok := d.Servers[id]
	if !ok {
		return ErrMissing
	}
	if previous.URL != endpoint || previous.Enabled != enabled {
		if previous.Revision == math.MaxUint64 {
			return ErrInvalid
		}
		previous.Revision++
	}
	previous.Name, previous.URL, previous.Enabled = name, endpoint, enabled
	return d.setServer(id, previous)
}
func (d *Directory) setServer(id string, value Server) error {
	if !validID(id) || !namePattern.MatchString(value.Name) || !validURL(value.URL) || value.Revision == 0 {
		return ErrInvalid
	}
	for other, server := range d.Servers {
		if other != id && server.Name == value.Name {
			return ErrInvalid
		}
	}
	d.Servers[id] = value
	return nil
}
func (d *Directory) AddAccount(value Account) (string, error) {
	if d == nil || d.Validate() != nil || len(d.Accounts) >= MaxAccounts {
		return "", ErrInvalid
	}
	id, err := newID()
	if err != nil {
		return "", err
	}
	if _, exists := d.Accounts[id]; exists {
		return "", ErrInvalid
	}
	value.Revision = 1
	if err := d.setAccount(id, value); err != nil {
		return "", err
	}
	return id, nil
}

// ReplaceAccount owns supplied credentials and invalidates prior preselection.
func (d *Directory) ReplaceAccount(id string, value Account) error {
	if d == nil || d.Validate() != nil {
		return ErrInvalid
	}
	previous, ok := d.Accounts[id]
	if !ok {
		return ErrMissing
	}
	if value.ServerID != previous.ServerID || previous.Revision == math.MaxUint64 {
		return ErrInvalid
	}
	value.Revision = previous.Revision + 1
	return d.setAccount(id, value)
}
func (d *Directory) RenameAccount(id, name string) error {
	if d == nil || d.Validate() != nil {
		return ErrInvalid
	}
	previous, ok := d.Accounts[id]
	if !ok {
		return ErrMissing
	}
	previous.Name = name
	return d.setAccount(id, previous)
}
func (d *Directory) setAccount(id string, value Account) error {
	if !validID(id) || !validAccount(value) {
		return ErrInvalid
	}
	if _, ok := d.Servers[value.ServerID]; !ok {
		return ErrMissing
	}
	for other, account := range d.Accounts {
		if other != id && account.ServerID == value.ServerID && account.Name == value.Name {
			return ErrInvalid
		}
	}
	owned := ownAccount(value)
	if previous, ok := d.Accounts[id]; ok {
		previous.Clear()
	}
	d.Accounts[id] = owned
	return nil
}
func (d *Directory) RemoveAccount(id string) error {
	if d == nil || d.Validate() != nil {
		return ErrInvalid
	}
	previous, ok := d.Accounts[id]
	if !ok {
		return ErrMissing
	}
	previous.Clear()
	delete(d.Accounts, id)
	d.prune(id)
	return nil
}
func (d *Directory) RemoveServer(id string) error {
	if d == nil || d.Validate() != nil {
		return ErrInvalid
	}
	if _, ok := d.Servers[id]; !ok {
		return ErrMissing
	}
	for accountID, account := range d.Accounts {
		if account.ServerID == id {
			account.Clear()
			delete(d.Accounts, accountID)
			d.prune(accountID)
		}
	}
	delete(d.Servers, id)
	return nil
}
func (d *Directory) prune(account string) {
	for context, selected := range d.Last {
		kept := make([]Binding, 0, len(selected))
		for _, b := range selected {
			if b.AccountID != account {
				kept = append(kept, b)
			}
		}
		d.Last[context] = kept
	}
}

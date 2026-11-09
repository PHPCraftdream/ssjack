package ownermcp

import (
	"github.com/PHPCraftdream/ssjack/internal/mcpdirectory"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func Apply(v *vault.Vault, change ownerpacket.DirectoryChange) error {
	if !change.Valid() {
		return mcpdirectory.ErrInvalid
	}
	text := func(i int) string { return string(change.Fields[i]) }
	d := v.RemoteMCP
	if change.Action == "add-mcp-server" {
		if d == nil {
			d = mcpdirectory.New()
		}
		if _, err := d.AddServer(text(0), text(1)); err != nil {
			return err
		}
		v.RemoteMCP = d
		return nil
	}
	if d == nil {
		return mcpdirectory.ErrMissing
	}
	if _, exists := d.Servers[change.ServerID]; !exists {
		return mcpdirectory.ErrMissing
	}
	switch change.Action {
	case "edit-mcp-server":
		enabled, err := parseEnabled(text(2))
		if err != nil {
			return mcpdirectory.ErrInvalid
		}
		return d.EditServer(change.ServerID, text(0), text(1), enabled)
	case "remove-mcp-server":
		if text(0) != "REMOVE" {
			return mcpdirectory.ErrInvalid
		}
		return d.RemoveServer(change.ServerID)
	case "add-mcp-account":
		return applyAccount(d, change, false)
	}
	account, exists := d.Accounts[change.Account]
	if !exists || account.ServerID != change.ServerID {
		return mcpdirectory.ErrMissing
	}
	switch change.Action {
	case "edit-mcp-account":
		return applyAccount(d, change, true)
	case "rename-mcp-account":
		return d.RenameAccount(change.Account, text(0))
	case "remove-mcp-account":
		if text(0) != "REMOVE" {
			return mcpdirectory.ErrInvalid
		}
		return d.RemoveAccount(change.Account)
	case "edit-mcp-header":
		return applyHeader(d, change, account)
	}
	return mcpdirectory.ErrInvalid
}

func parseEnabled(value string) (bool, error) {
	if value != "true" && value != "false" {
		return false, mcpdirectory.ErrInvalid
	}
	return value == "true", nil
}

func applyAccount(d *mcpdirectory.Directory, c ownerpacket.DirectoryChange, editing bool) error {
	text := func(i int) string { return string(c.Fields[i]) }
	enabled, err := parseEnabled(text(1))
	if err != nil {
		return mcpdirectory.ErrInvalid
	}
	a := mcpdirectory.Account{ServerID: c.ServerID, Name: text(0), Enabled: enabled, Auth: mcpdirectory.Authentication{Kind: text(2), Username: text(3)}}
	previous := d.Accounts[c.Account]
	if editing {
		a.Headers = previous.Headers
	}
	switch text(4) {
	case "keep":
		if !editing || len(c.Fields[5]) != 0 || a.Auth.Kind != previous.Auth.Kind || a.Auth.Username != previous.Auth.Username {
			return mcpdirectory.ErrInvalid
		}
		a.Auth.Secret = previous.Auth.Secret
	case "replace":
		if len(c.Fields[5]) == 0 {
			return mcpdirectory.ErrInvalid
		}
		a.Auth.Secret = c.Fields[5]
	case "clear":
		if len(c.Fields[5]) != 0 || a.Auth.Kind != "none" || a.Auth.Username != "" {
			return mcpdirectory.ErrInvalid
		}
	default:
		return mcpdirectory.ErrInvalid
	}
	if editing {
		if a.Name != previous.Name {
			return mcpdirectory.ErrInvalid
		}
		return d.ReplaceAccount(c.Account, a)
	}
	_, err = d.AddAccount(a)
	return err
}

func applyHeader(d *mcpdirectory.Directory, c ownerpacket.DirectoryChange, a mcpdirectory.Account) error {
	name, mode := string(c.Fields[0]), string(c.Fields[1])
	var headers []mcpdirectory.Header
	found := false
	for _, h := range a.Headers {
		if h.Name == name {
			found = true
			continue
		}
		headers = append(headers, h)
	}
	switch mode {
	case "replace":
		if len(c.Fields[2]) == 0 {
			return mcpdirectory.ErrInvalid
		}
		headers = append(headers, mcpdirectory.Header{Name: name, Value: c.Fields[2]})
	case "clear":
		if !found || len(c.Fields[2]) != 0 {
			return mcpdirectory.ErrInvalid
		}
	default:
		return mcpdirectory.ErrInvalid
	}
	a.Headers = headers
	return d.ReplaceAccount(c.Account, a)
}

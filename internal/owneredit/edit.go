// Package owneredit owns the closed directory mutations shared by local and IPC owners.
package owneredit

import (
	"errors"
	"io"
	"os"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
	"github.com/PHPCraftdream/ssjack/internal/ownermcp"
	"github.com/PHPCraftdream/ssjack/internal/ownerpacket"
	"github.com/PHPCraftdream/ssjack/internal/sshproxy"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

var ErrChange = errors.New("invalid owner directory change")

type Change = ownerpacket.DirectoryChange

func Dispatch(backend interface {
	Edit(func(*vault.Vault) error) error
}, change Change) error {
	if remote, ok := backend.(interface{ ApplyDirectory(Change) error }); ok {
		return remote.ApplyDirectory(change)
	}
	return backend.Edit(func(v *vault.Vault) error { return Apply(v, change) })
}

func Apply(v *vault.Vault, f Change) error {
	if !f.Valid() {
		return ErrChange
	}
	if strings.Contains(f.Action, "-mcp-") {
		return ownermcp.Apply(v, f)
	}
	text := func(index int) string { return string(f.Fields[index]) }
	if f.Action == "edit-proxy" {
		return editProxy(v, f)
	}
	if f.Action == "edit-server" {
		return Server(v, f.ServerID, text(0), text(1))
	}
	if f.Action == "rename-server" {
		return v.RenameServer(f.ServerID, text(0))
	}
	start, account := 1, text(0)
	var target vault.Target
	if f.Action == "add-server" {
		start, account = 3, text(2)
		target.Address = text(1)
		for _, encoded := range strings.Split(text(7), "|") {
			target.HostKeys = append(target.HostKeys, strings.TrimSpace(encoded))
		}
	} else {
		server, exists := v.Servers[f.ServerID]
		if !exists {
			return ErrChange
		}
		profile, exists := server.Accounts[account]
		if f.Action == "edit-account" {
			if !exists || account != f.Account {
				return ErrChange
			}
			target = v.Targets[profile]
		} else {
			if exists {
				return ErrChange
			}
			for _, profile := range server.Accounts {
				previous := v.Targets[profile]
				target.Address, target.HostKeys = previous.Address, previous.HostKeys
				break
			}
		}
	}
	target.User, target.Usage = text(start), text(start+3)
	kind, credential := text(start+1), f.Fields[start+2]
	if kind != "key" && kind != "password" {
		return ErrChange
	}
	var imported []byte
	if len(credential) != 0 {
		if kind == "password" {
			target.Password, target.PrivateKey = credential, nil
		} else {
			var err error
			imported, err = readPrivateKey(string(credential))
			if err != nil {
				return ErrChange
			}
			defer clear(imported)
			target.PrivateKey, target.Password = imported, nil
		}
	} else if (kind == "key" && len(target.PrivateKey) == 0) || (kind == "password" && len(target.Password) == 0) {
		return ErrChange
	}
	if f.Action == "add-server" {
		_, err := v.AddServer(text(0), account, target)
		return err
	}
	return v.SetAccount(f.ServerID, account, target)
}

func editProxy(v *vault.Vault, f Change) error {
	if len(f.Fields) != 4 {
		return ErrChange
	}
	kind := string(f.Fields[0])
	if kind == "direct" {
		return v.SetServerProxy(f.ServerID, nil)
	}
	route := &sshproxy.Config{Type: kind, Address: string(f.Fields[1]), Username: string(f.Fields[2]), Password: append([]byte(nil), f.Fields[3]...)}
	defer route.Clear()
	if route.Username != "" && len(route.Password) == 0 {
		server, exists := v.Servers[f.ServerID]
		if !exists {
			return ErrChange
		}
		for _, profile := range server.Accounts {
			previous := v.Targets[profile].Proxy
			if previous == nil || previous.Type != route.Type || previous.Address != route.Address || previous.Username != route.Username {
				return ErrChange
			}
			route.Password = append([]byte(nil), previous.Password...)
			break
		}
	}
	if route.Validate() != nil || route.Type == "" {
		return ErrChange
	}
	return v.SetServerProxy(f.ServerID, route)
}

func Server(v *vault.Vault, id, address, replacement string) error {
	server, exists := v.Servers[id]
	if !exists {
		return ErrChange
	}
	var pins []string
	if replacement != "" {
		for _, pin := range strings.Split(replacement, "|") {
			pins = append(pins, strings.TrimSpace(pin))
		}
	}
	updated := make(map[string]vault.Target, len(server.Accounts))
	for _, profile := range server.Accounts {
		target := v.Targets[profile]
		target.Address = address
		if len(pins) != 0 {
			target.HostKeys = append([]string(nil), pins...)
		}
		if err := target.Validate(); err != nil {
			return ErrChange
		}
		updated[profile] = target
	}
	for profile, target := range updated {
		v.Targets[profile] = target
	}
	return nil
}

func readPrivateKey(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrChange
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > keyfile.MaxPlaintext {
		return nil, ErrChange
	}
	data, err := io.ReadAll(io.LimitReader(file, keyfile.MaxPlaintext+1))
	if err != nil || len(data) > keyfile.MaxPlaintext {
		clear(data)
		return nil, ErrChange
	}
	return data, nil
}

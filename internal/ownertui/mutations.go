package ownertui

import (
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/keyfile"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

var errForm = errors.New("invalid owner form")

func editDirectory(v *vault.Vault, f *form) error {
	text := func(index int) string { return string(f.fields[index].value) }
	if f.action == "rename-server" {
		return v.RenameServer(f.origin.server, text(0))
	}
	start, account := 1, text(0)
	var target vault.Target
	if f.action == "add-server" {
		start, account = 3, text(2)
		target.Address = text(1)
		for _, encoded := range strings.Split(text(7), "|") {
			target.HostKeys = append(target.HostKeys, strings.TrimSpace(encoded))
		}
	} else {
		server, exists := v.Servers[f.origin.server]
		if !exists {
			return errForm
		}
		profile, exists := server.Accounts[account]
		if f.action == "edit-account" {
			if !exists || account != f.origin.account {
				return errForm
			}
			target = v.Targets[profile]
		} else {
			if exists {
				return errForm
			}
			for _, profile := range server.Accounts {
				previous := v.Targets[profile]
				target.Address, target.HostKeys = previous.Address, previous.HostKeys
				break
			}
		}
	}
	target.User, target.Usage = text(start), text(start+3)
	kind, credential := text(start+1), f.fields[start+2].value
	if kind != "key" && kind != "password" {
		return errForm
	}
	var imported []byte
	if len(credential) != 0 {
		if kind == "password" {
			target.Password, target.PrivateKey = credential, nil
		} else {
			var err error
			imported, err = readPrivateKey(string(credential))
			if err != nil {
				return errForm
			}
			defer clear(imported)
			target.PrivateKey, target.Password = imported, nil
		}
	} else if (kind == "key" && len(target.PrivateKey) == 0) || (kind == "password" && len(target.Password) == 0) {
		return errForm
	}
	if f.action == "add-server" {
		_, err := v.AddServer(text(0), account, target)
		return err
	}
	return v.SetAccount(f.origin.server, account, target)
}

func readPrivateKey(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errForm
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > keyfile.MaxPlaintext {
		return nil, errForm
	}
	data, err := io.ReadAll(io.LimitReader(file, keyfile.MaxPlaintext+1))
	if err != nil || len(data) > keyfile.MaxPlaintext {
		clear(data)
		return nil, errForm
	}
	return data, nil
}

func (m *Model) submitSecret(f *form) error {
	change := vault.OwnerChange{Action: "add", Name: string(f.fields[0].value), ServerID: f.origin.server, MediaType: "text/plain"}
	if f.action != "add-secret" {
		metadata, err := m.backend.Metadata()
		if err != nil {
			return err
		}
		alias, exists := metadata.Secrets[f.origin.secret]
		if !exists || alias.ServerID != f.origin.server {
			return errForm
		}
		ref, err := appstoreplaceholder.Parse([]byte(alias.Ref))
		if err != nil {
			return errForm
		}
		object := ref.ObjectID()
		change.AliasID, change.ObjectID = f.origin.secret, hex.EncodeToString(object[:])
		change.PreviousReference = alias.Ref
		change.Action = "update"
		if f.action == "remove-secret" {
			if string(f.fields[0].value) != "REMOVE" {
				return errForm
			}
			change.Action, change.Name = "remove", alias.Name
		}
	}
	if change.Action != "remove" {
		change.Value = f.fields[1].value
	}
	return m.backend.Submit(change)
}

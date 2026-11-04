package ownercommand

import (
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/PHPCraftdream/ssjack/internal/vault"
)

var ErrArguments = errors.New("invalid owner command; use ssjack help owner (secrets and confirmations are terminal-only)")

// Parse accepts only action-specific metadata options, never arbitrary form input.
func Parse(args []string, server, account string) (Request, error) {
	if len(args) == 0 {
		return Request{}, ErrArguments
	}
	spec, ok := Lookup(args[0])
	if !ok {
		return Request{}, ErrArguments
	}
	r := Request{Action: spec.Action, Server: server, Account: account, Fields: make(map[string]string)}
	seen := make(map[string]bool)
	if server != "" {
		seen["server"] = true
	}
	if account != "" {
		seen["account"] = true
	}
	for i := 1; i < len(args); i++ {
		argument := args[i]
		if !strings.HasPrefix(argument, "--") {
			return Request{}, ErrArguments
		}
		key, value, assigned := strings.Cut(argument[2:], "=")
		if seen[key] {
			return Request{}, ErrArguments
		}
		seen[key] = true
		if !assigned {
			i++
			if i == len(args) || strings.HasPrefix(args[i], "--") {
				return Request{}, ErrArguments
			}
			value = args[i]
		}
		if len(value) > 16384 || !utf8.ValidString(value) || strings.ContainsAny(value, "\x00\r\n\x1b") {
			return Request{}, ErrArguments
		}
		switch key {
		case "server":
			r.Server = value
		case "account":
			r.Account = value
		case "scope":
			r.Scope = value
		case "secret":
			r.Secret = value
		default:
			label, exists := spec.Options[key]
			if !exists {
				return Request{}, ErrArguments
			}
			r.Fields[label] = value
		}
	}
	if err := r.validate(spec, seen); err != nil {
		return Request{}, err
	}
	if label, exists := spec.Options["account"]; exists && r.Account != "" {
		r.Fields[label] = r.Account
	}
	if seen["key-file"] {
		if kind, exists := r.Fields["Authentication"]; exists && kind != "key" {
			return Request{}, ErrArguments
		}
		r.Fields["Authentication"] = "key"
	}
	return r, nil
}

func (r Request) validate(spec Spec, seen map[string]bool) error {
	for key, name := range map[string]string{"server": r.Server, "account": r.Account, "secret": r.Secret} {
		if (seen[key] || name != "") && vault.ValidateName(name) != nil {
			return ErrArguments
		}
	}
	needsServer := spec.Scope == "server" || spec.Scope == "account"
	if spec.Scope == "secrets" || spec.Scope == "secret" {
		if r.Scope != "global" && r.Scope != "server" {
			return ErrArguments
		}
		needsServer = r.Scope == "server"
	} else if spec.Scope == "export" {
		if r.Scope == "" {
			r.Scope = "all"
		}
		if r.Scope != "all" && r.Scope != "global" && r.Scope != "server" && r.Scope != "account" {
			return ErrArguments
		}
		needsServer = r.Scope == "server" || r.Scope == "account"
	} else if seen["scope"] {
		return ErrArguments
	}
	if needsServer != (r.Server != "") {
		return ErrArguments
	}
	needsAccount := spec.Scope == "account" || (spec.Scope == "export" && r.Scope == "account")
	allowsAccount := needsAccount || spec.Action == "add-account" || spec.Action == "add-server"
	if (needsAccount && r.Account == "") || (!allowsAccount && r.Account != "") {
		return ErrArguments
	}
	if (spec.Scope == "secret") != (r.Secret != "") {
		return ErrArguments
	}
	if kind, ok := r.Fields["Authentication"]; ok && kind != "key" && kind != "password" {
		return ErrArguments
	}
	if format, ok := r.Fields["Format"]; ok && format != "encrypted" && format != "plaintext" {
		return ErrArguments
	}
	if kind, ok := r.Fields["Proxy type"]; ok && kind != "direct" && kind != "socks5" && kind != "http" {
		return ErrArguments
	}
	if usage, ok := r.Fields["Usage"]; ok && usage != "both" && usage != "human" && usage != "agent" {
		return ErrArguments
	}
	if action, ok := r.Fields["Action"]; ok {
		switch action {
		case "retry-db", "reconcile", "resume-draft", "cancel-draft", "resume-import", "abort-import":
		default:
			return ErrArguments
		}
	}
	return nil
}

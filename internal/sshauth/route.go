package sshauth

import (
	"context"
	"errors"
	"net"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/sshproxy"
)

type routedAuth struct {
	ssh.AuthMethod
	proxy *sshproxy.Config
}

// WithProxy binds an owned route to the selected credential, not a global map.
func WithProxy(method ssh.AuthMethod, route *sshproxy.Config) (ssh.AuthMethod, error) {
	if _, nested := method.(*routedAuth); nested {
		return nil, errors.New("SSH proxy is already bound")
	}
	if _, _, err := connectionMethod(&ssh.ClientConfig{Auth: []ssh.AuthMethod{method}}); err != nil {
		return nil, err
	}
	if route == nil {
		return method, nil
	}
	if route.Type == "" || route.Validate() != nil {
		return nil, sshproxy.ErrConfig
	}
	return &routedAuth{AuthMethod: method, proxy: sshproxy.Clone(route)}, nil
}

func connectionMethod(config *ssh.ClientConfig) (ssh.AuthMethod, *sshproxy.Config, error) {
	if config == nil || len(config.Auth) != 1 {
		return nil, nil, errors.New("SSH requires exactly one selected identity")
	}
	method := config.Auth[0]
	var route *sshproxy.Config
	if selected, ok := method.(*routedAuth); ok {
		if selected == nil || selected.proxy == nil || selected.proxy.Type == "" || selected.proxy.Validate() != nil {
			return nil, nil, sshproxy.ErrConfig
		}
		route, method = selected.proxy, selected.AuthMethod
	}
	switch selected := method.(type) {
	case *publicKeyAuth:
		if selected != nil && selected.signer != nil {
			return method, route, nil
		}
	case *passwordAuth:
		if selected != nil && selected.password != "" {
			return method, route, nil
		}
	}
	return nil, nil, errors.New("SSH configuration lacks an identifiable selected identity")
}

// DialContext keeps routing attached to credentials across every existing caller.
func DialContext(ctx context.Context, address string, config *ssh.ClientConfig) (net.Conn, error) {
	_, route, err := connectionMethod(config)
	if err != nil {
		return nil, err
	}
	return sshproxy.DialContext(ctx, address, route)
}

package sshauth

import (
	"errors"
	"sync/atomic"

	"golang.org/x/crypto/ssh"
)

type passwordAuth struct {
	ssh.AuthMethod
	password string
}

// Password owns the selected credential independently of vault buffer cleanup.
func Password(value []byte) ssh.AuthMethod {
	password := string(value)
	return &passwordAuth{AuthMethod: ssh.Password(password), password: password}
}

func passwordForConnection(config *ssh.ClientConfig, method *passwordAuth) (*ssh.ClientConfig, func() bool, error) {
	if method == nil || method.password == "" {
		return nil, nil, errors.New("SSH configuration lacks selected-password authentication")
	}
	var offered atomic.Bool
	copy := *config
	copy.Auth = []ssh.AuthMethod{ssh.PasswordCallback(func() (string, error) {
		offered.Store(true)
		return method.password, nil
	})}
	return &copy, offered.Load, nil
}

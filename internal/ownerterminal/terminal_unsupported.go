//go:build !windows && !linux && !darwin

package ownerterminal

import "context"

func start(context.Context, Command) (*Terminal, error) { return nil, ErrTerminal }

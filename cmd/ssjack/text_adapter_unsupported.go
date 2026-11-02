//go:build !linux || !amd64

package main

import (
	"context"
	"errors"
)

func runTextAdapterCommand(_ context.Context, _, _ string, args []string) (int, error) {
	if len(args) > 0 && (args[0] == "register" || args[0] == "revoke") {
		return 1, errors.New("text-adapter registration and revocation are unavailable on this platform")
	}
	return 1, errors.New("text-adapter is unavailable on this platform")
}

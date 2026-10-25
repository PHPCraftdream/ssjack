package broker

import (
	"context"
	"encoding/hex"
	"errors"

	"storagehost/internal/wire"
)

const (
	EnvToken    = "SSJACK_ENV_TOKEN"
	EnvSession  = "SSJACK_SESSION"
	EnvEndpoint = "SSJACK_ENDPOINT"
	EnvPin      = "SSJACK_CERTIFICATE_SHA256"
	// EnvFile is scrubbed for compatibility, never read or written.
	EnvFile = "SSJACK_BOOTSTRAP_FILE"
)

// Bootstrap exists only in memory and the launched harness environment.
type Bootstrap struct {
	Session  string
	Endpoint string
	Pin      string
	Token    string
}

func validToken(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	clear(decoded)
	return err == nil
}

func ConnectBootstrap(ctx context.Context, bootstrap Bootstrap) (*Client, error) {
	if !validToken(bootstrap.Session) || !validToken(bootstrap.Token) {
		return nil, errors.New("invalid memory-only bootstrap parameters")
	}
	return Connect(ctx, bootstrap.Endpoint, bootstrap.Pin, wire.Auth{
		Version: 2, Session: bootstrap.Session, Token: bootstrap.Token,
	})
}

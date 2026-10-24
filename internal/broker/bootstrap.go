package broker

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/ktav-lang/golang/pure"

	"storagehost/internal/wire"
)

const (
	EnvToken = "SSJACK_ENV_TOKEN"
	EnvFile  = "SSJACK_BOOTSTRAP_FILE"
)

type Bootstrap struct {
	Version   int    `json:"version"`
	Session   string `json:"session"`
	Endpoint  string `json:"endpoint"`
	Pin       string `json:"certificate_sha256"`
	DiskToken string `json:"disk_token"`
}

func WriteBootstrap(parent string, bootstrap Bootstrap) (string, func(), error) {
	if err := os.MkdirAll(parent, 0700); err != nil {
		return "", nil, err
	}
	dir, err := os.MkdirTemp(parent, "session-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { os.RemoveAll(dir) }
	path := filepath.Join(dir, "bootstrap.ktav")
	data, err := pure.EmitCanonical(bootstrap)
	if err != nil {
		cleanup()
		return "", nil, errors.New("failed to encode Ktav bootstrap data")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		cleanup()
		return "", nil, err
	}
	_, writeErr := io.WriteString(file, data)
	closeErr := file.Close()
	if writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		cleanup()
		return "", nil, writeErr
	}
	return path, cleanup, nil
}

func ConnectFile(ctx context.Context, path, envToken string) (*Client, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 16*1024 {
		return nil, errors.New("bootstrap path is missing or invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("failed to open bootstrap file")
	}
	data, err := io.ReadAll(io.LimitReader(file, 16*1024+1))
	file.Close()
	if err != nil || len(data) > 16*1024 {
		return nil, errors.New("failed to read bootstrap file")
	}
	var bootstrap Bootstrap
	if err := pure.LoadsInto(string(data), &bootstrap); err != nil || bootstrap.Version != 1 || len(bootstrap.Session) != 64 || len(bootstrap.DiskToken) != 64 || len(envToken) != 64 {
		return nil, errors.New("invalid Ktav bootstrap data")
	}
	client, err := Connect(ctx, bootstrap.Endpoint, bootstrap.Pin, wire.Auth{
		Session: bootstrap.Session, EnvToken: envToken, DiskToken: bootstrap.DiskToken,
	})
	if err != nil {
		return nil, err
	}
	if err := os.Remove(path); err != nil {
		client.Close()
		return nil, errors.New("failed to remove consumed bootstrap file; session closed")
	}
	return client, nil
}

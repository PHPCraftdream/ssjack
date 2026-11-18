package credential

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/startup"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/terminal"
	"github.com/PHPCraftdream/ssjack/internal/keyfile"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func ReadVaultCredential(ctx context.Context, path, name, usage string) (*ssh.ClientConfig, string, string, error) {
	v, config, address, selected, err := OpenVaultCredential(ctx, path, name, usage)
	if err != nil {
		return nil, "", "", err
	}
	v.Close()
	return config, address, selected, nil
}

func OpenVaultCredential(ctx context.Context, path, name, usage string) (_ *vault.Vault, _ *ssh.ClientConfig, _ string, _ string, err error) {
	if name != "" {
		if err := ValidateCredentialSelection(name); err != nil {
			return nil, nil, "", "", err
		}
	}
	secret, err := startup.ReadVaultPassword(ctx, "Vault secret: ", terminal.Secret)
	if err != nil {
		return nil, nil, "", "", err
	}
	v, err := vault.Load(path, secret)
	clear(secret)
	if err != nil {
		return nil, nil, "", "", err
	}
	defer func() {
		if err != nil {
			v.Close()
		}
	}()
	name, err = ChooseCredential(v, name)
	if err != nil {
		return nil, nil, "", "", err
	}
	target := v.Targets[name]
	if usage != "" {
		if err := target.RequireUsage(usage); err != nil {
			return nil, nil, "", "", err
		}
	}
	config, err := target.ClientConfig()
	if err != nil {
		return nil, nil, "", "", err
	}
	fmt.Fprintln(os.Stderr, "Using credentials:", name)
	return v, config, target.Address, name, nil
}

func CredentialCipherDigest(path string) ([sha256.Size]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > keyfile.MaxSize {
		return [sha256.Size]byte{}, errors.New("vault must be a regular encrypted file within the size limit")
	}
	file, err := os.Open(path)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Size() > keyfile.MaxSize {
		return [sha256.Size]byte{}, errors.New("vault must be a regular encrypted file within the size limit")
	}
	hash := sha256.New()
	encodedSize, err := io.Copy(hash, io.LimitReader(file, int64(keyfile.MaxSize)+1))
	if err != nil || encodedSize > int64(keyfile.MaxSize) {
		return [sha256.Size]byte{}, errors.New("failed to read encrypted vault")
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

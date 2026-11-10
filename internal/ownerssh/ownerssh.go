package ownerssh

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"

	"github.com/PHPCraftdream/ssjack/internal/keyfile"
	"github.com/PHPCraftdream/ssjack/internal/outputguard"
	"github.com/PHPCraftdream/ssjack/internal/ownerdb"
	"github.com/PHPCraftdream/ssjack/internal/sshlive"
	"golang.org/x/crypto/ssh"
)

var ErrUnavailable = errors.New("SSH live capability unavailable")

func healthy(snapshot ownerdb.Snapshot) bool {
	status := snapshot.Status
	database := status.Database
	return database.Err == nil && !database.Pending && database.Revision == database.SavedRevision &&
		!status.Busy && !status.Pending && status.Err == nil && snapshot.CipherDigest != ([32]byte{})
}

func diskDigest(path string) ([sha256.Size]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > keyfile.MaxSize {
		return [sha256.Size]byte{}, ErrUnavailable
	}
	file, err := os.Open(path)
	if err != nil {
		return [sha256.Size]byte{}, ErrUnavailable
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Size() != info.Size() || !os.SameFile(info, opened) {
		return [sha256.Size]byte{}, ErrUnavailable
	}
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(file, int64(keyfile.MaxSize)+1))
	if err != nil || size != opened.Size() || size > int64(keyfile.MaxSize) {
		return [sha256.Size]byte{}, ErrUnavailable
	}
	final, err := file.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !os.SameFile(opened, final) || !os.SameFile(opened, pathInfo) || final.Size() != size {
		return [sha256.Size]byte{}, ErrUnavailable
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

type ownerSource interface {
	Snapshot() (ownerdb.Snapshot, error)
	OutputGuard(context.Context) (*outputguard.Snapshot, error)
	AgentSSHAt(uint64, [32]byte, string) (*ssh.ClientConfig, string, string, error)
}

func openMaterial(ctx context.Context, path, profile string, owner ownerSource) (sshlive.Material, error) {
	if ctx == nil || ctx.Err() != nil || owner == nil || path == "" || profile == "" {
		return sshlive.Material{}, ErrUnavailable
	}
	before, err := owner.Snapshot()
	if err != nil || !healthy(before) {
		return sshlive.Material{}, ErrUnavailable
	}
	digest, err := diskDigest(path)
	if err != nil || digest != before.CipherDigest {
		return sshlive.Material{}, ErrUnavailable
	}
	guard, err := owner.OutputGuard(ctx)
	if err != nil || guard == nil {
		return sshlive.Material{}, ErrUnavailable
	}
	config, address, scope, err := owner.AgentSSHAt(before.Status.Database.Revision, before.CipherDigest, profile)
	if err != nil || config == nil || address == "" || scope == "" {
		return sshlive.Material{}, ErrUnavailable
	}
	after, err := owner.Snapshot()
	if err != nil || !healthy(after) || after.Status.Database.Revision != before.Status.Database.Revision || after.CipherDigest != before.CipherDigest {
		return sshlive.Material{}, ErrUnavailable
	}
	finalDigest, err := diskDigest(path)
	if err != nil || finalDigest != before.CipherDigest || ctx.Err() != nil {
		return sshlive.Material{}, ErrUnavailable
	}
	return sshlive.Material{Profile: profile, Scope: scope, Revision: before.Status.Database.Revision, Config: config, Address: address, Guard: guard}, nil
}

func Open(ctx context.Context, path, profile string, owner *ownerdb.Manager) (*sshlive.Runtime, error) {
	if owner == nil {
		return nil, ErrUnavailable
	}
	source := func(sourceCtx context.Context) (sshlive.Material, error) {
		return openMaterial(sourceCtx, path, profile, owner)
	}
	runtime, err := sshlive.New(ctx, profile, source)
	if err != nil {
		return nil, ErrUnavailable
	}
	return runtime, nil
}

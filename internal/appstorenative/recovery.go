package appstorenative

import (
	"context"
	"encoding/hex"
	"io"
	"os"

	"github.com/PHPCraftdream/ssjack/internal/ownerfs"
)

func (t *Transaction) Retain(ctx context.Context, snapshot, txn [16]byte, source *os.File, expected [32]byte, limit uint64) error {
	release, err := t.mutation()
	if err != nil {
		return err
	}
	defer release()
	if snapshot == ([16]byte{}) || txn == ([16]byte{}) || expected == ([32]byte{}) || limit > 1<<42 {
		return ownerfs.ErrInvalid
	}
	digest, err := Hash(ctx, source, limit)
	if err != nil {
		return err
	}
	if digest != expected {
		return ownerfs.ErrChanged
	}
	before, err := Stat(source, false)
	if err != nil {
		return err
	}
	if uint64(before.Size) > limit {
		return ownerfs.ErrInvalid
	}
	root, err := t.directory("recovery")
	if err != nil {
		return err
	}
	name := hex.EncodeToString(snapshot[:]) + "-" + hex.EncodeToString(txn[:]) + ".bin"
	target, err := root.Write(name, true)
	if err != nil {
		return err
	}
	defer target.Close()
	buffer := make([]byte, 65536)
	remaining := before.Size
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		count := int64(len(buffer))
		if count > remaining {
			count = remaining
		}
		if _, err := io.ReadFull(source, buffer[:count]); err != nil {
			return ownerfs.ErrChanged
		}
		if err := writeExact(target, buffer[:count]); err != nil {
			return err
		}
		remaining -= count
	}
	after, err := Stat(source, false)
	if err != nil || before != after {
		return ownerfs.ErrChanged
	}
	if target.Sync() != nil || target.Close() != nil || root.Flush(name) != nil {
		return ownerfs.ErrUncertain
	}
	copyFile, err := t.OpenNamed("recovery", name)
	if err != nil {
		return err
	}
	actual, hashErr := Hash(ctx, copyFile, limit)
	closeErr := copyFile.Close()
	if hashErr != nil {
		return hashErr
	}
	if closeErr != nil {
		return ownerfs.ErrUnavailable
	}
	if actual != expected {
		return ownerfs.ErrChanged
	}
	return nil
}

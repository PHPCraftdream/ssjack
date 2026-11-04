package appstorenative

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"

	"github.com/PHPCraftdream/ssjack/internal/ownerfs"
)

func idName(id [16]byte) string { return hex.EncodeToString(id[:]) + ".bin" }
func canonical(kind, name string) bool {
	valid := func(text string) bool {
		if len(text) != 32 {
			return false
		}
		raw, err := hex.DecodeString(text)
		return err == nil && hex.EncodeToString(raw) == text && string(raw) != string(make([]byte, 16))
	}
	switch kind {
	case "snapshots", "candidates", "intents", "quarantine":
		return len(name) == 36 && name[32:] == ".bin" && valid(name[:32])
	case "recovery":
		return len(name) == 69 && name[32] == '-' && name[65:] == ".bin" && valid(name[:32]) && valid(name[33:65])
	}
	return false
}
func (t *Transaction) OpenNamed(kind, name string) (*os.File, error) {
	if !canonical(kind, name) {
		return nil, ownerfs.ErrInvalid
	}
	root, err := t.directory(kind)
	if err != nil {
		return nil, err
	}
	return root.Read(name)
}
func (t *Transaction) CreateCandidate(id [16]byte) (*os.File, error) {
	if id == ([16]byte{}) {
		return nil, ownerfs.ErrInvalid
	}
	root, err := t.directory("candidates")
	if err != nil {
		return nil, err
	}
	return root.Write(idName(id), true)
}
func (t *Transaction) SyncCandidate(id [16]byte) error {
	if id == ([16]byte{}) {
		return ownerfs.ErrInvalid
	}
	root, err := t.directory("candidates")
	if err != nil {
		return err
	}
	return syncNamed(root, idName(id))
}
func syncNamed(root *ownerfs.Root, name string) error {
	file, err := root.Write(name, false)
	if err != nil {
		return err
	}
	before, err := Stat(file, false)
	if err != nil {
		file.Close()
		return err
	}
	if file.Sync() != nil || root.Flush(name) != nil {
		file.Close()
		return ownerfs.ErrUncertain
	}
	after, statErr := Stat(file, false)
	closeErr := file.Close()
	if statErr != nil || before != after {
		return ownerfs.ErrChanged
	}
	if closeErr != nil {
		return ownerfs.ErrUnavailable
	}
	check, err := root.Read(name)
	if err != nil {
		return ownerfs.ErrChanged
	}
	named, statErr := Stat(check, false)
	closeErr = check.Close()
	if statErr != nil || named != after {
		return ownerfs.ErrChanged
	}
	if closeErr != nil {
		return ownerfs.ErrUnavailable
	}
	return nil
}
func (t *Transaction) Entries(kind string, visit func(string) error) error {
	if visit == nil {
		return ownerfs.ErrInvalid
	}
	root, err := t.directory(kind)
	if err != nil {
		return err
	}
	return root.Entries(func(name string) error {
		if !canonical(kind, name) {
			return ownerfs.ErrInvalid
		}
		file, err := t.OpenNamed(kind, name)
		if err != nil {
			return err
		}
		if file.Close() != nil {
			return ownerfs.ErrUnavailable
		}
		return visit(name)
	})
}
func Hash(ctx context.Context, file *os.File, limit uint64) ([32]byte, error) {
	var zero [32]byte
	if ctx == nil {
		return zero, ownerfs.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	before, err := Stat(file, false)
	if err != nil {
		return zero, err
	}
	if limit > 1<<42 || uint64(before.Size) > limit {
		return zero, ownerfs.ErrInvalid
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return zero, ownerfs.ErrUnavailable
	}
	hash := sha256.New()
	reader := io.LimitReader(file, before.Size+1)
	buffer := make([]byte, 65536)
	var count int64
	for {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		n, err := reader.Read(buffer)
		count += int64(n)
		if count > before.Size {
			return zero, ownerfs.ErrChanged
		}
		if n > 0 {
			hash.Write(buffer[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return zero, ownerfs.ErrUnavailable
		}
	}
	after, err := Stat(file, false)
	if err != nil || after != before || count != before.Size {
		return zero, ownerfs.ErrChanged
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return zero, ownerfs.ErrUnavailable
	}
	copy(zero[:], hash.Sum(nil))
	return zero, nil
}
func writeExact(file *os.File, data []byte) error {
	for len(data) > 0 {
		n, err := file.Write(data)
		if err != nil || n == 0 {
			return ownerfs.ErrUncertain
		}
		data = data[n:]
	}
	return nil
}

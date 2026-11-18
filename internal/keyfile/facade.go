package keyfile

import (
	core "github.com/PHPCraftdream/ssjack/internal/keyfile/internal/core"
)

const (
	Magic        = core.Magic
	MaxSize      = core.MaxSize
	MaxPlaintext = core.MaxPlaintext
	Layers       = core.Layers
	MemoryKiB    = core.MemoryKiB
)

type Unlocked = core.Unlocked

func IsContainer(data []byte) bool { return core.IsContainer(data) }

func Format(encoded []byte) (int, error) { return core.Format(encoded) }

func Generate(password []byte) ([]byte, []byte, error) { return core.Generate(password) }

func GenerateRecovery(password []byte) ([]byte, []byte, []byte, error) {
	return core.GenerateRecovery(password)
}

func Seal(plaintext, password []byte) ([]byte, error) { return core.Seal(plaintext, password) }

func SealVersion(plaintext, password []byte, version int) ([]byte, error) {
	return core.SealVersion(plaintext, password, version)
}

func Open(encoded, password []byte) ([]byte, error) { return core.Open(encoded, password) }

func NewUnlocked(password []byte, version int) (*Unlocked, error) {
	return core.NewUnlocked(password, version)
}

func Unlock(encoded, password []byte) ([]byte, *Unlocked, error) {
	return core.Unlock(encoded, password)
}

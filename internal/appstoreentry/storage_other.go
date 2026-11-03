//go:build !linux

package appstoreentry

import (
	"errors"
	"os"
)

var ErrUnsupported = errors.New("protected installation storage requires Linux")

type Store struct{}

func Supported() bool                            { return false }
func Open(string) (*Store, error)                { return nil, ErrUnsupported }
func (*Store) Close() error                      { return ErrUnsupported }
func (*Store) Identity() (uint64, uint64, error) { return 0, 0, ErrUnsupported }
func (*Store) Root() (*os.File, error)           { return nil, ErrUnsupported }
func (*Store) RequireUninstalled() error         { return ErrUnsupported }
func (*Store) Install([]byte) error              { return ErrUnsupported }
func (*Store) Load() ([]byte, [32]byte, error)   { return nil, [32]byte{}, ErrUnsupported }
func (*Store) VerifyUnchanged([32]byte) error    { return ErrUnsupported }

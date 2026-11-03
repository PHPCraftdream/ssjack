//go:build !linux

package appstoreanchorledger

import "os"

func openBackend(*os.File, [16]byte, int) (*Backend, error) { return nil, ErrUnsupported }
func checkFiles(*backendState, int64) error                 { return ErrUnsupported }

//go:build !linux

package appstorefile

import (
	"context"
	"encoding/hex"
	"os"
	"sync"
)

type directoryState struct{ store [16]byte }
type transactionState struct {
	mu sync.Mutex
}

func directoryIdentity(*Directory) (uint64, uint64, error)         { return 0, 0, ErrUnsupported }
func begin(*Transaction) (func(), error)                           { return nil, ErrUnsupported }
func open(*os.File, [16]byte) (*Directory, error)                  { return nil, ErrUnsupported }
func lock(*Directory) (*Transaction, error)                        { return nil, ErrUnsupported }
func closeDirectory(*Directory) error                              { return ErrUnsupported }
func end(*Transaction) error                                       { return ErrUnsupported }
func live(*Transaction) (*directoryState, error)                   { return nil, ErrUnsupported }
func journal(*Transaction) (*os.File, error)                       { return nil, ErrUnsupported }
func appendJournal(*Transaction, [40]byte, uint64) error           { return ErrUnsupported }
func createCandidate(*Transaction, [16]byte) (*os.File, error)     { return nil, ErrUnsupported }
func openNamed(*Transaction, string, string) (*os.File, error)     { return nil, ErrUnsupported }
func syncJournal(*Transaction) error                               { return ErrUnsupported }
func quarantine(*Transaction, [16]byte) error                      { return ErrUnsupported }
func syncCandidate(*Transaction, [16]byte) error                   { return ErrUnsupported }
func createIntent(*Transaction, [16]byte, [312]byte) error         { return ErrUnsupported }
func loadIntent(*Transaction, [16]byte) ([312]byte, error)         { return [312]byte{}, ErrUnsupported }
func entries(*Transaction, string, func(string) error) error       { return ErrUnsupported }
func publish(*Transaction, [16]byte) error                         { return ErrUnsupported }
func pointer(*Transaction, [64]byte) error                         { return ErrUnsupported }
func readPointer(*Transaction) ([64]byte, error)                   { return [64]byte{}, ErrUnsupported }
func statFile(*os.File) (Revision, error)                          { return Revision{}, ErrUnsupported }
func hashFile(context.Context, *os.File, uint64) ([32]byte, error) { return [32]byte{}, ErrUnsupported }
func retain(*Transaction, context.Context, [16]byte, [16]byte, *os.File, [32]byte, uint64) error {
	return ErrUnsupported
}
func temporary(*Transaction) (*os.File, error) { return nil, ErrUnsupported }
func statTemporary(*os.File) (Revision, error) { return Revision{}, ErrUnsupported }
func fmtHex(b []byte) string                   { return hex.EncodeToString(b) }

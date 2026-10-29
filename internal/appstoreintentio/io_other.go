//go:build !linux

package appstoreintentio

import (
	"os"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorrequest"
)

func newDirectory(*os.File, [16]byte) (*Directory, error)                  { return nil, ErrUnsupported }
func lockDirectory(*directoryState) error                                  { return ErrUnsupported }
func unlockDirectory(*directoryState)                                      {}
func closeDirectory(*directoryState) error                                 { return ErrUnsupported }
func create(*directoryState, [appstoreanchorrequest.IntentSize]byte) error { return ErrUnsupported }
func readRaw(*directoryState, [16]byte) ([appstoreanchorrequest.IntentSize]byte, error) {
	return [appstoreanchorrequest.IntentSize]byte{}, ErrUnsupported
}

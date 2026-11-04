//go:build linux || darwin

package ownerfscheck

import (
	"errors"
	"os"
)

func inaccessible(path string) error {
	file, err := os.Open(path)
	if file != nil {
		file.Close()
		return errors.New("anonymous spool is reachable by an ambient file path")
	}
	if !os.IsNotExist(err) {
		return errors.New("anonymous spool lookup did not prove pathname absence")
	}
	return nil
}

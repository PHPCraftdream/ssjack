package appstorenative

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"

	"github.com/PHPCraftdream/ssjack/internal/ownerfs"
)

func (t *Transaction) Publish(id [16]byte) error {
	release, err := t.mutation()
	if err != nil {
		return err
	}
	defer release()
	if id == ([16]byte{}) {
		return ownerfs.ErrInvalid
	}
	source, err := t.directory("candidates")
	if err != nil {
		return err
	}
	target, err := t.directory("snapshots")
	if err != nil {
		return err
	}
	return source.Rename(idName(id), target, idName(id), false)
}
func (t *Transaction) Quarantine(id [16]byte) error {
	release, err := t.mutation()
	if err != nil {
		return err
	}
	defer release()
	if id == ([16]byte{}) {
		return ownerfs.ErrInvalid
	}
	source, err := t.directory("candidates")
	if err != nil {
		return err
	}
	target, err := t.directory("quarantine")
	if err != nil {
		return err
	}
	err = source.Rename(idName(id), target, idName(id), false)
	if !errors.Is(err, ownerfs.ErrMissing) {
		return err
	}
	return syncNamed(target, idName(id))
}
func readExact(root *ownerfs.Root, name string, output []byte) (Revision, error) {
	file, err := root.Read(name)
	if err != nil {
		return Revision{}, err
	}
	before, err := Stat(file, false)
	if err != nil || before.Size != int64(len(output)) {
		file.Close()
		return Revision{}, ownerfs.ErrInvalid
	}
	_, readErr := io.ReadFull(file, output)
	after, statErr := Stat(file, false)
	closeErr := file.Close()
	if readErr != nil || statErr != nil || before != after {
		return Revision{}, ownerfs.ErrChanged
	}
	if closeErr != nil {
		return Revision{}, ownerfs.ErrUnavailable
	}
	check, err := root.Read(name)
	if err != nil {
		return Revision{}, ownerfs.ErrChanged
	}
	named, statErr := Stat(check, false)
	closeErr = check.Close()
	if statErr != nil || named != after {
		return Revision{}, ownerfs.ErrChanged
	}
	if closeErr != nil {
		return Revision{}, ownerfs.ErrUnavailable
	}
	return after, nil
}
func writeRecord(root *ownerfs.Root, name string, data []byte) error {
	file, err := root.Write(name, true)
	if err != nil {
		return err
	}
	writeErr := writeExact(file, data)
	syncErr := file.Sync()
	before, statErr := Stat(file, false)
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || statErr != nil || closeErr != nil || root.Flush(name) != nil {
		return ownerfs.ErrUncertain
	}
	actual := make([]byte, len(data))
	after, err := readExact(root, name, actual)
	if err != nil || before.Dev != after.Dev || before.Ino != after.Ino || string(actual) != string(data) {
		return ownerfs.ErrUncertain
	}
	return nil
}
func (t *Transaction) Pointer(tuple [64]byte) error {
	release, err := t.mutation()
	if err != nil {
		return err
	}
	defer release()
	d, err := t.live()
	if err != nil {
		return err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return ownerfs.ErrUnavailable
	}
	name := hex.EncodeToString(random[:]) + ".ptr"
	if err := writeRecord(d.root, name, tuple[:]); err != nil {
		return err
	}
	if err := d.root.Rename(name, d.root, "pointer.bin", true); err != nil {
		return ownerfs.ErrUncertain
	}
	actual, err := t.ReadPointer()
	if err != nil || actual != tuple {
		return ownerfs.ErrUncertain
	}
	return nil
}
func (t *Transaction) ReadPointer() ([64]byte, error) {
	var tuple [64]byte
	d, err := t.live()
	if err != nil {
		return tuple, err
	}
	_, err = readExact(d.root, "pointer.bin", tuple[:])
	if err != nil {
		return [64]byte{}, err
	}
	return tuple, nil
}
func validIntent(txn [16]byte, raw [312]byte) bool {
	return txn != ([16]byte{}) && string(raw[:8]) == "SSAPCMT1" && string(raw[8:24]) == string(txn[:])
}
func (t *Transaction) CreateIntent(txn [16]byte, raw [312]byte) error {
	release, err := t.mutation()
	if err != nil {
		return err
	}
	defer release()
	if !validIntent(txn, raw) {
		return ownerfs.ErrInvalid
	}
	root, err := t.directory("intents")
	if err != nil {
		return err
	}
	return writeRecord(root, idName(txn), raw[:])
}
func (t *Transaction) LoadIntent(txn [16]byte) ([312]byte, error) {
	var raw [312]byte
	if txn == ([16]byte{}) {
		return raw, ownerfs.ErrInvalid
	}
	root, err := t.directory("intents")
	if err != nil {
		return raw, err
	}
	if _, err := readExact(root, idName(txn), raw[:]); err != nil {
		return [312]byte{}, err
	}
	if !validIntent(txn, raw) {
		return [312]byte{}, ownerfs.ErrInvalid
	}
	if err := syncNamed(root, idName(txn)); err != nil {
		return [312]byte{}, err
	}
	return raw, nil
}

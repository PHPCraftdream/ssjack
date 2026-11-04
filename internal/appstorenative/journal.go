package appstorenative

import (
	"encoding/binary"
	"errors"
	"os"

	"github.com/PHPCraftdream/ssjack/internal/ownerfs"
)

func (t *Transaction) Journal() (*os.File, error) {
	d, err := t.live()
	if err != nil {
		return nil, err
	}
	file, err := d.root.Read("journal.bin")
	if errors.Is(err, ownerfs.ErrMissing) {
		created, createErr := d.root.Write("journal.bin", true)
		if createErr != nil {
			return nil, createErr
		}
		before, statErr := Stat(created, false)
		syncErr := created.Sync()
		closeErr := created.Close()
		if statErr != nil || syncErr != nil || closeErr != nil || d.root.Flush("journal.bin") != nil {
			return nil, ownerfs.ErrUncertain
		}
		file, err = d.root.Read("journal.bin")
		if err != nil {
			return nil, ownerfs.ErrUncertain
		}
		after, statErr := Stat(file, false)
		if statErr != nil || before != after {
			file.Close()
			return nil, ownerfs.ErrChanged
		}
	}
	if err != nil {
		return nil, err
	}
	metadata, err := Stat(file, false)
	if err != nil || metadata.Size > 40*(1<<20) || metadata.Size%40 != 0 {
		file.Close()
		return nil, ownerfs.ErrInvalid
	}
	return file, nil
}
func (t *Transaction) AppendJournal(entry [40]byte, count uint64) error {
	var zero [16]byte
	if count >= 1<<20 || binary.BigEndian.Uint64(entry[:8]) != count || string(entry[8:24]) == string(zero[:]) || string(entry[24:]) == string(zero[:]) {
		return ownerfs.ErrInvalid
	}
	file, err := t.Journal()
	if err != nil {
		return err
	}
	defer file.Close()
	before, err := Stat(file, false)
	if err != nil {
		return err
	}
	if uint64(before.Size) != count*40 {
		return ownerfs.ErrChanged
	}
	d, err := t.live()
	if err != nil {
		return err
	}
	writer, err := d.root.Write("journal.bin", false)
	if err != nil {
		return err
	}
	writable, err := Stat(writer, false)
	if err != nil || writable != before {
		writer.Close()
		return ownerfs.ErrChanged
	}
	n, writeErr := writer.WriteAt(entry[:], before.Size)
	syncErr := writer.Sync()
	after, statErr := Stat(writer, false)
	closeErr := writer.Close()
	if writeErr != nil || n != len(entry) || syncErr != nil || statErr != nil || closeErr != nil || after.Dev != before.Dev || after.Ino != before.Ino || after.Size != before.Size+40 || d.root.Flush("journal.bin") != nil {
		return ownerfs.ErrUncertain
	}
	var actual [40]byte
	if n, err := file.ReadAt(actual[:], before.Size); err != nil || n != len(actual) || actual != entry {
		return ownerfs.ErrUncertain
	}
	check, err := d.root.Read("journal.bin")
	if err != nil {
		return ownerfs.ErrUncertain
	}
	current, err := Stat(check, false)
	closeErr = check.Close()
	if err != nil || current != after || closeErr != nil {
		return ownerfs.ErrUncertain
	}
	return nil
}
func (t *Transaction) SyncJournal() error {
	file, err := t.Journal()
	if err != nil {
		return err
	}
	if file.Close() != nil {
		return ownerfs.ErrUnavailable
	}
	d, err := t.live()
	if err != nil {
		return err
	}
	return syncNamed(d.root, "journal.bin")
}

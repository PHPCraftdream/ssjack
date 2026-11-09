package appstorefilecheck

import (
	"errors"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstorefile"
)

func TestNativeRecordsRejectPartialJournalIntentAndPointer(t *testing.T) {
	root, directory := fixture(t)
	tx, err := directory.Lock()
	must(t, err)
	defer tx.Close()
	journal, err := tx.Journal()
	must(t, err)
	must(t, journal.Close())
	writer, err := root.Write("journal.bin", false)
	must(t, err)
	_, err = writer.Write([]byte{1})
	must(t, err)
	must(t, writer.Close())
	if file, err := tx.Journal(); !errors.Is(err, appstorefile.ErrInvalid) {
		if file != nil {
			file.Close()
		}
		t.Fatal("partial journal entry accepted")
	}
	writer, err = root.Write("pointer.bin", true)
	must(t, err)
	_, err = writer.Write(make([]byte, 63))
	must(t, err)
	must(t, writer.Close())
	if _, err := tx.ReadPointer(); !errors.Is(err, appstorefile.ErrInvalid) {
		t.Fatal("truncated pointer accepted")
	}
	intents, err := root.Child("intents", false)
	must(t, err)
	defer intents.Close()
	writer, err = intents.Write("00000000000000000000000000000003.bin", true)
	must(t, err)
	_, err = writer.Write(make([]byte, 312))
	must(t, err)
	must(t, writer.Close())
	if _, err := tx.LoadIntent(id(3)); !errors.Is(err, appstorefile.ErrInvalid) {
		t.Fatal("invalid intent domain accepted")
	}
	if err := tx.CreateIntent(id(3), [312]byte{}); !errors.Is(err, appstorefile.ErrInvalid) {
		t.Fatal("invalid intent admitted to disk")
	}
}

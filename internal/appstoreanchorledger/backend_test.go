package appstoreanchorledger

import (
	"bytes"
	"encoding/binary"
	"os"
	"runtime"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorcore"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorrequest"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
	"github.com/PHPCraftdream/ssjack/internal/appstorejournal"
)

func id(v byte) [16]byte   { return [16]byte(bytes.Repeat([]byte{v}, 16)) }
func hash(v byte) [32]byte { return [32]byte(bytes.Repeat([]byte{v}, 32)) }
func scope(t *testing.T, credential byte, role appstoreanchorcore.Role) appstoreanchorcore.Grant {
	t.Helper()
	g, err := appstoreanchorcore.NewGrant(id(1), hash(credential), role)
	if err != nil {
		t.Fatal(err)
	}
	return g
}
func fixture(t *testing.T, capacity int) (*Backend, *os.File, string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("Linux durable backend required")
	}
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	dir, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dir.Close() })
	b, err := New(dir, id(1), capacity)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	return b, dir, path
}
func request(t *testing.T, r appstoreanchorrequest.Request) appstoreanchorcore.Request {
	t.Helper()
	result, err := appstoreanchorcore.Parse(r.Bytes(), id(1))
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func operations(t *testing.T) (appstoreanchorcore.Request, appstoreanchorcore.Request, appstoreanchorcore.Request, appstoreanchorcore.Request) {
	t.Helper()
	genesis, _ := appstoreanchorstate.Genesis(id(1))
	read, err := appstoreanchorrequest.NewRead(id(1), id(9))
	if err != nil {
		t.Fatal(err)
	}
	create, err := appstoreanchorrequest.NewCreate(id(1))
	if err != nil {
		t.Fatal(err)
	}
	entry, err := appstorejournal.NewEntry(0, id(2), id(4))
	if err != nil {
		t.Fatal(err)
	}
	reserve, err := appstoreanchorrequest.PlanReservation(genesis, entry)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := appstoreanchorrequest.PlanCommit(reserve, hash(3))
	if err != nil {
		t.Fatal(err)
	}
	return request(t, read), request(t, create), request(t, reserve), request(t, commit)
}
func execute(t *testing.T, b *Backend, r appstoreanchorcore.Request, g appstoreanchorcore.Grant, want appstoreanchorreply.Outcome) [288]byte {
	t.Helper()
	result, err := b.Execute(r, g)
	if err != nil || result.Outcome() != want {
		t.Fatalf("outcome %v: %v", result.Outcome(), err)
	}
	raw, err := result.Unsigned()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestDurableReplayReturnsOriginalResultAfterLaterStateAndRestart(t *testing.T) {
	b, dir, _ := fixture(t, 8)
	read, create, reserve, commit := operations(t)
	writer := scope(t, 5, appstoreanchorcore.Writer)
	execute(t, b, read, writer, appstoreanchorreply.NotFound)
	original := execute(t, b, create, writer, appstoreanchorreply.Committed)
	execute(t, b, reserve, writer, appstoreanchorreply.Committed)
	execute(t, b, commit, writer, appstoreanchorreply.Committed)
	conflict := execute(t, b, create, scope(t, 6, appstoreanchorcore.Writer), appstoreanchorreply.Conflict)
	if binary.BigEndian.Uint64(conflict[48:56]) != 2 {
		t.Fatal("conflict current version")
	}
	if got := execute(t, b, create, writer, appstoreanchorreply.Committed); got != original {
		t.Fatal("replay returned latest state")
	}
	if len(b.state.records) != 4 {
		t.Fatal("read/replay consumed ledger capacity")
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(dir, id(1), 8)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if got := execute(t, reopened, create, writer, appstoreanchorreply.Committed); got != original {
		t.Fatal("restart replay changed result")
	}
	if got := execute(t, reopened, create, scope(t, 6, appstoreanchorcore.Writer), appstoreanchorreply.Conflict); got != conflict {
		t.Fatal("recorded conflict changed")
	}
	observed := execute(t, reopened, read, scope(t, 5, appstoreanchorcore.Reader), appstoreanchorreply.ReadState)
	if binary.BigEndian.Uint64(observed[48:56]) != 2 {
		t.Fatal("restart lost version")
	}
}

func TestCanonicalCollisionAndReadIDNamespace(t *testing.T) {
	b, _, _ := fixture(t, 8)
	_, create, reserve, _ := operations(t)
	writer := scope(t, 5, appstoreanchorcore.Writer)
	execute(t, b, create, writer, appstoreanchorreply.Committed)
	execute(t, b, reserve, writer, appstoreanchorreply.Committed)
	changed := reserve.Bytes()
	changed[48] ^= 1
	other, err := appstoreanchorcore.Parse(changed, id(1))
	if err != nil {
		t.Fatal("fixture must remain canonical", err)
	}
	if result, err := b.Execute(other, writer); err != ErrConflict || result.Valid() {
		t.Fatal("changed canonical mutation accepted")
	}
	read, err := appstoreanchorrequest.NewRead(id(1), create.RequestID())
	if err != nil {
		t.Fatal(err)
	}
	if result, err := b.Execute(request(t, read), writer); err != ErrConflict || result.Valid() {
		t.Fatal("read reused mutation ID")
	}
	if len(b.state.records) != 2 {
		t.Fatal("collision changed durable records")
	}
}

func TestCapacityAndAuthorizedRejectionRetention(t *testing.T) {
	b, dir, _ := fixture(t, 1)
	read, create, reserve, _ := operations(t)
	writer := scope(t, 5, appstoreanchorcore.Writer)
	original := execute(t, b, reserve, writer, appstoreanchorreply.Rejected)
	if result, err := b.Execute(create, writer); err != ErrCapacity || result.Valid() {
		t.Fatal("capacity exceeded before mutation")
	}
	execute(t, b, read, writer, appstoreanchorreply.NotFound)
	if got := execute(t, b, reserve, writer, appstoreanchorreply.Rejected); got != original {
		t.Fatal("capacity blocked existing replay")
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := New(dir, id(1), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if got := execute(t, next, reserve, writer, appstoreanchorreply.Rejected); got != original {
		t.Fatal("rejected outcome lost on restart")
	}
}

func TestReaderDenialDoesNotConsumeCapacityOrBypassRevocation(t *testing.T) {
	b, _, _ := fixture(t, 2)
	_, create, _, _ := operations(t)
	reader, writer := scope(t, 5, appstoreanchorcore.Reader), scope(t, 5, appstoreanchorcore.Writer)
	execute(t, b, create, reader, appstoreanchorreply.Rejected)
	if len(b.state.records) != 0 {
		t.Fatal("unauthorized attempt consumed durable capacity")
	}
	execute(t, b, create, writer, appstoreanchorreply.Committed)
	execute(t, b, create, reader, appstoreanchorreply.Rejected)
	if len(b.state.records) != 1 {
		t.Fatal("downgraded credential rewrote original outcome")
	}
}

func TestUnsupportedPlatformsFailClosed(t *testing.T) {
	if runtime.GOOS == "linux" {
		return
	}
	if b, err := New(nil, id(1), 1); b != nil || err != ErrUnsupported {
		t.Fatal("weaker non-Linux IO selected")
	}
}

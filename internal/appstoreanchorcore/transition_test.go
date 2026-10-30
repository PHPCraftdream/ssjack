package appstoreanchorcore

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
)

func grant(t *testing.T, role Role) Grant {
	t.Helper()
	g, err := NewGrant(id(1), hash(5), role)
	if err != nil {
		t.Fatal(err)
	}
	return g
}
func verify(t *testing.T, result Result) appstoreanchorreply.Reply {
	t.Helper()
	unsigned, err := result.Unsigned()
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, 32))
	signed := append(unsigned[:], ed25519.Sign(key, unsigned[:])...)
	reply, err := appstoreanchorreply.Verify(signed, key.Public().(ed25519.PublicKey), appstoreanchorreply.Expected{Operation: result.request.Operation(), RequestID: result.request.RequestID(), StoreID: result.request.StoreID()})
	if err != nil || reply.Outcome() != result.Outcome() {
		t.Fatal("result violates signed reply contract", err)
	}
	return reply
}
func evaluate(t *testing.T, r Request, g Grant, current Current) Result {
	t.Helper()
	result, err := Evaluate(r, g, current)
	if err != nil {
		t.Fatal(err)
	}
	verify(t, result)
	return result
}

func TestCreateReserveCommitAndRead(t *testing.T) {
	genesis, _ := appstoreanchorstate.Genesis(id(1))
	missing, _ := Missing(id(1))
	reader, writer := grant(t, Reader), grant(t, Writer)
	read := parsed(t, wire(Read, [32]byte{}, genesis))
	result := evaluate(t, read, reader, missing)
	if result.Outcome() != appstoreanchorreply.NotFound {
		t.Fatal("missing read")
	}
	create := parsed(t, wire(Create, [32]byte{}, genesis))
	result = evaluate(t, create, writer, missing)
	current, changed := result.Next()
	if !changed || !current.Valid() || current.Version() != 0 {
		t.Fatal("genesis create")
	}
	if evaluate(t, create, writer, current).Outcome() != appstoreanchorreply.Conflict {
		t.Fatal("existing store reset")
	}
	reserve := parsed(t, wire(Reserve, genesis.Hash(), state(t, 0, 1)))
	result = evaluate(t, reserve, writer, current)
	current, changed = result.Next()
	if !changed || current.Version() != 1 {
		t.Fatal("reservation version")
	}
	reserved, _ := current.State()
	commit := parsed(t, wire(Commit, reserved.Hash(), state(t, 1, 1)))
	result = evaluate(t, commit, writer, current)
	current, changed = result.Next()
	if !changed || current.Version() != 2 {
		t.Fatal("commit version")
	}
	observed := evaluate(t, read, reader, current)
	if reply := verify(t, observed); reply.ServiceVersion() != 2 || reply.Outcome() != appstoreanchorreply.ReadState {
		t.Fatal("read changed version")
	}
	if _, changed := observed.Next(); changed {
		t.Fatal("read proposes mutation")
	}
	// Durable replay must precede evaluation; raw re-evaluation is a stale CAS conflict.
	if evaluate(t, commit, writer, current).Outcome() != appstoreanchorreply.Conflict {
		t.Fatal("stale expected hash changed state")
	}
	unknown, err := Unknown(commit)
	if err != nil {
		t.Fatal(err)
	}
	verify(t, unknown)
	if unknown.Outcome() != appstoreanchorreply.Unknown {
		t.Fatal("unknown asserted outcome")
	}
	if _, changed := unknown.Next(); changed {
		t.Fatal("unknown proposes mutation")
	}
}

func TestReaderMutationDeniedWithoutInspectingState(t *testing.T) {
	genesis, _ := appstoreanchorstate.Genesis(id(1))
	for _, kind := range []Kind{Create, Reserve, Commit} {
		proposed := genesis
		if kind == Reserve {
			proposed = state(t, 0, 1)
		} else if kind == Commit {
			proposed = state(t, 1, 1)
		}
		result := evaluate(t, parsed(t, wire(kind, hash(6), proposed)), grant(t, Reader), Current{})
		if result.Outcome() != appstoreanchorreply.Rejected {
			t.Fatal("reader mutation admitted")
		}
		if _, changed := result.Next(); changed {
			t.Fatal("reader changes state")
		}
	}
}

func TestScopeInvalidCurrentAndVersionOverflow(t *testing.T) {
	genesis, _ := appstoreanchorstate.Genesis(id(1))
	read := parsed(t, wire(Read, [32]byte{}, genesis))
	missing, _ := Missing(id(1))
	wrong, _ := NewGrant(id(2), hash(5), Writer)
	for _, tc := range []struct {
		r Request
		g Grant
		c Current
	}{
		{Request{}, grant(t, Reader), missing},
		{read, Grant{}, missing},
		{read, wrong, missing},
		{read, grant(t, Reader), Current{}},
	} {
		if result, err := Evaluate(tc.r, tc.g, tc.c); err != ErrInvalid || result.Valid() {
			t.Fatal("invalid context accepted")
		}
	}
	if _, err := Existing(state(t, 0, 1), 0); err != ErrInvalid {
		t.Fatal("mutated state at version zero")
	}
	if _, err := Existing(appstoreanchorstate.State{}, 1); err != ErrInvalid {
		t.Fatal("invalid persisted state")
	}
	if _, err := Missing([16]byte{}); err != ErrInvalid {
		t.Fatal("zero store")
	}
	for _, role := range []Role{0, 3} {
		if _, err := NewGrant(id(1), hash(5), role); err != ErrInvalid {
			t.Fatal("unknown role")
		}
	}
	if _, err := NewGrant(id(1), [32]byte{}, Writer); err != ErrInvalid {
		t.Fatal("missing credential identity")
	}
	first, _ := NewGrant(id(1), hash(5), Writer)
	second, _ := NewGrant(id(1), hash(6), Writer)
	if first.CredentialID() == second.CredentialID() {
		t.Fatal("credential namespaces collapsed")
	}
	current, _ := Existing(genesis, ^uint64(0))
	reserve := parsed(t, wire(Reserve, genesis.Hash(), state(t, 0, 1)))
	result := evaluate(t, reserve, grant(t, Writer), current)
	if result.Outcome() != appstoreanchorreply.Rejected {
		t.Fatal("service version overflow")
	}
	if _, changed := result.Next(); changed {
		t.Fatal("overflow proposes mutation")
	}
	if _, err := (Result{}).Unsigned(); err != ErrInvalid {
		t.Fatal("zero result serialized")
	}
}

func TestCASDoesNotPretendToVerifyJournalSemantics(t *testing.T) {
	genesis, _ := appstoreanchorstate.Genesis(id(1))
	advanced := state(t, 1, 1)
	current, _ := Existing(advanced, 2)
	// A canonical reservation DTO does not carry the entry needed to prove its head/key.
	reset := parsed(t, wire(Reserve, advanced.Hash(), genesis))
	result := evaluate(t, reset, grant(t, Writer), current)
	next, changed := result.Next()
	proposed, exists := next.State()
	if !changed || !exists || proposed != genesis || next.Version() != 3 {
		t.Fatal("unexpected journal-semantic claim")
	}
}

package appstoreanchorresult_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorrequest"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorresult"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorstate"
)

func TestExactRecordedMutationStateNotJustSignature(t *testing.T) {
	g, reserve, commit, create := requests(t)
	for _, row := range []struct {
		request appstoreanchorrequest.Request
		version uint64
	}{{create, 0}, {reserve, 1}, {commit, 2}} {
		proposed, _ := row.request.ProposedState()
		r := reply(t, row.request, appstoreanchorreply.Committed, proposed, row.version)
		before := row.request.Bytes()
		got, err := appstoreanchorresult.CheckMutation(row.request, r)
		if err != nil || got != appstoreanchorresult.ExactRecordedResult || !bytes.Equal(before, row.request.Bytes()) {
			t.Fatalf("exact recorded state: %v", err)
		}
	}
	// This fixture has a valid signature, schema, operation and correlation, but
	// reports genesis instead of the proposed reservation state.
	wrong := reply(t, reserve, appstoreanchorreply.Committed, g, 1)
	if !wrong.SignatureValid() {
		t.Fatal("wrong-result witness was not signature checked")
	}
	got, err := appstoreanchorresult.CheckMutation(reserve, wrong)
	if !errors.Is(err, appstoreanchorresult.ErrInvalid) || got != 0 {
		t.Fatal("signature masked wrong mutation result")
	}
	for _, row := range []struct {
		outcome appstoreanchorreply.Outcome
		want    appstoreanchorresult.MutationResult
	}{
		{appstoreanchorreply.Conflict, appstoreanchorresult.ReadRequired},
		{appstoreanchorreply.Unknown, appstoreanchorresult.ReadRequired},
		{appstoreanchorreply.Rejected, appstoreanchorresult.ReportedRejected},
	} {
		state := appstoreanchorstate.State{}
		if row.outcome == appstoreanchorreply.Conflict {
			state = g
		}
		got, err := appstoreanchorresult.CheckMutation(reserve, reply(t, reserve, row.outcome, state, 1))
		if err != nil || got != row.want {
			t.Fatalf("non-success outcome: %v", err)
		}
	}
}

func TestReadFirstStateClassification(t *testing.T) {
	g, reserve, commit, create := requests(t)
	reserved, _ := reserve.ProposedState()
	committed, _ := commit.ProposedState()
	read, err := appstoreanchorrequest.NewRead(id(1), id(9))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		original appstoreanchorrequest.Request
		state    appstoreanchorstate.State
		want     appstoreanchorresult.Observation
	}{
		{reserve, g, appstoreanchorresult.AtExpected},
		{reserve, reserved, appstoreanchorresult.AtProposed},
		{reserve, committed, appstoreanchorresult.AtOther},
		{commit, reserved, appstoreanchorresult.AtExpected},
		{commit, committed, appstoreanchorresult.AtProposed},
		{commit, g, appstoreanchorresult.AtOther},
		{create, g, appstoreanchorresult.AtProposed},
		{create, reserved, appstoreanchorresult.AtOther},
	} {
		before := row.original.Bytes()
		got, err := appstoreanchorresult.ClassifyRead(row.original, read, reply(t, read, appstoreanchorreply.ReadState, row.state, 10))
		if err != nil || got != row.want || !bytes.Equal(before, row.original.Bytes()) {
			t.Fatalf("read classification: %v", err)
		}
	}
	for _, original := range []appstoreanchorrequest.Request{reserve, commit, create} {
		for _, row := range []struct {
			outcome appstoreanchorreply.Outcome
			want    appstoreanchorresult.Observation
		}{
			{appstoreanchorreply.NotFound, appstoreanchorresult.ReportedMissing},
			{appstoreanchorreply.Unknown, appstoreanchorresult.ReadUnavailable},
			{appstoreanchorreply.Rejected, appstoreanchorresult.ReadRejected},
		} {
			got, err := appstoreanchorresult.ClassifyRead(original, read, reply(t, read, row.outcome, appstoreanchorstate.State{}, 0))
			if err != nil || got != row.want {
				t.Fatalf("read non-state outcome: %v", err)
			}
		}
	}
	// A later current state does not rewrite a recorded idempotent result.
	recorded := reply(t, reserve, appstoreanchorreply.Committed, reserved, 1)
	_, _ = appstoreanchorresult.ClassifyRead(reserve, read, reply(t, read, appstoreanchorreply.ReadState, committed, 2))
	if got, err := appstoreanchorresult.CheckMutation(reserve, recorded); err != nil || got != appstoreanchorresult.ExactRecordedResult {
		t.Fatal("recorded result confused with latest state")
	}
}

func TestEachSignedCorrelationField(t *testing.T) {
	_, reserve, _, _ := requests(t)
	read, _ := appstoreanchorrequest.NewRead(id(1), id(9))
	for _, q := range []appstoreanchorrequest.Request{reserve, read} {
		for field := 0; field < 3; field++ {
			expected := appstoreanchorreply.Expected{Operation: appstoreanchorreply.Operation(q.Operation()), RequestID: q.RequestID(), StoreID: q.StoreID()}
			if field == 0 {
				expected.Operation = appstoreanchorreply.CreateIfAbsent
			}
			if field == 1 {
				expected.RequestID[15] ^= 0x80
			}
			if field == 2 {
				expected.StoreID[15] ^= 0x80
			}
			r := signed(t, expected, appstoreanchorreply.Unknown, appstoreanchorstate.State{}, 1)
			if q.Operation() == 3 {
				got, err := appstoreanchorresult.CheckMutation(q, r)
				if !errors.Is(err, appstoreanchorresult.ErrInvalid) || got != 0 {
					t.Fatal("single signed mutation correlation change admitted")
				}
			} else {
				got, err := appstoreanchorresult.ClassifyRead(reserve, q, r)
				if !errors.Is(err, appstoreanchorresult.ErrInvalid) || got != 0 {
					t.Fatal("single signed read correlation change admitted")
				}
			}
		}
	}
}

func TestInvalidKindsAndSignedCorrelationMismatch(t *testing.T) {
	g, reserve, commit, _ := requests(t)
	read, _ := appstoreanchorrequest.NewRead(id(1), id(9))
	otherID, _ := appstoreanchorrequest.NewRead(id(1), id(8))
	otherStore, _ := appstoreanchorrequest.NewRead(id(2), id(9))
	readReply := reply(t, read, appstoreanchorreply.ReadState, g, 0)
	for _, q := range []appstoreanchorrequest.Request{{}, read, commit} {
		got, err := appstoreanchorresult.CheckMutation(q, readReply)
		if !errors.Is(err, appstoreanchorresult.ErrInvalid) || got != 0 {
			t.Fatal("wrong operation accepted")
		}
	}
	for _, r := range []appstoreanchorreply.Reply{{}, readReply, reply(t, commit, appstoreanchorreply.Unknown, appstoreanchorstate.State{}, 2)} {
		got, err := appstoreanchorresult.CheckMutation(reserve, r)
		if !errors.Is(err, appstoreanchorresult.ErrInvalid) || got != 0 {
			t.Fatal("signed mutation correlation mismatch accepted")
		}
	}
	for _, row := range []struct {
		original, read appstoreanchorrequest.Request
		reply          appstoreanchorreply.Reply
	}{
		{appstoreanchorrequest.Request{}, read, readReply},
		{read, read, readReply},
		{reserve, reserve, readReply},
		{reserve, otherID, readReply},
		{reserve, otherStore, readReply},
		{reserve, read, appstoreanchorreply.Reply{}},
		{reserve, read, reply(t, otherID, appstoreanchorreply.ReadState, g, 0)},
	} {
		got, err := appstoreanchorresult.ClassifyRead(row.original, row.read, row.reply)
		if !errors.Is(err, appstoreanchorresult.ErrInvalid) || got != 0 {
			t.Fatal("invalid read correlation/kind admitted")
		}
	}
}

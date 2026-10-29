// Package appstoreanchorresult classifies causal metadata without authorizing actions.
package appstoreanchorresult

import (
	"errors"

	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorreply"
	"github.com/PHPCraftdream/ssjack/internal/appstoreanchorrequest"
)

var ErrInvalid = errors.New("invalid application-store causal reply metadata")

type MutationResult byte

const (
	ExactRecordedResult MutationResult = iota + 1
	ReadRequired
	ReportedRejected
)

type Observation byte

const (
	AtProposed Observation = iota + 1
	AtExpected
	AtOther
	ReportedMissing
	ReadUnavailable
	ReadRejected
)

func mutation(q appstoreanchorrequest.Request) bool {
	return q.Valid() && (q.Operation() == 2 || q.Operation() == 3)
}
func correlated(q appstoreanchorrequest.Request, r appstoreanchorreply.Reply) bool {
	return q.Valid() && r.SignatureValid() && q.Operation() == byte(r.Operation()) && q.StoreID() == r.StoreID() && q.RequestID() == r.RequestID()
}

// CheckMutation never turns a signed but wrong resulting state into success.
func CheckMutation(q appstoreanchorrequest.Request, r appstoreanchorreply.Reply) (MutationResult, error) {
	if !mutation(q) || !correlated(q, r) {
		return 0, ErrInvalid
	}
	switch r.Outcome() {
	case appstoreanchorreply.Committed:
		proposed, ok := q.ProposedState()
		observed, present := r.State()
		if !ok || !present || observed != proposed {
			return 0, ErrInvalid
		}
		return ExactRecordedResult, nil
	case appstoreanchorreply.Conflict, appstoreanchorreply.Unknown:
		return ReadRequired, nil
	case appstoreanchorreply.Rejected:
		return ReportedRejected, nil
	}
	return 0, ErrInvalid
}

// ClassifyRead is descriptive only: matches do not grant commit or replay permission.
func ClassifyRead(original, read appstoreanchorrequest.Request, reply appstoreanchorreply.Reply) (Observation, error) {
	if !mutation(original) || read.Operation() != 1 || original.StoreID() != read.StoreID() || !correlated(read, reply) {
		return 0, ErrInvalid
	}
	switch reply.Outcome() {
	case appstoreanchorreply.ReadState:
		proposed, valid := original.ProposedState()
		observed, present := reply.State()
		if !valid || !present {
			return 0, ErrInvalid
		}
		if observed == proposed {
			return AtProposed, nil
		}
		if expected, ok := original.ExpectedStateHash(); ok && expected == observed.Hash() {
			return AtExpected, nil
		}
		return AtOther, nil
	case appstoreanchorreply.NotFound:
		return ReportedMissing, nil
	case appstoreanchorreply.Unknown:
		return ReadUnavailable, nil
	case appstoreanchorreply.Rejected:
		return ReadRejected, nil
	}
	return 0, ErrInvalid
}

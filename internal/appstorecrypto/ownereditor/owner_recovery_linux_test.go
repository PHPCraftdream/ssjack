package ownereditor

import (
	"context"
	"errors"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstorecrypto/snapshotstore"
)

func recoveryExpectation(proposal snapshotstore.OwnerWriteProposal) snapshotstore.OwnerRecoveryExpectation {
	expected := snapshotstore.OwnerRecoveryExpectation{TransactionID: proposal.TransactionID, SnapshotID: proposal.SnapshotID, PreviousHash: proposal.Previous.Hash(), Versions: make(map[[16]byte][16]byte)}
	for _, reference := range proposal.References {
		expected.Versions[reference.ObjectID()] = reference.VersionID()
	}
	return expected
}

func TestOwnerRecoveryMatchesOnlyThePreparedCommittedProposal(t *testing.T) {
	ctx, installation, directory := ownerFixture(t)
	owner := openOwnerFixture(t, ctx, installation, directory)
	if _, err := owner.Add("text/plain", []byte("synthetic recovery value")); err != nil {
		t.Fatal(err)
	}
	var proposal snapshotstore.OwnerWriteProposal
	commit, err := owner.CommitPrepared(ctx, func(_ context.Context, prepared snapshotstore.OwnerWriteProposal) error {
		proposal = prepared
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	writer, transport, err := installation.Writer(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	expected := recoveryExpectation(proposal)
	wrong := recoveryExpectation(proposal)
	wrong.TransactionID[0] ^= 1
	if _, err := writer.RecoverOwner(ctx, wrong); !errors.Is(err, snapshotstore.ErrWriterPending) {
		t.Fatal("recovery adopted an unrelated transaction")
	}
	wrong = recoveryExpectation(proposal)
	for object, version := range wrong.Versions {
		version[0] ^= 1
		wrong.Versions[object] = version
	}
	if _, err := writer.RecoverOwner(ctx, wrong); !errors.Is(err, snapshotstore.ErrWriterPending) {
		t.Fatal("recovery adopted an unexpected exact version")
	}
	recovered, err := writer.RecoverOwner(ctx, expected)
	if err != nil || recovered.State.Hash() != commit.State.Hash() || recovered.EncodedHash != commit.EncodedHash || len(recovered.Refs) != len(commit.Refs) {
		t.Fatalf("exact committed owner reconciliation failed: %v", err)
	}
	state, err := snapshotstore.ReadAnchor(ctx, transport, directory.StoreID())
	if err != nil || state.Hash() != commit.State.Hash() {
		t.Fatal("owner reconciliation changed the already committed anchor")
	}
}

func TestOwnerRecoveryProvesAProposalWasNeverDispatched(t *testing.T) {
	ctx, installation, directory := ownerFixture(t)
	owner := openOwnerFixture(t, ctx, installation, directory)
	if _, err := owner.Add("text/plain", []byte("synthetic undispatched value")); err != nil {
		t.Fatal(err)
	}
	var proposal snapshotstore.OwnerWriteProposal
	refused := errors.New("synthetic database intent refusal")
	if _, err := owner.CommitPrepared(ctx, func(_ context.Context, prepared snapshotstore.OwnerWriteProposal) error {
		proposal = prepared
		return refused
	}); !errors.Is(err, refused) {
		t.Fatal("intent refusal was not observed")
	}
	writer, transport, err := installation.Writer(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	if _, err := writer.RecoverOwner(ctx, recoveryExpectation(proposal)); !errors.Is(err, snapshotstore.ErrOwnerUndispatched) {
		t.Fatal("recovery fabricated dispatch or adopted an absent proposal")
	}
	state, err := snapshotstore.ReadAnchor(ctx, transport, directory.StoreID())
	if err != nil || state.Hash() != proposal.Previous.Hash() {
		t.Fatal("no-dispatch inspection changed the anchor")
	}
}

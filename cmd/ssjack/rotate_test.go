package main

import (
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/vault"
)

func TestLegacyRotateRefusesActiveJournalBeforeRemoteEffects(t *testing.T) {
	active := []string{
		vault.RotationPrepared, vault.RotationAttempting, vault.RotationUnknown,
		vault.RotationAdded, vault.RotationVerified, vault.RotationCommitted,
	}
	for _, phase := range active {
		v := &vault.Vault{Rotation: &vault.RotationJournal{Phase: phase}}
		if err := refuseActiveRotation(v); err == nil {
			t.Fatalf("active phase %q admitted legacy rotate", phase)
		}
	}
	for _, phase := range []string{vault.RotationCancelled, vault.RotationComplete, vault.RotationArchived} {
		v := &vault.Vault{Rotation: &vault.RotationJournal{Phase: phase}}
		if err := refuseActiveRotation(v); err != nil {
			t.Fatalf("inactive phase %q refused: %v", phase, err)
		}
	}
	if err := refuseActiveRotation(&vault.Vault{}); err != nil {
		t.Fatalf("no journal refused: %v", err)
	}
}

package vault

import "testing"

func TestRotationPhasePredicates(t *testing.T) {
	active := map[string]bool{
		RotationPrepared: true, RotationAttempting: true, RotationUnknown: true,
		RotationAdded: true, RotationVerified: true, RotationCommitted: true,
	}
	verification := map[string]bool{RotationAttempting: true, RotationUnknown: true, RotationAdded: true}
	phases := []string{
		RotationPrepared, RotationAttempting, RotationUnknown, RotationAdded, RotationVerified,
		RotationCommitted, RotationComplete, RotationCancelled, RotationArchived, "", "bogus",
	}
	for _, phase := range phases {
		if got := LiveRotationPhase(phase); got != active[phase] {
			t.Errorf("LiveRotationPhase(%q) = %v, want %v", phase, got, active[phase])
		}
		if got := RotationAwaitsVerification(phase); got != verification[phase] {
			t.Errorf("RotationAwaitsVerification(%q) = %v, want %v", phase, got, verification[phase])
		}
	}
}

func TestClearRotationTargetWipesSecretBuffers(t *testing.T) {
	key, password := []byte("private-key"), []byte("password")
	target := Target{PrivateKey: key, Password: password}
	clearRotationTarget(&target)
	for name, buffer := range map[string][]byte{"private key": key, "password": password} {
		for _, b := range buffer {
			if b != 0 {
				t.Fatalf("%s buffer not wiped: %v", name, buffer)
			}
		}
	}
}

func TestWithRotationMaterialAtRequiresCallback(t *testing.T) {
	if err := (&Session{}).WithRotationMaterialAt(0, 0, nil); err == nil {
		t.Fatal("nil callback accepted")
	}
}

func TestDiscardRotationJournalDestroysMaterialAndCancels(t *testing.T) {
	original, replacement := []byte("old-private"), []byte("new-private")
	j := &RotationJournal{
		Phase:      RotationUnknown,
		Original:   Target{PrivateKey: original},
		NewPrivate: replacement,
		NewPublic:  []byte("new-public"),
		OldPublic:  []byte("old-public"),
	}
	discardRotationJournal(j)
	if j.Phase != RotationCancelled || !rotationTargetEmpty(j.Original) || len(j.NewPrivate)+len(j.NewPublic)+len(j.OldPublic) != 0 {
		t.Fatalf("journal retains material or phase: %+v", j)
	}
	for name, buffer := range map[string][]byte{"original": original, "replacement": replacement} {
		for _, b := range buffer {
			if b != 0 {
				t.Fatalf("%s private key not wiped: %v", name, buffer)
			}
		}
	}
}

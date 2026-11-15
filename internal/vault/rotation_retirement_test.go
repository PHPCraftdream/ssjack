package vault

import (
	"bytes"
	"errors"
	"testing"
)

func retirementSession() *Session {
	account := Target{Address: "host.invalid:22", User: "deploy"}
	original, current := account, account
	original.PrivateKey = []byte("old-private")
	current.PrivateKey = []byte("new-private")
	return &Session{revision: 7, state: &Vault{
		Targets: map[string]Target{"main": current},
		Rotation: &RotationJournal{
			PlanID: 3, Phase: RotationComplete, Profile: "main", Original: original,
			NewPrivate: []byte("new-private"), OldPublic: []byte("old-public"), NewPublic: []byte("new-public"),
		},
	}}
}

func TestRetirementMaterialLendsCommittedKeyAndWipesTheLoan(t *testing.T) {
	s := retirementSession()
	var lent []byte
	err := s.WithRetirementMaterialAt(7, 3, func(current Target, oldPublic, newPublic []byte) error {
		if string(current.PrivateKey) != "new-private" || current.Address != "host.invalid:22" || current.User != "deploy" {
			t.Fatalf("lent credential = %+v, want the committed replacement key", current)
		}
		if string(oldPublic) != "old-public" || string(newPublic) != "new-public" {
			t.Fatalf("lent public keys = %q, %q", oldPublic, newPublic)
		}
		lent = current.PrivateKey
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(lent, make([]byte, len(lent))) {
		t.Fatalf("lent private key not wiped: %q", lent)
	}
	if string(s.state.Targets["main"].PrivateKey) != "new-private" || string(s.state.Rotation.NewPrivate) != "new-private" {
		t.Fatal("wiping the loan damaged the stored credential")
	}
	sentinel := errors.New("remote failed")
	if err := s.WithRetirementMaterialAt(7, 3, func(Target, []byte, []byte) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("callback error = %v", err)
	}
}

func TestRetirementMaterialRefusesAnythingButTheExactCompletedRotation(t *testing.T) {
	for name, mutate := range map[string]func(*Session) (revision, plan uint64){
		"stale revision": func(*Session) (uint64, uint64) { return 6, 3 },
		"wrong plan":     func(*Session) (uint64, uint64) { return 7, 4 },
		"verified, not committed": func(s *Session) (uint64, uint64) {
			s.state.Rotation.Phase = RotationVerified
			return 7, 3
		},
		"archived": func(s *Session) (uint64, uint64) {
			s.state.Rotation.Phase = RotationArchived
			return 7, 3
		},
		"credential changed after completion": func(s *Session) (uint64, uint64) {
			target := s.state.Targets["main"]
			target.PrivateKey = []byte("later-private")
			s.state.Targets["main"] = target
			return 7, 3
		},
		"endpoint changed after completion": func(s *Session) (uint64, uint64) {
			target := s.state.Targets["main"]
			target.Address = "elsewhere.invalid:22"
			s.state.Targets["main"] = target
			return 7, 3
		},
		"another profile still uses the old key on this account": func(s *Session) (uint64, uint64) {
			s.state.Targets["agent"] = Target{Address: "host.invalid:22", User: "deploy", PrivateKey: []byte("old-private")}
			return 7, 3
		},
		"closed session": func(s *Session) (uint64, uint64) {
			s.closed = true
			return 7, 3
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := retirementSession()
			revision, plan := mutate(s)
			lent := false
			err := s.WithRetirementMaterialAt(revision, plan, func(Target, []byte, []byte) error { lent = true; return nil })
			if err == nil || lent {
				t.Fatalf("retirement material lent: err=%v lent=%v", err, lent)
			}
		})
	}
}

func TestRetirementMaterialIgnoresOldKeyOnOtherAccounts(t *testing.T) {
	s := retirementSession()
	s.state.Targets["other-host"] = Target{Address: "other.invalid:22", User: "deploy", PrivateKey: []byte("old-private")}
	s.state.Targets["other-user"] = Target{Address: "host.invalid:22", User: "backup", PrivateKey: []byte("old-private")}
	if err := s.WithRetirementMaterialAt(7, 3, func(Target, []byte, []byte) error { return nil }); err != nil {
		t.Fatalf("old key on a different remote account blocked retirement: %v", err)
	}
	if err := s.WithRetirementMaterialAt(7, 3, nil); err == nil {
		t.Fatal("nil callback accepted")
	}
}

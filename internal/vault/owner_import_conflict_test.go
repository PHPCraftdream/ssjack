package vault

import (
	"fmt"
	"testing"
)

func importID(n int) string { return fmt.Sprintf("%032x", n+1) }

func rawImportServer(t *testing.T, v *Vault, id, name, profile string) {
	t.Helper()
	v.Targets[profile] = testTarget(t)
	v.Servers[id] = Server{Name: name, Accounts: map[string]string{"main": profile}}
}

func hasConflict(conflicts []ImportConflict, kind, subject string) bool {
	for _, conflict := range conflicts {
		if conflict.Kind == kind && (subject == "" || conflict.Subject == subject) {
			return true
		}
	}
	return false
}

func TestOwnerImportConflictKindsRefuseWholePlan(t *testing.T) {
	fx := newImportFixture(t, []byte("synthetic-global-value"))
	ref := directoryRef(t, 9)
	alphaMain := fx.source.Servers[fx.alpha].Accounts["main"]
	cases := []struct {
		name, kind, subject string
		linked              bool
		mutate              func(*Vault)
	}{
		{"server id", ConflictServerID, "production", true, func(v *Vault) { rawImportServer(t, v, fx.alpha, "unrelated", importID(500)) }},
		{"server name", ConflictServerName, "staging", true, func(v *Vault) { rawImportServer(t, v, importID(1), "staging", importID(500)) }},
		{"account id", ConflictAccountID, "production/main", true, func(v *Vault) { rawImportServer(t, v, importID(1), "mine", alphaMain) }},
		{"secret id", ConflictSecretID, "token", true, func(v *Vault) { v.Secrets[fx.tokenID] = SecretBinding{Name: "other", Ref: ref} }},
		{"secret name", ConflictSecretName, "token", true, func(v *Vault) { v.Secrets[importID(1)] = SecretBinding{Name: "token", Ref: ref} }},
		{"server limit", ConflictServerLimit, "", true, func(v *Vault) {
			for n := 0; n < 63; n++ {
				rawImportServer(t, v, importID(n), fmt.Sprintf("srv%d", n), importID(500+n))
			}
		}},
		{"account limit", ConflictAccountLimit, "", true, func(v *Vault) {
			base, accounts := testTarget(t), make(map[string]string)
			for n := 0; n < 63; n++ {
				v.Targets[importID(500+n)], accounts[fmt.Sprintf("acc%d", n)] = ownTarget(base), importID(500+n)
			}
			v.Servers[importID(1)] = Server{Name: "wide", Accounts: accounts}
		}},
		{"secret limit", ConflictSecretLimit, "", true, func(v *Vault) {
			for n := 0; n < 126; n++ {
				v.Secrets[importID(n)] = SecretBinding{Name: fmt.Sprintf("s%d", n), Ref: ref}
			}
		}},
		{"pending intent", ConflictPendingIntent, "", true, func(v *Vault) {
			if _, err := v.StageOwnerChange(OwnerChange{Action: "add", Name: "queued", MediaType: "text/plain", Value: []byte("synthetic queued")}); err != nil {
				t.Fatal(err)
			}
		}},
		{"unlinked store", ConflictUnlinkedStore, "", false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := importDestination(t, tc.linked, tc.mutate)
			conflicts, err := s.ImportConflicts(fx.imported)
			if err != nil || !hasConflict(conflicts, tc.kind, tc.subject) {
				t.Fatalf("missing %s conflict: %v", tc.kind, conflicts)
			}
			if err := s.ApplyOwnerImportDirectory(fx.imported); err != ErrImportConflict {
				t.Fatal("conflicting import was applied")
			}
			if s.Status().Revision != 0 {
				t.Fatal("refused import changed the revision")
			}
		})
	}
	t.Run("directory version", func(t *testing.T) {
		s := newSession(New(), nil, func() {})
		t.Cleanup(s.Discard)
		conflicts, err := s.ImportConflicts(fx.imported)
		if err != nil || !hasConflict(conflicts, ConflictDirectoryVersion, "") || s.ApplyOwnerImportDirectory(fx.imported) != ErrImportConflict {
			t.Fatal("version 1 destination was not refused")
		}
	})
}

func TestOwnerImportRefusalLeavesDestinationUntouched(t *testing.T) {
	fx := newImportFixture(t, []byte("synthetic-global-value"))
	var existing Target
	s := importDestination(t, true, func(v *Vault) {
		// Only "staging" (the second server by name) collides.
		rawImportServer(t, v, importID(1), "staging", importID(500))
		existing = ownTarget(v.Targets[importID(500)])
	})
	conflicts, err := s.ImportConflicts(fx.imported)
	if err != nil || len(conflicts) != 1 || conflicts[0] != (ImportConflict{Kind: ConflictServerName, Subject: "staging"}) {
		t.Fatalf("unexpected conflicts: %v", conflicts)
	}
	if err := s.ApplyOwnerImportDirectory(fx.imported); err != ErrImportConflict {
		t.Fatal("partially conflicting plan was not refused")
	}
	inspectSession(s, func(v *Vault) {
		if len(v.Servers) != 1 || len(v.Targets) != 1 || v.Servers[importID(1)].Name != "staging" || !sameImportedTarget(v.Targets[importID(500)], existing) {
			t.Fatal("refusal merged part of the plan or overwrote the destination")
		}
	})
	if s.Status().Revision != 0 {
		t.Fatal("refusal bumped the revision")
	}
}

func TestOwnerImportUnsupportedValuesAreConflicts(t *testing.T) {
	for _, value := range [][]byte{{0xff, 0xfe}, []byte("a\x00b")} {
		fx := newImportFixture(t, value)
		preview := fx.imported.Preview()
		if !hasConflict(preview.Conflicts, ConflictValueUnsupported, "token") || len(preview.Conflicts) != 1 {
			t.Fatal("preview did not flag the unsupported value")
		}
		s := importDestination(t, true, nil)
		conflicts, err := s.ImportConflicts(fx.imported)
		if err != nil || !hasConflict(conflicts, ConflictValueUnsupported, "token") {
			t.Fatal("session conflicts omitted the unsupported value")
		}
		if _, err := fx.imported.SecretChange(0); err == nil {
			t.Fatal("unsupported value became an owner change")
		}
		if s.ApplyOwnerImportDirectory(fx.imported) != ErrImportConflict || s.Status().Revision != 0 {
			t.Fatal("plan with an unsupported value was applied")
		}
	}
}

func TestVerifyOwnerImportDirectoryDetectsLaterEdits(t *testing.T) {
	fx := newImportFixture(t, []byte("synthetic-global-value"))
	accounts := fx.source.Servers[fx.alpha].Accounts
	retarget := func(profile string, change func(*Target)) func(*Vault) {
		return func(v *Vault) {
			target := ownTarget(v.Targets[profile])
			change(&target)
			v.Targets[profile] = target
		}
	}
	cases := []struct {
		name string
		edit func(*Vault)
	}{
		{"server renamed", func(v *Vault) {
			server := v.Servers[fx.alpha]
			server.Name = "renamed"
			v.Servers[fx.alpha] = server
		}},
		{"account user", retarget(accounts["main"], func(x *Target) { x.User = "changed" })},
		{"account password", retarget(accounts["deploy"], func(x *Target) { x.Password = []byte("synthetic-replaced-password") })},
		{"account private key", retarget(accounts["main"], func(x *Target) { x.PrivateKey = testTarget(t).PrivateKey })},
		{"server removed", func(v *Vault) {
			delete(v.Servers, fx.alpha)
			for _, profile := range accounts {
				delete(v.Targets, profile)
			}
		}},
	}
	if (&Session{}).VerifyOwnerImportDirectory(nil) != ErrImportInvalid {
		t.Fatal("nil import was accepted")
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := importDestination(t, true, nil)
			if err := s.ApplyOwnerImportDirectory(fx.imported); err != nil {
				t.Fatal(err)
			}
			if err := s.VerifyOwnerImportDirectory(fx.imported); err != nil {
				t.Fatalf("exact import failed verification: %v", err)
			}
			if err := s.Apply(func(v *Vault) error { tc.edit(v); return nil }); err != nil {
				t.Fatal(err)
			}
			if err := s.VerifyOwnerImportDirectory(fx.imported); err != ErrImportChanged {
				t.Fatalf("later edit was not detected: %v", err)
			}
		})
	}
}

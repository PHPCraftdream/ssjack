package sshlive

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/sshauth"
)

func TestAdmissionRejectsHealthyRuntimeAuthorityChanges(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Material)
	}{
		{"profile", func(m *Material) { m.Profile = "other-profile" }},
		{"scope", func(m *Material) { m.Scope = "other-scope" }},
		{"address", func(m *Material) { m.Address = "other.example:22" }},
		{"user", func(m *Material) { m.Config.User = "other-user" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			baseline := testMaterial("127.0.0.1:22")
			baseline.Revision = 4
			current := baseline
			runtime, err := New(context.Background(), baseline.Profile, func(context.Context) (Material, error) {
				return current, nil
			})
			if err != nil {
				t.Fatal("healthy baseline was not accepted")
			}
			current = baseline
			config := *baseline.Config
			config.Auth = append([]ssh.AuthMethod(nil), baseline.Config.Auth...)
			current.Config = &config
			test.mutate(&current)
			current.Revision++
			operation, err := runtime.Admit(context.Background(), baseline.Profile, "synthetic-command")
			status := runtime.Status()
			if !errors.Is(err, ErrUnavailable) || operation.Runner != nil || operation.Guard != nil || operation.Issued != nil || !status.Unavailable || !status.DesiredKnown || status.DesiredRevision != baseline.Revision || status.DeliveredKnown || status.AdoptedKnown {
				t.Fatal("healthy source with changed authority was not refused without delivery or adoption")
			}
		})
	}
}

func TestAdmissionAcceptsCredentialOnlyReplacementsAtNewRevision(t *testing.T) {
	for _, test := range []struct {
		name   string
		key    bool
		change func(*testing.T, *ssh.ClientConfig)
	}{
		{"password", false, func(_ *testing.T, config *ssh.ClientConfig) {
			config.Auth = []ssh.AuthMethod{sshauth.Password([]byte("synthetic replacement password"))}
		}},
		{"key", true, func(t *testing.T, config *ssh.ClientConfig) {
			_, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal("synthetic replacement key generation failed")
			}
			signer, err := ssh.NewSignerFromKey(private)
			if err != nil {
				t.Fatal("synthetic replacement signer creation failed")
			}
			config.Auth = []ssh.AuthMethod{sshauth.PublicKey(signer)}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			baseline := testMaterial("127.0.0.1:22")
			baseline.Revision = 4
			if test.key {
				_, private, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal("synthetic baseline key generation failed")
				}
				signer, err := ssh.NewSignerFromKey(private)
				if err != nil {
					t.Fatal("synthetic baseline signer creation failed")
				}
				config := *baseline.Config
				config.Auth = []ssh.AuthMethod{sshauth.PublicKey(signer)}
				baseline.Config = &config
			}
			current := baseline
			runtime, err := New(context.Background(), baseline.Profile, func(context.Context) (Material, error) {
				return current, nil
			})
			if err != nil {
				t.Fatal("healthy baseline was not accepted")
			}
			current = baseline
			config := *baseline.Config
			config.Auth = append([]ssh.AuthMethod(nil), baseline.Config.Auth...)
			test.change(t, &config)
			current.Config = &config
			current.Revision++
			operation, err := runtime.Admit(context.Background(), baseline.Profile, "synthetic-command")
			status := runtime.Status()
			if err != nil || operation.Runner == nil || operation.Guard == nil || operation.Issued == nil || !status.DesiredKnown || status.DesiredRevision != current.Revision || status.DeliveredKnown || status.AdoptedKnown {
				t.Fatal("credential-only replacement was not admitted at its current revision before issuance")
			}
			operation.Issued()
			status = runtime.Status()
			if !status.DesiredKnown || status.DesiredRevision != current.Revision || !status.DeliveredKnown || status.DeliveredRevision != current.Revision || status.AdoptedKnown || status.Unavailable {
				t.Fatal("issuance did not mark delivery at the current revision without adoption")
			}
		})
	}
}

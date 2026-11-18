//go:build linux && amd64

package declarativeauthority

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
)

func textAdapterTestRef(t *testing.T, storeByte, objectByte, versionByte, snapshotByte byte) string {
	t.Helper()
	store, object, version, snapshot := [16]byte{}, [16]byte{}, [16]byte{}, [16]byte{}
	for i := range store {
		store[i], object[i], version[i], snapshot[i] = storeByte, objectByte, versionByte, snapshotByte
	}
	ref, err := appstoreref.New(store, object, version, snapshot)
	if err != nil {
		t.Fatalf("New reference: %v", err)
	}
	encoded, err := appstoreplaceholder.Encode(ref)
	if err != nil {
		t.Fatalf("Encode reference: %v", err)
	}
	return string(encoded)
}

func validTextAdapterGrant(t *testing.T, now time.Time) TextAdapterGrant {
	t.Helper()
	return TextAdapterGrant{
		ID:                 base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef")),
		RecipientUID:       1000,
		StorePath:          "/approved/store",
		DirectoryDev:       1,
		DirectoryIno:       2,
		InstallationSHA256: strings.Repeat("a", 64),
		EncodedHash:        strings.Repeat("a", 64),
		References: []string{
			textAdapterTestRef(t, 1, 3, 5, 7),
			textAdapterTestRef(t, 1, 4, 6, 7),
		},
		Profile:          "approved-profile",
		CredentialSHA256: strings.Repeat("a", 64),
		Command:          "/approved/command",
		File:             "/approved/config",
		Mode:             "hydrate-v1",
		ExpiresAt:        now.Add(time.Hour).UTC().Format(time.RFC3339),
	}
}

func TestValidateTextAdapterGrant(t *testing.T) {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	valid := validTextAdapterGrant(t, now)
	if err := ValidateTextAdapterGrant(valid, now); err != nil {
		t.Fatalf("valid grant rejected: %v", err)
	}

	mutations := []struct {
		name   string
		mutate func(*TextAdapterGrant)
	}{
		{"uid-zero", func(g *TextAdapterGrant) { g.RecipientUID = 0 }},
		{"uid-root", func(g *TextAdapterGrant) {
			g.RecipientUID = 1000
			g.RecipientUID = 0
		}},
		{"id-bad", func(g *TextAdapterGrant) { g.ID = "bad" }},
		{"id-noncanonical", func(g *TextAdapterGrant) { g.ID += "=" }},
		{"expiry-past", func(g *TextAdapterGrant) { g.ExpiresAt = now.Add(-time.Second).Format(time.RFC3339) }},
		{"expiry-over-24h", func(g *TextAdapterGrant) { g.ExpiresAt = now.Add(25 * time.Hour).Format(time.RFC3339) }},
		{"reversed-mode", func(g *TextAdapterGrant) { g.Mode = "v1-hydrate" }},
		{"bad-hash", func(g *TextAdapterGrant) { g.EncodedHash = "not-a-digest" }},
		{"bad-reference", func(g *TextAdapterGrant) { g.References[0] = "not-a-reference" }},
		{"duplicate-reference", func(g *TextAdapterGrant) { g.References[1] = g.References[0] }},
		{"cross-store", func(g *TextAdapterGrant) { g.References[1] = textAdapterTestRef(t, 9, 4, 6, 7) }},
		{"cross-snapshot", func(g *TextAdapterGrant) { g.References[1] = textAdapterTestRef(t, 1, 4, 6, 9) }},
		{"no-references", func(g *TextAdapterGrant) { g.References = nil }},
		{"too-many-references", func(g *TextAdapterGrant) {
			for len(g.References) <= 16 {
				g.References = append(g.References, textAdapterTestRef(t, 1, byte(len(g.References)+10), 6, 7))
			}
		}},
		{"oversized-command", func(g *TextAdapterGrant) { g.Command = strings.Repeat("x", 8193) }},
		{"nul-command", func(g *TextAdapterGrant) { g.Command = "/approved/command\x00suffix" }},
		{"relative-file", func(g *TextAdapterGrant) { g.File = "approved/config" }},
		{"relative-store", func(g *TextAdapterGrant) { g.StorePath = "approved/store" }},
		{"revoked", func(g *TextAdapterGrant) { g.Revoked = true }},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			g := valid
			g.References = append([]string(nil), valid.References...)
			tc.mutate(&g)
			if err := ValidateTextAdapterGrant(g, now); !errors.Is(err, ErrAuthority) {
				t.Fatalf("expected ErrAuthority, got %v", err)
			}
		})
	}
}

func TestTextStreamProfilesRemainSeparateFromV1(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	for _, mode := range []string{"hydrate-stream-v2", "reverse-copy-stream-v2"} {
		grant := validTextAdapterGrant(t, now)
		grant.Mode = mode
		if err := ValidateTextStreamGrant(grant, now); err != nil {
			t.Fatal(err)
		}
		if grant.Mode != mode {
			t.Fatal("stream validation rewrote caller metadata")
		}
		if err := ValidateTextAdapterGrant(grant, now); err == nil {
			t.Fatal("v1 accepted a streaming grant")
		}
	}
	for _, mode := range []string{"hydrate-v1", "reverse-copy-v1", "hydrate-v2", "stream", ""} {
		grant := validTextAdapterGrant(t, now)
		grant.Mode = mode
		if err := ValidateTextStreamGrant(grant, now); err == nil {
			t.Fatal("stream profile accepted another authority mode")
		}
	}
	if textStreamName == textAdapterName || textStreamFormat == textAdapterFormat {
		t.Fatal("stream registration replaced the v1 registry namespace")
	}
}

func TestTextStreamRetainsFiniteImmutableGrantValidation(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	mutations := []func(*TextAdapterGrant){
		func(g *TextAdapterGrant) { g.RecipientUID = 0 },
		func(g *TextAdapterGrant) { g.ID = "caller-approval" },
		func(g *TextAdapterGrant) { g.CredentialSHA256 = "caller-approved" },
		func(g *TextAdapterGrant) { g.File = "relative" },
		func(g *TextAdapterGrant) { g.StorePath = "relative" },
		func(g *TextAdapterGrant) { g.DirectoryIno = 0 },
		func(g *TextAdapterGrant) { g.EncodedHash = "latest" },
		func(g *TextAdapterGrant) { g.References[1] = g.References[0] },
		func(g *TextAdapterGrant) { g.References[1] = textAdapterTestRef(t, 2, 4, 6, 7) },
		func(g *TextAdapterGrant) { g.References[1] = textAdapterTestRef(t, 1, 4, 6, 8) },
		func(g *TextAdapterGrant) { g.ExpiresAt = now.Add(25 * time.Hour).Format(time.RFC3339) },
		func(g *TextAdapterGrant) { g.ExpiresAt = now.Add(-time.Second).Format(time.RFC3339) },
		func(g *TextAdapterGrant) { g.Revoked = true },
	}
	for _, mutate := range mutations {
		grant := validTextAdapterGrant(t, now)
		grant.Mode = "hydrate-stream-v2"
		mutate(&grant)
		if err := ValidateTextStreamGrant(grant, now); err == nil {
			t.Fatal("stream registration weakened immutable finite authority validation")
		}
	}
}

func TestTextStreamDiskRejectsDuplicatesWrongFormatAndLegacyModes(t *testing.T) {
	grant := validTextAdapterGrant(t, time.Now())
	grant.Mode = "hydrate-stream-v2"
	if err := validateTextStreamDisk(textAdapterDisk{Format: textStreamFormat, Grants: []TextAdapterGrant{grant}}); err != nil {
		t.Fatal(err)
	}
	for _, disk := range []textAdapterDisk{
		{Format: textAdapterFormat, Grants: []TextAdapterGrant{grant}},
		{Format: textStreamFormat},
		{Format: textStreamFormat, Grants: []TextAdapterGrant{grant, grant}},
		{Format: textStreamFormat, Grants: []TextAdapterGrant{validTextAdapterGrant(t, time.Now())}},
	} {
		if err := validateTextStreamDisk(disk); err == nil {
			t.Fatal("stream registry accepted an ambiguous or wrong-profile record")
		}
	}
}

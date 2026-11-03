//go:build linux && amd64

package declarativeauthority

import (
	"testing"
	"time"
)

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

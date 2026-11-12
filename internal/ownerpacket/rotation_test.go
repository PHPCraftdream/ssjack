package ownerpacket

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestRotationCommandUnionIsClosedAndIdentityBound(t *testing.T) {
	revision := uint64(0)
	id := strings.Repeat("01", 16)
	valid := []Command{
		{Operation: "rotation", Revision: &revision, Rotation: &Rotation{Action: "prepare", ServerID: id, Account: "deploy"}},
		{Operation: "rotation", Revision: &revision, Rotation: &Rotation{Action: "install", ID: id, PlanID: 7}},
		{Operation: "rotation", Revision: &revision, Rotation: &Rotation{Action: "verify", ID: id, PlanID: 7}},
		{Operation: "rotation", Revision: &revision, Rotation: &Rotation{Action: "commit", ID: id, PlanID: 7}},
		{Operation: "rotation", Revision: &revision, Rotation: &Rotation{Action: "cancel", ID: id, PlanID: 7}},
		{Operation: "rotation", Revision: &revision, Rotation: &Rotation{Action: "recover", ID: id, PlanID: 7}},
		{Operation: "rotation", Revision: &revision, Rotation: &Rotation{Action: "archive", ID: id, PlanID: 7}},
	}
	for _, command := range valid {
		if !command.Valid() {
			t.Fatalf("valid rotation operation %q rejected", command.Rotation.Action)
		}
	}
	invalid := []Command{
		{Operation: "rotation", Rotation: valid[0].Rotation},
		{Operation: "rotation", Revision: &revision, Plan: 7, Rotation: valid[1].Rotation},
		{Operation: "rotation", Revision: &revision, Rotation: &Rotation{Action: "install", ID: id}},
		{Operation: "rotation", Revision: &revision, Rotation: &Rotation{Action: "prepare", ServerID: "../etc/passwd", Account: "deploy"}},
		{Operation: "rotation", Revision: &revision, Rotation: &Rotation{Action: "install", ID: id, PlanID: 7, ServerID: id}},
		{Operation: "rotation", Revision: &revision, Rotation: &Rotation{Action: "install", ID: strings.Repeat("00", 16), PlanID: 7}},
		{Operation: "rotation", Revision: &revision, Rotation: &Rotation{Action: "delete", ID: id, PlanID: 7}},
		{Operation: "rotation", Revision: &revision, Rotation: &Rotation{Action: "archive", ID: id}},
		{Operation: "rotation", Revision: &revision, Plan: 7, Rotation: &Rotation{Action: "archive", ID: id, PlanID: 7}},
		{Operation: "rotation", Revision: &revision, Rotation: &Rotation{Action: "archive", ID: id, PlanID: 7, ServerID: id}},
		{Operation: "rotation", Revision: &revision, Rotation: &Rotation{Action: "archive", ID: id, PlanID: 7, Account: "deploy"}},
		{Operation: "rotation", Rotation: &Rotation{Action: "archive", ID: id, PlanID: 7}},
	}
	for _, command := range invalid {
		if command.Valid() {
			t.Fatal("invalid rotation operation entered the packet union")
		}
	}
}

func rotationInfo(phase string) *RotationMetadata {
	return &RotationMetadata{ID: strings.Repeat("01", 16), Phase: phase, ServerID: strings.Repeat("02", 16), Account: "deploy", Profile: "profile", PlanID: 1, BaseRevision: 7, Address: "host.invalid:22", User: "deploy", Usage: "human", OldPublic: []byte("old"), NewPublic: []byte("new"), HostKeys: []string{"ssh-ed25519 AAAA"}}
}

func TestRotationMetadataAcceptsReloadedEpochAndAllPhases(t *testing.T) {
	for _, phase := range []string{"prepared", "attempting", "unknown", "added", "verified", "committed", "complete", "cancelled"} {
		info := rotationInfo(phase)
		if phase == "complete" {
			info.CommitDigest = strings.Repeat("a", 64)
		}
		if phase == "cancelled" {
			info.OldPublic, info.NewPublic = nil, nil
			info.Address, info.User, info.Usage, info.HostKeys = "", "", "", nil
		}
		reply := Reply{Status: Status{Revision: 0, SavedRevision: 0, CipherDigest: [32]byte{9}}, Rotation: info}
		if !reply.valid() {
			t.Fatalf("phase %q rejected after revision epoch reset", phase)
		}
	}
	complete := rotationInfo("complete")
	complete.CommitDigest = strings.Repeat("a", 64)
	if !(Reply{Status: Status{CipherDigest: [32]byte{9}}, Rotation: complete}).valid() {
		t.Fatal("completed proof with persisted revision zero was rejected")
	}
	archived := &RotationMetadata{ID: strings.Repeat("01", 16), Phase: "archived", ServerID: strings.Repeat("02", 16), Account: "deploy", Profile: "profile", PlanID: 9, BaseRevision: 7, CommitRevision: 0, CommitDigest: strings.Repeat("a", 64), RecoveryPath: "rotation-recovery.vault", RecoveryDigest: strings.Repeat("b", 64)}
	if !(Reply{Status: Status{CipherDigest: [32]byte{9}}, Rotation: archived}).valid() {
		t.Fatal("archived receipt with an epoch-zero commit revision was rejected")
	}
	encoded, err := json.Marshal(Reply{Rotation: archived})
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{[]byte(`"old_public"`), []byte(`"new_public"`), []byte(`"host_keys"`), []byte(`"address"`), []byte(`"user"`), []byte(`"usage"`)} {
		if bytes.Contains(encoded, forbidden) {
			t.Fatalf("archived receipt serialized forbidden metadata field %s", forbidden)
		}
	}
	for _, mutate := range []func(*RotationMetadata){
		func(r *RotationMetadata) { r.RecoveryPath = "" },
		func(r *RotationMetadata) { r.RecoveryPath = strings.Repeat("p", 4097) },
		func(r *RotationMetadata) { r.RecoveryDigest = strings.Repeat("0", 64) },
		func(r *RotationMetadata) { r.RecoveryDigest = strings.Repeat("B", 64) },
		func(r *RotationMetadata) { r.CommitDigest = strings.Repeat("0", 64) },
		func(r *RotationMetadata) { r.RecoveryPath = "bad\npath" },
		func(r *RotationMetadata) { r.Profile = strings.Repeat("p", 65) },
		func(r *RotationMetadata) { r.Phase = "archive-complete" },
		func(r *RotationMetadata) { r.OldPublic = []byte("sneaked-public") },
		func(r *RotationMetadata) { r.NewPublic = []byte("sneaked-public") },
		func(r *RotationMetadata) { r.HostKeys = []string{"sneaked-host-key"} },
		func(r *RotationMetadata) { r.Address = "sneaked-address" },
		func(r *RotationMetadata) { r.User = "sneaked-user" },
		func(r *RotationMetadata) { r.Usage = "both" },
	} {
		bad := *archived
		mutate(&bad)
		if (Reply{Status: Status{CipherDigest: [32]byte{9}}, Rotation: &bad}).valid() {
			t.Fatal("malformed archived rotation metadata accepted")
		}
	}

	priorEpoch := rotationInfo("prepared")
	if !(Reply{Status: Status{Revision: 1, SavedRevision: 1, CipherDigest: [32]byte{9}}, Rotation: priorEpoch}).valid() {
		t.Fatal("prepared rotation based on a prior epoch was rejected")
	}
	commitOnly := rotationInfo("complete")
	commitOnly.CommitDigest, commitOnly.OldPublic, commitOnly.NewPublic = strings.Repeat("a", 64), nil, nil
	if (Reply{Status: Status{CipherDigest: [32]byte{9}}, Rotation: commitOnly}).valid() {
		t.Fatal("complete metadata without retained public keys was accepted")
	}

	noKeys := rotationInfo("complete")
	noKeys.CommitDigest = strings.Repeat("a", 64)
	noKeys.OldPublic, noKeys.NewPublic = nil, nil
	if (Reply{Status: Status{CipherDigest: [32]byte{9}}, Rotation: noKeys}).valid() {
		t.Fatal("completed rotation without retained public keys was accepted")
	}
}

func TestRotationMetadataRejectsMalformedClosedFields(t *testing.T) {
	for _, mutate := range []func(*RotationMetadata){
		func(r *RotationMetadata) { r.Phase = "install" },
		func(r *RotationMetadata) { r.ID = strings.Repeat("00", 16) },
		func(r *RotationMetadata) { r.ID = strings.Repeat("A1", 16) },
		func(r *RotationMetadata) { r.ServerID = "../path" },
		func(r *RotationMetadata) { r.HostKeys = make([]string, 17) },
		func(r *RotationMetadata) { r.OldPublic = nil },
		func(r *RotationMetadata) { r.Account = "" },
		func(r *RotationMetadata) { r.CommitDigest = strings.Repeat("0", 64); r.Phase = "complete" },
		func(r *RotationMetadata) { r.OldPublic = []byte("one-sided"); r.Phase = "cancelled" },
	} {
		info := rotationInfo("prepared")
		mutate(info)
		if (Reply{Status: Status{CipherDigest: [32]byte{9}}, Rotation: info}).valid() {
			t.Fatal("malformed rotation metadata accepted")
		}
	}
}

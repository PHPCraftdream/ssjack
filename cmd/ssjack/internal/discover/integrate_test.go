package discover

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/application"
	"github.com/PHPCraftdream/ssjack/internal/application/discovery"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

const fixtureDescriptor = `{"format":"ssjack-app-v1","name":"appsvc","launch":{"executable":"bin/tool.exe"}}`

func writeDescriptor(t *testing.T, dir, name, content string) {
	t.Helper()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, application.DescriptorFile), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, name), []byte("not executed"), 0700); err != nil {
		t.Fatal(err)
	}
}

func fixtureScan(t *testing.T, name string) (string, discovery.Result, discovery.Candidate, vault.Approval) {
	t.Helper()
	root := t.TempDir()
	child := filepath.Join(root, "appsvc")
	content := strings.Replace(fixtureDescriptor, `"appsvc"`, fmt.Sprintf(`"%s"`, name), 1)
	writeDescriptor(t, child, "tool.exe", content)
	result := discovery.Scan(root)
	for _, candidate := range result.Candidates {
		if candidate.Name == name {
			hash := hex.EncodeToString(candidate.Fingerprint[:])
			return root, result, candidate, vault.Approval{Name: name, Path: candidate.CanonicalPath, Hash: hash}
		}
	}
	t.Fatalf("candidate %q missing from scan: %#v", name, result)
	return "", discovery.Result{}, discovery.Candidate{}, vault.Approval{}
}

func TestApprovedIntegration(t *testing.T) {
	t.Run("candidate_without_approval_stays_disabled", func(t *testing.T) {
		_, scan, _, _ := fixtureScan(t, "appsvc")
		apps, statuses, err := Approved(scan, nil, nil)
		if err != nil || len(apps) != 0 || len(statuses) != 0 {
			t.Fatalf("got apps=%v statuses=%v err=%v", apps, statuses, err)
		}
	})
	t.Run("approved_unchanged_registers_from_scanned_buffer", func(t *testing.T) {
		_, scan, candidate, record := fixtureScan(t, "appsvc")
		original, err := application.ParseDescriptorBuffer(candidate.Buffer, candidate.CanonicalPath)
		if err != nil {
			t.Fatal(err)
		}
		apps, statuses, err := Approved(scan, []vault.Approval{record}, nil)
		if err != nil || len(apps) != 1 || apps[0].Name != "appsvc" || apps[0].Directory != candidate.CanonicalPath || len(statuses) != 1 || statuses[0].Kind != "enabled" {
			t.Fatalf("got apps=%v statuses=%v err=%v", apps, statuses, err)
		}
		if err := os.WriteFile(filepath.Join(candidate.CanonicalPath, application.DescriptorFile), []byte(`{"different":true}`), 0600); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(apps[0], original) {
			t.Fatalf("registered app differs from scanned-buffer parse: %#v != %#v", apps[0], original)
		}
	})
	t.Run("one_changed_byte_disables_until_reapproval", func(t *testing.T) {
		_, scan, candidate, record := fixtureScan(t, "appsvc")
		candidate.Fingerprint[0]++
		scan.Candidates = []discovery.Candidate{candidate}
		apps, statuses, err := Approved(scan, []vault.Approval{record}, nil)
		if err != nil || len(apps) != 0 || len(statuses) != 1 || statuses[0].Kind != "changed" {
			t.Fatalf("got apps=%v statuses=%v err=%v", apps, statuses, err)
		}
	})
	t.Run("rebound_directory_between_check_and_registration_fails_closed", func(t *testing.T) {
		root := t.TempDir()
		dirA, dirB := filepath.Join(root, "appsvc"), filepath.Join(root, "other")
		writeDescriptor(t, dirA, "tool.exe", fixtureDescriptor)
		if err := os.MkdirAll(dirB, 0700); err != nil {
			t.Fatal(err)
		}
		scan := discovery.Scan(root)
		if len(scan.Candidates) == 0 {
			t.Fatal("candidate missing")
		}
		candidate := scan.Candidates[0]
		candidate.CanonicalPath = dirB
		candidate.Path = "other"
		candidate.Fingerprint = [32]byte{1}
		scan.Candidates = []discovery.Candidate{candidate}
		record := vault.Approval{Name: candidate.Name, Path: dirB, Hash: hex.EncodeToString(candidate.Fingerprint[:])}
		apps, statuses, err := Approved(scan, []vault.Approval{record}, nil)
		if err != nil || len(apps) != 0 || len(statuses) != 1 || statuses[0].Kind != "changed" {
			t.Fatalf("got apps=%v statuses=%v err=%v", apps, statuses, err)
		}
	})
	t.Run("overflow_activates_nothing", func(t *testing.T) {
		_, _, _, record := fixtureScan(t, "appsvc")
		apps, statuses, err := Approved(discovery.Result{Overflow: true, OverflowReason: "entry_cap_overflow"}, []vault.Approval{record}, nil)
		if err != nil || len(apps) != 0 || len(statuses) != 1 || statuses[0].Kind != "overflow" {
			t.Fatalf("got apps=%v statuses=%v err=%v", apps, statuses, err)
		}
	})
	t.Run("overflow_with_zero_approvals_keeps_explicit_start", func(t *testing.T) {
		explicit := []application.App{{Name: "explicit-00", Directory: filepath.Join(t.TempDir(), "exp00")}}
		apps, statuses, err := Approved(discovery.Result{Overflow: true, OverflowReason: "candidate_cap_overflow"}, nil, explicit)
		if err != nil || len(apps) != 0 || len(statuses) != 1 || statuses[0].Kind != "overflow" {
			t.Fatalf("got apps=%v statuses=%v err=%v", apps, statuses, err)
		}
	})
	t.Run("combined_cap_refuses_without_truncation", func(t *testing.T) {
		root, scan, _, first := fixtureScan(t, "appsvc")
		secondDir := filepath.Join(root, "other")
		writeDescriptor(t, secondDir, "tool.exe", strings.Replace(fixtureDescriptor, `"appsvc"`, `"otherapp"`, 1))
		scan = discovery.Scan(root)
		approvals := []vault.Approval{first}
		for _, candidate := range scan.Candidates {
			if candidate.Name == "otherapp" {
				approvals = append(approvals, vault.Approval{Name: candidate.Name, Path: candidate.CanonicalPath, Hash: hex.EncodeToString(candidate.Fingerprint[:])})
			}
		}
		explicit := make([]application.App, application.MaxApplications-1)
		for i := range explicit {
			explicit[i] = application.App{Name: fmt.Sprintf("explicit-%02d", i), Directory: filepath.Join(root, fmt.Sprintf("exp%02d", i))}
		}
		apps, statuses, err := Approved(scan, approvals, explicit)
		if err != nil || len(apps) != 0 || len(statuses) != 1 || statuses[0].Kind != "cap_overflow_refused" {
			t.Fatalf("got apps=%v statuses=%v err=%v", apps, statuses, err)
		}
	})
	t.Run("name_collision_fails_closed_for_collision", func(t *testing.T) {
		_, scan, _, record := fixtureScan(t, "appsvc")
		explicit := []application.App{{Name: "appsvc", Directory: filepath.Join(t.TempDir(), "other")}}
		apps, statuses, err := Approved(scan, []vault.Approval{record}, explicit)
		if err != nil || len(apps) != 0 || len(statuses) != 1 || statuses[0].Kind != "collision_refused" || statuses[0].Name != "appsvc" {
			t.Fatalf("got apps=%v statuses=%v err=%v", apps, statuses, err)
		}
	})
	t.Run("collision_between_two_discovered_approved_registers_neither", func(t *testing.T) {
		_, scan, candidate, record := fixtureScan(t, "appsvc")
		duplicate := candidate
		duplicate.Path = "other"
		scan.Candidates = []discovery.Candidate{candidate, duplicate}
		apps, statuses, err := Approved(scan, []vault.Approval{record}, nil)
		if err != nil || len(apps) != 0 || len(statuses) != 2 {
			t.Fatalf("got apps=%v statuses=%v err=%v", apps, statuses, err)
		}
		for _, status := range statuses {
			if status.Kind != "collision_refused" || status.Name != "appsvc" {
				t.Fatalf("unexpected status: %#v", status)
			}
		}
	})
	t.Run("non_colliding_discovered_still_registers_next_to_collision", func(t *testing.T) {
		root, _, _, first := fixtureScan(t, "appsvc")
		secondDir := filepath.Join(root, "other")
		writeDescriptor(t, secondDir, "tool.exe", strings.Replace(fixtureDescriptor, `"appsvc"`, `"otherapp"`, 1))
		scan := discovery.Scan(root)
		approvals := make([]vault.Approval, 0, len(scan.Candidates))
		for _, candidate := range scan.Candidates {
			approvals = append(approvals, vault.Approval{Name: candidate.Name, Path: candidate.CanonicalPath, Hash: hex.EncodeToString(candidate.Fingerprint[:])})
		}
		explicit := []application.App{{Name: "appsvc", Directory: filepath.Join(t.TempDir(), "elsewhere")}}
		apps, statuses, err := Approved(scan, append([]vault.Approval{first}, approvals...), explicit)
		if err != nil || len(apps) != 1 || apps[0].Name != "otherapp" {
			t.Fatalf("got apps=%v statuses=%v err=%v", apps, statuses, err)
		}
		foundCollision, foundEnabled := false, false
		for _, status := range statuses {
			if status.Kind == "collision_refused" && status.Name == "appsvc" {
				foundCollision = true
			}
			if status.Kind == "enabled" && status.Name == "otherapp" {
				foundEnabled = true
			}
		}
		if !foundCollision || !foundEnabled {
			t.Fatalf("missing expected statuses: %#v", statuses)
		}
	})
	t.Run("unapproved_candidates_never_block_explicit", func(t *testing.T) {
		_, scan, _, _ := fixtureScan(t, "appsvc")
		explicit := []application.App{{Name: "appsvc", Directory: filepath.Join(t.TempDir(), "other")}}
		apps, _, err := Approved(scan, nil, explicit)
		if err != nil || len(apps) != 0 {
			t.Fatalf("got apps=%v err=%v", apps, err)
		}
	})
	t.Run("approval_without_matching_candidate_only_reported", func(t *testing.T) {
		apps, statuses, err := Approved(discovery.Result{}, []vault.Approval{{Name: "ghost"}}, nil)
		if err != nil || len(apps) != 0 || len(statuses) != 1 || statuses[0].Kind != "absent" || statuses[0].Name != "ghost" {
			t.Fatalf("got apps=%v statuses=%v err=%v", apps, statuses, err)
		}
	})
	t.Run("canonical_dedupe_does_not_double_register", func(t *testing.T) {
		_, scan, candidate, record := fixtureScan(t, "appsvc")
		explicit := []application.App{{Name: "appsvc", Directory: candidate.CanonicalPath}}
		apps, statuses, err := Approved(scan, []vault.Approval{record}, explicit)
		if err != nil || len(apps) != 0 || len(statuses) != 1 || statuses[0].Kind != "enabled" {
			t.Fatalf("got apps=%v statuses=%v err=%v", apps, statuses, err)
		}
	})
	t.Run("zero_approvals_unchanged_behavior", func(t *testing.T) {
		apps, statuses, err := Approved(discovery.Scan(t.TempDir()), nil, nil)
		if err != nil || len(apps) != 0 || len(statuses) != 0 {
			t.Fatalf("got apps=%v statuses=%v err=%v", apps, statuses, err)
		}
	})
}

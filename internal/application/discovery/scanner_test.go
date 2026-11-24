package discovery

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/application"
	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
)

func TestScanRootAndImmediateChildren(t *testing.T) {
	t.Run("root child grandchild", func(t *testing.T) {
		root := t.TempDir()
		writeDescriptor(t, root, "root")
		writeDescriptor(t, filepath.Join(root, "child"), "child")
		writeDescriptor(t, filepath.Join(root, "child", "grandchild"), "grandchild")
		got := Scan(root)
		if len(got.Candidates) != 2 || !reflect.DeepEqual(paths(got.Candidates), []string{".", "child"}) {
			t.Fatalf("candidate_count=%d", len(got.Candidates))
		}
	})
	t.Run("normalized sort through scan", func(t *testing.T) {
		root := t.TempDir()
		for _, name := range []string{"z", "a", "m"} {
			writeDescriptor(t, filepath.Join(root, name), name)
		}
		got := Scan(root)
		if !reflect.DeepEqual(paths(got.Candidates), []string{"a", "m", "z"}) {
			t.Fatalf("candidate_count=%d", len(got.Candidates))
		}
	})
	t.Run("hardcoded ignored directory basenames", func(t *testing.T) {
		root := t.TempDir()
		for _, name := range []string{".git", ".hg", ".svn", "node_modules", "vendor", "target", "dist", "build", ".cache", ".next", ".venv", "venv", "__pycache__"} {
			writeDescriptor(t, filepath.Join(root, name), "ignored")
		}
		writeDescriptor(t, filepath.Join(root, "ordinary"), "included")
		got := Scan(root)
		if !reflect.DeepEqual(paths(got.Candidates), []string{"ordinary"}) {
			t.Fatalf("candidate_count=%d", len(got.Candidates))
		}
	})
	t.Run("platform case semantics", func(t *testing.T) {
		root := t.TempDir()
		writeDescriptor(t, filepath.Join(root, "VENDOR"), "ignored")
		got := Scan(root)
		if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
			if len(got.Candidates) != 0 {
				t.Fatalf("candidate_count=%d", len(got.Candidates))
			}
			return
		}
		if !reflect.DeepEqual(paths(got.Candidates), []string{"VENDOR"}) {
			t.Fatalf("candidate_count=%d", len(got.Candidates))
		}
	})
}

func TestScanEntryAndCandidateCaps(t *testing.T) {
	runEntryCapCase := func(t *testing.T, entries int, rootDesc, overflow bool) {
		t.Helper()
		root := t.TempDir()
		if rootDesc {
			writeDescriptor(t, root, "root")
		}
		writeDescriptor(t, filepath.Join(root, "valid-child"), "child")
		for i := 0; i < entries-1; i++ {
			if err := os.WriteFile(filepath.Join(root, fmtName(i)), []byte("x"), 0600); err != nil {
				t.Fatal("fixture_write_failed")
			}
		}
		got := Scan(root)
		if overflow {
			if !got.Overflow || got.OverflowReason != "entry_cap_overflow" || len(got.Candidates) != 0 {
				t.Fatalf("overflow=%t reason=%q candidate_count=%d", got.Overflow, got.OverflowReason, len(got.Candidates))
			}
			return
		}
		want := []string{"valid-child"}
		if rootDesc {
			want = []string{".", "valid-child"}
		}
		if got.Overflow || !reflect.DeepEqual(paths(got.Candidates), want) {
			t.Fatalf("overflow=%t reason=%q candidate_count=%d", got.Overflow, got.OverflowReason, len(got.Candidates))
		}
	}
	t.Run("256 entries without root descriptor", func(t *testing.T) { runEntryCapCase(t, 256, false, false) })
	t.Run("257 entries without root descriptor", func(t *testing.T) { runEntryCapCase(t, 257, false, true) })
	t.Run("256 entries with root descriptor", func(t *testing.T) { runEntryCapCase(t, 256, true, false) })
	t.Run("257 entries with root descriptor", func(t *testing.T) { runEntryCapCase(t, 257, true, true) })
	t.Run("exactly 16 candidates succeeds", func(t *testing.T) {
		root := t.TempDir()
		for i := 0; i < 16; i++ {
			writeDescriptor(t, filepath.Join(root, fmtName(i)), fmtName(i))
		}
		got := Scan(root)
		if got.Overflow || len(got.Candidates) != 16 {
			t.Fatalf("overflow=%t reason=%q candidate_count=%d", got.Overflow, got.OverflowReason, len(got.Candidates))
		}
	})
	t.Run("17 candidates overflow without partial result", func(t *testing.T) {
		root := t.TempDir()
		writeDescriptor(t, root, "zero")
		for i := 0; i < 16; i++ {
			writeDescriptor(t, filepath.Join(root, fmtName(i)), fmtName(i))
		}
		got := Scan(root)
		if !got.Overflow || got.OverflowReason != "candidate_cap_overflow" || len(got.Candidates) != 0 {
			t.Fatalf("overflow=%t reason=%q candidate_count=%d", got.Overflow, got.OverflowReason, len(got.Candidates))
		}
	})
}

func TestScanDiagnosticsAndCollisions(t *testing.T) {
	t.Run("diagnostic cap and summary", func(t *testing.T) {
		root := t.TempDir()
		for i := 0; i < 22; i++ {
			if err := os.Mkdir(filepath.Join(root, fmtName(i)), 0700); err != nil {
				t.Fatal("fixture_mkdir_failed")
			}
		}
		got := Scan(root)
		if len(got.Diagnostics) != 17 || got.Diagnostics[16].Reason != "additional_rejections" {
			reason := ""
			if len(got.Diagnostics) > 16 {
				reason = got.Diagnostics[16].Reason
			}
			t.Fatalf("diagnostic_count=%d summary_reason=%q", len(got.Diagnostics), reason)
		}
	})
	t.Run("diagnostic selection deterministic order", func(t *testing.T) {
		entries := []Diagnostic{
			{Path: "zeta", Reason: "entry_unsafe"}, {Path: "alpha", Reason: "descriptor_missing"},
			{Path: "gamma", Reason: "descriptor_invalid"}, {Path: "beta", Reason: "entry_inaccessible"},
			{Path: "delta", Reason: "descriptor_unsafe"}, {Path: "epsilon", Reason: "descriptor_oversize"},
			{Path: "eta", Reason: "descriptor_inaccessible"}, {Path: "theta", Reason: "entry_unsafe"},
			{Path: "iota", Reason: "descriptor_missing"}, {Path: "kappa", Reason: "descriptor_invalid"},
			{Path: "lambda", Reason: "entry_inaccessible"}, {Path: "mu", Reason: "descriptor_unsafe"},
			{Path: "nu", Reason: "descriptor_oversize"}, {Path: "xi", Reason: "descriptor_inaccessible"},
			{Path: "omicron", Reason: "entry_unsafe"}, {Path: "pi", Reason: "descriptor_missing"},
			{Path: "rho", Reason: "descriptor_invalid"},
		}
		collect := func(order []Diagnostic) []Diagnostic {
			result := Result{Candidates: []Candidate{}, Diagnostics: []Diagnostic{}}
			for _, diagnostic := range order {
				addDiagnostic(&result, diagnostic.Path, diagnostic.Reason)
			}
			finish(&result)
			return result.Diagnostics
		}
		first := collect(entries)
		reversed := append([]Diagnostic(nil), entries...)
		for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
			reversed[i], reversed[j] = reversed[j], reversed[i]
		}
		second := collect(reversed)
		if !reflect.DeepEqual(first, second) {
			differentAt := -1
			limit := len(first)
			if len(second) < limit {
				limit = len(second)
			}
			for i := 0; i < limit; i++ {
				if first[i] != second[i] {
					differentAt = i
					break
				}
			}
			t.Fatalf("diagnostic_count=%d,%d first_difference_offset=%d", len(first), len(second), differentAt)
		}
		if len(first) != 17 || first[16].Reason != "additional_rejections" {
			reason := ""
			if len(first) > 16 {
				reason = first[16].Reason
			}
			t.Fatalf("diagnostic_count=%d summary_reason=%q", len(first), reason)
		}
		for i, diagnostic := range first[:16] {
			if diagnostic.Path == "" || diagnostic.Reason == "" || diagnostic.Reason == "additional_rejections" {
				t.Fatalf("diagnostic_offset=%d path_present=%t reason=%q", i, diagnostic.Path != "", diagnostic.Reason)
			}
		}
	})
	t.Run("collision status", func(t *testing.T) {
		root := t.TempDir()
		writeDescriptor(t, filepath.Join(root, "a"), "same")
		writeDescriptor(t, filepath.Join(root, "b"), "same")
		got := Scan(root)
		if len(got.Candidates) < 2 || !got.Candidates[0].Collision || !got.Candidates[1].Collision {
			var first, second bool
			if len(got.Candidates) > 0 {
				first = got.Candidates[0].Collision
			}
			if len(got.Candidates) > 1 {
				second = got.Candidates[1].Collision
			}
			t.Fatalf("candidate_count=%d collisions=%t,%t", len(got.Candidates), first, second)
		}
	})
}

func TestRootPathStillMatches(t *testing.T) {
	t.Run("unchanged root matches", func(t *testing.T) {
		path := t.TempDir()
		root, err := os.OpenRoot(path)
		if err != nil {
			t.Fatal("fixture_root_open_failed")
		}
		defer root.Close()
		identity, err := root.Stat(".")
		if err != nil {
			t.Fatal("fixture_stat_failed")
		}
		if !rootPathStillMatches(path, identity) {
			t.Fatal("root_identity_matches=false")
		}
	})
	t.Run("replacement root does not match", func(t *testing.T) {
		parent := t.TempDir()
		path := filepath.Join(parent, "root")
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal("fixture_mkdir_failed")
		}
		root, err := os.OpenRoot(path)
		if err != nil {
			t.Fatal("fixture_root_open_failed")
		}
		defer root.Close()
		identity, err := root.Stat(".")
		if err != nil {
			t.Fatal("fixture_stat_failed")
		}
		moved := filepath.Join(parent, "moved")
		if err := os.Rename(path, moved); err != nil {
			t.Skip("root_replacement_unavailable")
		}
		if err := os.Mkdir(path, 0700); err != nil {
			t.Skip("root_replacement_unavailable")
		}
		if rootPathStillMatches(path, identity) {
			t.Fatal("root_identity_matches=true")
		}
	})
}

func TestCanonicalDirectoryIdentity(t *testing.T) {
	t.Run("addCandidate deduplicates two path spellings", func(t *testing.T) {
		path := t.TempDir()
		writeDescriptor(t, path, "same")
		firstRoot, err := os.OpenRoot(path)
		if err != nil {
			t.Fatal("fixture_root_open_failed")
		}
		defer firstRoot.Close()
		secondRoot, err := os.OpenRoot(path + string(filepath.Separator) + ".")
		if err != nil {
			t.Fatal("fixture_root_open_failed")
		}
		defer secondRoot.Close()
		firstIdentity, err := firstRoot.Stat(".")
		if err != nil {
			t.Fatal("fixture_stat_failed")
		}
		secondIdentity, err := secondRoot.Stat(".")
		if err != nil {
			t.Fatal("fixture_stat_failed")
		}
		seen := []directoryIdentity{}
		result := Result{Candidates: []Candidate{}, Diagnostics: []Diagnostic{}}
		addCandidateFromRoot(&result, path, firstRoot, firstIdentity, "first", &seen, nil)
		addCandidateFromRoot(&result, path, secondRoot, secondIdentity, "duplicate", &seen, nil)
		if len(result.Candidates) != 1 {
			t.Fatalf("candidate_count=%d", len(result.Candidates))
		}
	})
	t.Run("case-only distinct directories retain identities", func(t *testing.T) {
		root := t.TempDir()
		upper := filepath.Join(root, "Case")
		lower := filepath.Join(root, "case")
		if err := os.Mkdir(upper, 0700); err != nil {
			t.Skip("case_only_directories_unavailable")
		}
		if err := os.Mkdir(lower, 0700); err != nil {
			t.Skip("case_only_directories_unavailable")
		}
		if os.SameFile(mustStat(t, upper), mustStat(t, lower)) {
			t.Skip("case_only_directories_alias")
		}
		writeDescriptor(t, upper, "upper")
		writeDescriptor(t, lower, "lower")
		got := Scan(root)
		if !reflect.DeepEqual(paths(got.Candidates), []string{"Case", "case"}) {
			t.Fatalf("candidate_count=%d", len(got.Candidates))
		}
	})
}

func TestFinishSortsCandidates(t *testing.T) {
	t.Run("direct finish sorts unsorted candidates", func(t *testing.T) {
		result := Result{Candidates: []Candidate{
			{Path: "z-child", Name: "z"}, {Path: "m-child", Name: "m"},
			{Path: ".", Name: "root"}, {Path: "a-child", Name: "a"},
		}}
		finish(&result)
		want := []string{".", "a-child", "m-child", "z-child"}
		if !reflect.DeepEqual(paths(result.Candidates), want) {
			t.Fatalf("candidate_count=%d", len(result.Candidates))
		}
	})
}

func mustStat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal("fixture_stat_failed")
	}
	return info
}

func TestScanRejectsControlFilename(t *testing.T) {
	t.Run("unsafe C1 path is omitted", func(t *testing.T) {
		root := t.TempDir()
		unsafeName := "unsafe\u0085name"
		if err := os.Mkdir(filepath.Join(root, unsafeName), 0700); err != nil {
			t.Skip("c1_fixture_unavailable")
		}
		got := Scan(root)
		found := false
		for _, diagnostic := range got.Diagnostics {
			if diagnostic.Reason == "path_unsafe" {
				found = true
				if diagnostic.Path != "" {
					t.Fatalf("reason=path_unsafe path_present=true")
				}
			}
		}
		if !found {
			t.Fatal("reason=path_unsafe_missing")
		}
	})
}

func TestScanRejectsLinksAndBoundsDescriptor(t *testing.T) {
	t.Run("directory symlink rejected with target retained once", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "real")
		writeDescriptor(t, target, "linked")
		if err := os.Symlink(target, filepath.Join(root, "linked")); err != nil {
			t.Skip("symlink_unavailable")
		}
		got := Scan(root)
		if !reflect.DeepEqual(paths(got.Candidates), []string{"real"}) {
			t.Fatalf("candidate_count=%d", len(got.Candidates))
		}
		count := 0
		for _, diagnostic := range got.Diagnostics {
			if diagnostic.Path == "linked" && diagnostic.Reason == "entry_unsafe" {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("reason=entry_unsafe diagnostic_count=%d", count)
		}
	})
	t.Run("descriptor symlink rejected with target retained once", func(t *testing.T) {
		root := t.TempDir()
		writeDescriptor(t, filepath.Join(root, "real"), "safe")
		if err := os.Symlink(filepath.Join(root, "real", "ssjack-app.json"), filepath.Join(root, "ssjack-app.json")); err != nil {
			t.Skip("symlink_unavailable")
		}
		got := Scan(root)
		if !reflect.DeepEqual(paths(got.Candidates), []string{"real"}) {
			t.Fatalf("candidate_count=%d", len(got.Candidates))
		}
		count := 0
		for _, diagnostic := range got.Diagnostics {
			if diagnostic.Path == "." && diagnostic.Reason == "descriptor_unsafe" {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("reason=descriptor_unsafe diagnostic_count=%d", count)
		}
	})
	t.Run("route field rejected", func(t *testing.T) {
		root := t.TempDir()
		data := []byte(`{"format":"ssjack-app-v1","name":"route","launch":{"executable":"/not-run"},"route":"file"}`)
		if err := os.WriteFile(filepath.Join(root, "ssjack-app.json"), data, 0600); err != nil {
			t.Fatal("fixture_write_failed")
		}
		got := Scan(root)
		if len(got.Candidates) != 0 || !hasReason(got, "descriptor_invalid") {
			t.Fatalf("candidate_count=%d reason=descriptor_invalid_present:%t", len(got.Candidates), hasReason(got, "descriptor_invalid"))
		}
	})
	t.Run("planted fixture is never run", func(t *testing.T) {
		root := t.TempDir()
		marker := filepath.Join(root, "marker")
		t.Setenv("SSJACK_DISCOVERY_HELPER", marker)
		data, err := json.Marshal(map[string]any{"format": "ssjack-app-v1", "name": "planted", "launch": map[string]any{"executable": os.Args[0], "args": []string{"-test.run=TestDiscoveryHelperProcess"}}, "workdir": "."})
		if err != nil {
			t.Fatal("fixture_marshal_failed")
		}
		if err := os.WriteFile(filepath.Join(root, "ssjack-app.json"), data, 0600); err != nil {
			t.Fatal("fixture_write_failed")
		}
		got := Scan(root)
		if len(got.Candidates) != 1 {
			t.Fatalf("candidate_count=%d", len(got.Candidates))
		}
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatal("fixture_execution_detected")
		}
	})
	t.Run("exactly 16KiB descriptor accepted", func(t *testing.T) {
		root := t.TempDir()
		data, err := json.Marshal(map[string]any{"format": "ssjack-app-v1", "name": "sized", "launch": map[string]any{"executable": "/not-run"}})
		if err != nil {
			t.Fatal("fixture_marshal_failed")
		}
		data = append(data, []byte(strings.Repeat(" ", maxDescriptor-len(data)))...)
		if err := os.WriteFile(filepath.Join(root, "ssjack-app.json"), data, 0600); err != nil {
			t.Fatal("fixture_write_failed")
		}
		got := Scan(root)
		if !reflect.DeepEqual(paths(got.Candidates), []string{"."}) {
			t.Fatalf("candidate_count=%d", len(got.Candidates))
		}
	})
	t.Run("16KiB plus one reports oversize", func(t *testing.T) {
		root := t.TempDir()
		data, err := json.Marshal(map[string]any{"format": "ssjack-app-v1", "name": "sized", "launch": map[string]any{"executable": "/not-run"}})
		if err != nil {
			t.Fatal("fixture_marshal_failed")
		}
		data = append(data, []byte(strings.Repeat(" ", maxDescriptor+1-len(data)))...)
		if err := os.WriteFile(filepath.Join(root, "ssjack-app.json"), data, 0600); err != nil {
			t.Fatal("fixture_write_failed")
		}
		got := Scan(root)
		if !hasReason(got, "descriptor_oversize") {
			t.Fatal("reason=descriptor_oversize_missing")
		}
	})
}

func TestCandidateFingerprintAndBuffer(t *testing.T) {
	t.Run("buffer hash and parse from one read", func(t *testing.T) {
		root := t.TempDir()
		child := filepath.Join(root, "probe")
		if err := os.Mkdir(child, 0700); err != nil {
			t.Fatal("fixture_mkdir_failed")
		}
		original := []byte(fmt.Sprintf(`{"format":"ssjack-app-v1","name":"probe","launch":{"executable":%q}}`, os.Args[0]))
		descriptor := filepath.Join(child, "ssjack-app.json")
		if err := os.WriteFile(descriptor, original, 0600); err != nil {
			t.Fatal("fixture_write_failed")
		}
		got := Scan(root)
		if len(got.Candidates) != 1 || got.Candidates[0].Path != "probe" {
			t.Fatalf("candidate_count=%d", len(got.Candidates))
		}
		candidate := got.Candidates[0]
		changed := []byte(fmt.Sprintf(`{"format":"ssjack-app-v1","name":"changed","launch":{"executable":%q}}`, os.Args[0]))
		if err := os.WriteFile(descriptor, changed, 0600); err != nil {
			t.Fatal("fixture_write_failed")
		}
		if !bytes.Equal(candidate.Buffer, original) {
			t.Fatal("candidate_buffer_mismatch")
		}
		fingerprint, ok := descriptorFingerprint(original)
		if !ok || candidate.Fingerprint != fingerprint {
			t.Fatal("candidate_fingerprint_mismatch")
		}
		app, err := application.ParseDescriptorBuffer(candidate.Buffer, candidate.CanonicalPath)
		if err != nil || app.Name != "probe" || app.Directory != candidate.CanonicalPath {
			t.Fatalf("buffer_parse_failed: name=%q directory_matches=%t err=%v", app.Name, app.Directory == candidate.CanonicalPath, err)
		}
	})
	t.Run("autocrlf style change keeps fingerprint", func(t *testing.T) {
		root := t.TempDir()
		plain := []byte(`{"format":"ssjack-app-v1","name":"same","launch":{"executable":"/not-run"}}`)
		crlf := []byte("{\r\n  \"format\" : \"ssjack-app-v1\",\r\n  \"name\" : \"same\",\r\n  \"launch\" : {\"executable\":\"/not-run\"}\r\n}")
		for name, data := range map[string][]byte{"plain": plain, "crlf": crlf} {
			dir := filepath.Join(root, name)
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal("fixture_mkdir_failed")
			}
			if err := os.WriteFile(filepath.Join(dir, "ssjack-app.json"), data, 0600); err != nil {
				t.Fatal("fixture_write_failed")
			}
		}
		got := Scan(root)
		if len(got.Candidates) != 2 || got.Candidates[0].Fingerprint != got.Candidates[1].Fingerprint || bytes.Equal(got.Candidates[0].Buffer, got.Candidates[1].Buffer) {
			t.Fatal("canonical_fingerprint_mismatch")
		}
	})
	t.Run("meaningful byte change changes fingerprint", func(t *testing.T) {
		plain := []byte(`{"format":"ssjack-app-v1","name":"same","launch":{"executable":"/not-run"}}`)
		changed := []byte(`{"format":"ssjack-app-v1","name":"other","launch":{"executable":"/not-run"}}`)
		plainFingerprint, plainOK := descriptorFingerprint(plain)
		changedFingerprint, changedOK := descriptorFingerprint(changed)
		if !plainOK || !changedOK || plainFingerprint == changedFingerprint {
			t.Fatal("meaningful_change_fingerprint_unchanged")
		}
	})
	t.Run("duplicate keys rejected through scan validation", func(t *testing.T) {
		data := []byte(`{"format":"ssjack-app-v1","name":"dup","name":"dup","launch":{"executable":"/not-run"}}`)
		if _, err := canonicaljson.Canonicalize(data); err == nil {
			t.Fatal("duplicate_keys_canonicalized")
		}
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "ssjack-app.json"), data, 0600); err != nil {
			t.Fatal("fixture_write_failed")
		}
		got := Scan(root)
		if len(got.Candidates) != 0 || !hasReason(got, "descriptor_invalid") {
			t.Fatal("duplicate_descriptor_not_rejected")
		}
	})
	t.Run("non canonicalizable descriptor is rejected", func(t *testing.T) {
		data := []byte(`{"format":"ssjack-app-v1","name":"decomposed","launch":{"executable":"/not-run","args":["cafe\u0301"]}}`)
		if _, err := application.ValidateDiscoveryDescriptor(data); err != nil {
			t.Skip("fixture_not_valid_per_descriptor_validator")
		}
		if _, err := canonicaljson.Canonicalize(data); err == nil {
			t.Skip("canonicalizer_accepts_fixture")
		}
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "ssjack-app.json"), data, 0600); err != nil {
			t.Fatal("fixture_write_failed")
		}
		got := Scan(root)
		if len(got.Candidates) != 0 || !hasReason(got, "fingerprint_unavailable") {
			t.Fatalf("candidate_count=%d fingerprint_unavailable_present=%t", len(got.Candidates), hasReason(got, "fingerprint_unavailable"))
		}
		if len(got.Diagnostics) != 1 || got.Diagnostics[0].Path != "." {
			t.Fatalf("diagnostic_count=%d root_path_present=%t", len(got.Diagnostics), len(got.Diagnostics) == 1 && got.Diagnostics[0].Path == ".")
		}
	})
}

func TestScanRootSymlinkResolved(t *testing.T) {
	t.Run("symlink root is resolved and scanned", func(t *testing.T) {
		parent := t.TempDir()
		real := filepath.Join(parent, "ordinary")
		writeDescriptor(t, real, "realroot")
		link := filepath.Join(parent, "linkroot")
		if err := os.Symlink(real, link); err != nil {
			t.Skip("symlink_unavailable")
		}
		got := Scan(link)
		if hasReason(got, "root_unsafe") || len(got.Candidates) != 1 || got.Candidates[0].Path != "." {
			t.Fatalf("candidate_count=%d root_unsafe=%t", len(got.Candidates), hasReason(got, "root_unsafe"))
		}
		want, err := filepath.EvalSymlinks(real)
		if err != nil {
			t.Fatal("fixture_resolve_failed")
		}
		actual := got.Candidates[0].CanonicalPath
		if filepath.Clean(actual) != filepath.Clean(want) {
			t.Fatalf("canonical_path_matches=%t", filepath.Clean(actual) == filepath.Clean(want))
		}
	})
	t.Run("links among children of a resolved root still rejected", func(t *testing.T) {
		parent := t.TempDir()
		real := filepath.Join(parent, "ordinary")
		writeDescriptor(t, filepath.Join(real, "real"), "real")
		link := filepath.Join(parent, "linkroot")
		if err := os.Symlink(real, link); err != nil {
			t.Skip("symlink_unavailable")
		}
		if err := os.Symlink(filepath.Join(real, "real"), filepath.Join(real, "linked")); err != nil {
			t.Skip("symlink_unavailable")
		}
		got := Scan(link)
		if !reflect.DeepEqual(paths(got.Candidates), []string{"real"}) {
			t.Fatalf("candidate_count=%d", len(got.Candidates))
		}
		count := 0
		for _, diagnostic := range got.Diagnostics {
			if diagnostic.Path == "linked" && diagnostic.Reason == "entry_unsafe" {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("linked_entry_unsafe_count=%d", count)
		}
	})
}

func TestDiscoveryHelperProcess(t *testing.T) {
	if os.Getenv("SSJACK_DISCOVERY_HELPER") == "" {
		return
	}
	_ = os.WriteFile(os.Getenv("SSJACK_DISCOVERY_HELPER"), []byte("ran"), 0600)
}

func writeDescriptor(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal("fixture_mkdir_failed")
	}
	data, err := json.Marshal(map[string]any{"format": "ssjack-app-v1", "name": name, "launch": map[string]any{"executable": "/not-run"}})
	if err != nil {
		t.Fatal("fixture_marshal_failed")
	}
	if err = os.WriteFile(filepath.Join(dir, "ssjack-app.json"), data, 0600); err != nil {
		t.Fatal("fixture_write_failed")
	}
}

func paths(c []Candidate) []string {
	out := make([]string, len(c))
	for i := range c {
		out[i] = c[i].Path
	}
	return out
}

func fmtName(i int) string {
	return fmt.Sprintf("entry-%03d", i)
}

func hasReason(r Result, reason string) bool {
	for _, d := range r.Diagnostics {
		if d.Reason == reason {
			return true
		}
	}
	return false
}

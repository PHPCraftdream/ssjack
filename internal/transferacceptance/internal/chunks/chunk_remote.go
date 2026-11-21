//go:build linux || darwin

package chunks

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/PHPCraftdream/ssjack/internal/flakediag"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/sshauth"
	fixture "github.com/PHPCraftdream/ssjack/internal/transferacceptance/internal/fixture"
	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlink"
	"github.com/PHPCraftdream/ssjack/internal/transferremote"
)

// The chunks package holds the chunked-mode acceptance scenarios as ordinary
// (non-test) tagged source so the root transferacceptance test package can
// register them under their stable CI subtest names without growing past the
// allowed root file budget. Only the sandbox environment builder lives in
// the root test harness (it must stay verbatim there); it is injected below.

// SandboxEnv builds the sandbox environment for the fixture exec server.
// It is injected by the root acceptance test package.
var SandboxEnv func(t *testing.T, env []string) []string

// evalDir creates and returns a fresh temporary directory for one side of a
// scenario (symlinks resolved, as the sandbox paths must be real).
func evalDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

// mkdirAll creates a directory and fails the test on error.
func mkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

// assertSHA asserts a sha256 digest reported in transfer status output.
func assertSHA(t *testing.T, payload []byte, got string) {
	t.Helper()
	sum := sha256.Sum256(payload)
	want := hex.EncodeToString(sum[:])
	if got != want {
		t.Fatalf("status sha256 does not match transferred bytes: got len=%d short=%s, want len=%d short=%s", len(got), flakediag.Short([]byte(got)), len(want), flakediag.Short([]byte(want)))
	}
}

// targetName mirrors the root harness target constant: the chunk scenarios
// register the same fixture target name as the manager-driven ones.
const targetName = "fixture-target"

// chunkRig runs the chunked-mode remote command layer against the real SSH
// exec fixture: every template executes under the sandbox userland (GNU,
// BusyBox applets or stock macOS tools), not under a fake.
type chunkRig struct {
	t       *testing.T
	sandbox string
	server  *fixture.ExecServer
	remote  transferremote.ChunkRemote
}

func newChunkRig(t *testing.T, limits transfercore.Limits) *chunkRig {
	t.Helper()
	sandbox := evalDir(t)
	server := fixture.StartExecServer(t, sandbox, SandboxEnv(t, nil))
	config := &ssh.ClientConfig{
		User:            "acceptance",
		Auth:            []ssh.AuthMethod{sshauth.PublicKey(server.ClientSigner())},
		HostKeyCallback: ssh.FixedHostKey(server.HostKey()),
		Timeout:         5 * time.Second,
	}
	runner, err := remote.NewCredentialStreamRunner(targetName, server.Address(), config)
	if err != nil {
		t.Fatal(err)
	}
	g := &chunkRig{t: t, sandbox: sandbox, server: server, remote: transferremote.NewChunk(runner, targetName, limits)}
	if err := g.remote.Probe(g.ctx()); err != nil {
		t.Fatalf("capability probe failed: %v", err)
	}
	return g
}

// ctx returns a bounded context for one remote call.
func (g *chunkRig) ctx() context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	g.t.Cleanup(cancel)
	return ctx
}

// dir creates a directory in the sandbox and returns its path.
func (g *chunkRig) dir(name string) string {
	path := filepath.Join(g.sandbox, name)
	mkdirAll(g.t, path)
	return path
}

func stageDir(parent, key string) string {
	return filepath.Join(parent, ".ssjack-transfer-"+key)
}

func chunkMarker(key string) string { return "SSJACK-STAGING 1 " + key + "\n" }

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func entryNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names
}

// describe renders an object (type, mode, link target, directory entries and
// file bytes, recursively) so a test can prove it was left untouched.
func describe(t *testing.T, path string) string {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		return "absent"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%v", info.Mode())
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		target, err := os.Readlink(path)
		if err != nil {
			t.Fatal(err)
		}
		b.WriteString(" -> " + target)
	case info.IsDir():
		for _, name := range entryNames(t, path) {
			b.WriteString("\n" + name + " " + describe(t, filepath.Join(path, name)))
		}
	case info.Mode().IsRegular():
		b.WriteString(" " + string(readFile(t, path)))
	}
	return b.String()
}

func assertMarker(t *testing.T, dir, key string) {
	t.Helper()
	got := string(readFile(t, filepath.Join(dir, "marker")))
	want := chunkMarker(key)
	if got != want {
		t.Fatalf("marker mismatch: got len=%d short=%s, want len=%d short=%s", len(got), flakediag.Short([]byte(got)), len(want), flakediag.Short([]byte(want)))
	}
}

func ensureCreated(t *testing.T, g *chunkRig, parent, key string) {
	t.Helper()
	state, err := g.remote.EnsureStaging(g.ctx(), parent, key)
	if err != nil || state != transferremote.StagingCreated {
		t.Fatalf("EnsureStaging = %v, %v; want created", state, err)
	}
}

func uploadPart(t *testing.T, g *chunkRig, parent, key string, part transferlink.Range, data []byte) transferremote.PartResult {
	t.Helper()
	res, err := g.remote.UploadPart(g.ctx(), parent, key, part, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("UploadPart %+v: %v", part, err)
	}
	return res
}

func partFile(dir string, part transferlink.Range) string {
	name, err := transferlink.PartName(part)
	if err != nil {
		panic(err)
	}
	return filepath.Join(dir, name)
}

func countAssembled(t *testing.T, dir string) int {
	t.Helper()
	n := 0
	for _, name := range entryNames(t, dir) {
		if strings.HasPrefix(name, "assembled.") {
			n++
		}
	}
	return n
}

// ScenarioChunkProbe checks the chunk capability line on the real userland.
func ScenarioChunkProbe(t *testing.T) {
	g := newChunkRig(t, transfercore.DefaultLimits())
	caps := g.remote.ChunkCaps()
	if !caps.Own {
		t.Fatalf("ownership and mode checks are not functional here: %+v", caps)
	}
	if caps.Read != transferremote.ReadDD {
		t.Fatalf("range read = %q, want dd on every supported userland: %+v", caps.Read, caps)
	}
	want := transferremote.MtimeGNU
	if runtime.GOOS == "darwin" {
		want = transferremote.MtimeBSD
	}
	if caps.Mtime != want {
		t.Fatalf("stat flavour = %q, want %q: %+v", caps.Mtime, want, caps)
	}
	if !caps.DF {
		t.Fatalf("df -P -k does not parse here: %+v", caps)
	}
	if !caps.Upload() || !caps.Download() {
		t.Fatalf("chunked directions unavailable: %+v", caps)
	}
}

// ScenarioChunkStagingLifecycle creates, reuses and removes a marked staging
// directory and proves foreign objects are reported but never used, written
// to or removed.
func ScenarioChunkStagingLifecycle(t *testing.T) {
	g := newChunkRig(t, transfercore.DefaultLimits())
	ctx := g.ctx()
	parent := g.dir("lifecycle parent it's ü ñ")
	key := transferremote.StagingKey("lifecycle", "own")
	dir := stageDir(parent, key)

	ensureCreated(t, g, parent, key)
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("staging directory = %v, %v; want a 0700 directory", info, err)
	}
	assertMarker(t, dir, key)
	state, err := g.remote.EnsureStaging(ctx, parent, key)
	if err != nil || state != transferremote.StagingReused {
		t.Fatalf("second EnsureStaging = %v, %v; want reused", state, err)
	}
	listing, err := g.remote.ListStaging(ctx, parent, key, 1000)
	if err != nil || len(listing.Parts) != 0 || len(listing.Remove) != 0 || listing.Overflow {
		t.Fatalf("empty staging listing = %+v, %v", listing, err)
	}

	// An absent staging directory: listing and upload report it, removal is
	// an idempotent success.
	missing := transferremote.StagingKey("lifecycle", "missing")
	if _, err := g.remote.ListStaging(ctx, parent, missing, 1000); !transferremote.IsStageMissing(err) {
		t.Fatalf("ListStaging on a missing staging = %v, want a missing-staging exit", err)
	}
	if _, err := g.remote.UploadPart(ctx, parent, missing, transferlink.Range{Off: 0, Len: 3}, strings.NewReader("abc")); !transferremote.IsStageMissing(err) {
		t.Fatalf("UploadPart on a missing staging = %v, want a missing-staging exit", err)
	}
	if err := g.remote.RemoveChunkStaging(ctx, parent, missing); err != nil {
		t.Fatalf("RemoveChunkStaging on a missing staging: %v", err)
	}

	foreign := []struct {
		name  string
		build func(path, key string)
	}{
		{"mode-0755", func(path, key string) {
			must(t, os.Mkdir(path, 0o700))
			writeFile(t, filepath.Join(path, "marker"), []byte(chunkMarker(key)))
			writeFile(t, filepath.Join(path, "part-0-1"), []byte("x"))
			must(t, os.Chmod(path, 0o755))
		}},
		{"no-marker", func(path, key string) {
			must(t, os.Mkdir(path, 0o700))
			writeFile(t, filepath.Join(path, "keep"), []byte("keep"))
		}},
		{"marker-of-another-key", func(path, key string) {
			must(t, os.Mkdir(path, 0o700))
			writeFile(t, filepath.Join(path, "marker"), []byte(chunkMarker(strings.Repeat("a", 32))))
			writeFile(t, filepath.Join(path, "part-0-1"), []byte("x"))
		}},
		{"marker-is-a-symlink", func(path, key string) {
			must(t, os.Mkdir(path, 0o700))
			real := filepath.Join(parent, "real-marker-"+key[:8])
			writeFile(t, real, []byte(chunkMarker(key)))
			must(t, os.Symlink(real, filepath.Join(path, "marker")))
		}},
		{"marker-is-a-directory", func(path, key string) {
			must(t, os.Mkdir(path, 0o700))
			must(t, os.Mkdir(filepath.Join(path, "marker"), 0o700))
		}},
		{"directory-symlink", func(path, key string) {
			real := filepath.Join(parent, "real-stage-"+key[:8])
			must(t, os.Mkdir(real, 0o700))
			writeFile(t, filepath.Join(real, "marker"), []byte(chunkMarker(key)))
			writeFile(t, filepath.Join(real, "part-0-1"), []byte("x"))
			must(t, os.Symlink(real, path))
		}},
		{"regular-file", func(path, key string) {
			writeFile(t, path, []byte("not a directory"))
		}},
	}
	for _, tc := range foreign {
		fkey := transferremote.StagingKey("lifecycle", tc.name)
		tc.build(stageDir(parent, fkey), fkey)
		before := describe(t, parent)
		state, err := g.remote.EnsureStaging(ctx, parent, fkey)
		if err != nil || state != transferremote.StagingForeign {
			t.Fatalf("%s: EnsureStaging = %v, %v; want foreign", tc.name, state, err)
		}
		if _, err := g.remote.ListStaging(ctx, parent, fkey, 1000); !transferremote.IsStageForeign(err) {
			t.Fatalf("%s: ListStaging = %v, want a foreign-staging exit", tc.name, err)
		}
		if _, err := g.remote.UploadPart(ctx, parent, fkey, transferlink.Range{Off: 0, Len: 3}, strings.NewReader("abc")); !transferremote.IsStageForeign(err) {
			t.Fatalf("%s: UploadPart = %v, want a foreign-staging exit", tc.name, err)
		}
		if err := g.remote.RemoveStagingEntries(ctx, parent, fkey, []string{"part-0-1"}); !transferremote.IsStageForeign(err) {
			t.Fatalf("%s: RemoveStagingEntries = %v, want a foreign-staging exit", tc.name, err)
		}
		if _, err := g.remote.AssembleStaging(ctx, parent, fkey, nil, 0, false); !transferremote.IsStageForeign(err) {
			t.Fatalf("%s: AssembleStaging = %v, want a foreign-staging exit", tc.name, err)
		}
		if err := g.remote.RemoveChunkStaging(ctx, parent, fkey); !transferremote.IsStageForeign(err) {
			t.Fatalf("%s: RemoveChunkStaging = %v, want a foreign-staging exit", tc.name, err)
		}
		if after := describe(t, parent); after != before {
			t.Fatalf("%s: a foreign object changed", tc.name)
		}
	}

	if err := g.remote.RemoveChunkStaging(ctx, parent, key); err != nil {
		t.Fatalf("RemoveChunkStaging: %v", err)
	}
	if exists(dir) {
		t.Fatal("RemoveChunkStaging left the staging directory")
	}
	if err := g.remote.RemoveChunkStaging(ctx, parent, key); err != nil {
		t.Fatalf("second RemoveChunkStaging: %v", err)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// ScenarioChunkPartsAndListing uploads parts with exact and short lengths and
// lists a staging directory holding junk, overlapping, wrong-size and
// over-long entries.
func ScenarioChunkPartsAndListing(t *testing.T) {
	g := newChunkRig(t, transfercore.DefaultLimits())
	ctx := g.ctx()
	parent := g.dir("parts parent it's ü ñ")
	key := transferremote.StagingKey("parts")
	dir := stageDir(parent, key)
	ensureCreated(t, g, parent, key)
	payload := fixture.SeedPayload(1000, 31)

	res := uploadPart(t, g, parent, key, transferlink.Range{Off: 0, Len: 100}, payload[:100])
	if !res.Stored || res.Count != 100 {
		t.Fatalf("exact part = %+v, want stored with 100 bytes", res)
	}
	if got := readFile(t, filepath.Join(dir, "part-0-100")); !bytes.Equal(got, payload[:100]) {
		t.Fatal("stored part differs from the uploaded bytes")
	}
	if info, err := os.Stat(filepath.Join(dir, "part-0-100")); err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("part mode = %v, %v; want private", info, err)
	}

	// A completed part refreshes the marker's modification time.
	marker := filepath.Join(dir, "marker")
	old := time.Now().Add(-72 * time.Hour)
	must(t, os.Chtimes(marker, old, old))
	res = uploadPart(t, g, parent, key, transferlink.Range{Off: 100, Len: 100}, payload[100:200])
	if !res.Stored {
		t.Fatalf("second part = %+v", res)
	}
	if info, err := os.Stat(marker); err != nil || time.Since(info.ModTime()) > 10*time.Minute {
		t.Fatalf("marker mtime = %v, %v; want it refreshed by the part", info, err)
	}

	// A short body is rejected: nothing is renamed and no temporary remains.
	res = uploadPart(t, g, parent, key, transferlink.Range{Off: 200, Len: 100}, payload[200:260])
	if res.Stored || res.Count != 60 {
		t.Fatalf("short part = %+v, want 60 bytes and not stored", res)
	}
	res = uploadPart(t, g, parent, key, transferlink.Range{Off: 200, Len: 100}, nil)
	if res.Stored || res.Count != 0 {
		t.Fatalf("empty part = %+v, want 0 bytes and not stored", res)
	}
	if exists(filepath.Join(dir, "part-200-100")) {
		t.Fatal("a short part was renamed to its final name")
	}
	for _, name := range entryNames(t, dir) {
		if strings.HasSuffix(name, ".tmp") {
			t.Fatalf("a rejected part left %q behind", name)
		}
	}
	res = uploadPart(t, g, parent, key, transferlink.Range{Off: 200, Len: 100}, payload[200:300])
	if !res.Stored || res.Count != 100 {
		t.Fatalf("retried part = %+v", res)
	}

	// Junk of every kind next to the good parts.
	writeFile(t, filepath.Join(dir, "part-0-50"), payload[:50])
	writeFile(t, filepath.Join(dir, "part-300-80"), payload[300:370])
	writeFile(t, filepath.Join(dir, "part-900-300"), payload[:300])
	writeFile(t, filepath.Join(dir, "part-007-5"), payload[:5])
	writeFile(t, filepath.Join(dir, "part-x"), []byte("abc"))
	writeFile(t, filepath.Join(dir, "part-1-1.0123456789abcdef.tmp"), []byte("z"))
	writeFile(t, filepath.Join(dir, "other.txt"), []byte("other"))
	must(t, os.Mkdir(filepath.Join(dir, "part-5-5"), 0o700))
	must(t, os.Symlink(filepath.Join(dir, "other.txt"), filepath.Join(dir, "part-400-10")))

	listing, err := g.remote.ListStaging(ctx, parent, key, 1000)
	if err != nil {
		t.Fatal(err)
	}
	wantParts := []transferlink.Range{{Off: 0, Len: 100}, {Off: 100, Len: 100}, {Off: 200, Len: 100}}
	if fmt.Sprint(listing.Parts) != fmt.Sprint(wantParts) || listing.Overflow {
		t.Fatalf("Parts = %v overflow=%v, want %v", listing.Parts, listing.Overflow, wantParts)
	}
	remove := append([]string(nil), listing.Remove...)
	sort.Strings(remove)
	if got, want := strings.Join(remove, ","), "part-0-50,part-007-5,part-300-80,part-900-300"; got != want {
		t.Fatalf("Remove = %s, want %s", got, want)
	}
	if exists(filepath.Join(dir, "part-1-1.0123456789abcdef.tmp")) {
		t.Fatal("the listing left a stale temporary file")
	}
	for _, name := range []string{"part-x", "other.txt", "part-5-5", "part-400-10", "part-0-50"} {
		if !exists(filepath.Join(dir, name)) {
			t.Fatalf("the listing removed %q", name)
		}
	}
	if err := g.remote.RemoveStagingEntries(ctx, parent, key, listing.Remove); err != nil {
		t.Fatal(err)
	}
	for _, name := range listing.Remove {
		if exists(filepath.Join(dir, name)) {
			t.Fatalf("RemoveStagingEntries left %q", name)
		}
	}
	for _, name := range []string{"part-0-100", "part-100-100", "part-200-100", "part-x", "other.txt", "part-5-5", "part-400-10"} {
		if !exists(filepath.Join(dir, name)) {
			t.Fatalf("RemoveStagingEntries removed %q", name)
		}
	}
	listing, err = g.remote.ListStaging(ctx, parent, key, 1000)
	if err != nil || len(listing.Parts) != 3 || len(listing.Remove) != 0 {
		t.Fatalf("second listing = %+v, %v", listing, err)
	}
	// A shorter file than the parts cover rejects the part past its end.
	listing, err = g.remote.ListStaging(ctx, parent, key, 250)
	if err != nil || len(listing.Parts) != 2 || fmt.Sprint(listing.Remove) != "[part-200-100]" {
		t.Fatalf("listing for a 250-byte file = %+v, %v", listing, err)
	}

	// More entries than the bound: the staging is reported as corrupt.
	small := newChunkRig(t, transfercore.Limits{MaxBytes: 1 << 20, MaxEntries: 100000, MaxPathBytes: 1024, MaxDepth: 64})
	smallParent := small.dir("overflow parent")
	okey := transferremote.StagingKey("overflow")
	ensureCreated(t, small, smallParent, okey)
	odir := stageDir(smallParent, okey)
	bound := transferremote.MaxListedParts(transfercore.Limits{MaxBytes: 1 << 20})
	for i := 0; i < bound+2; i++ {
		writeFile(t, filepath.Join(odir, "part-"+strconv.Itoa(i)+"-1"), []byte("x"))
	}
	over, err := small.remote.ListStaging(small.ctx(), smallParent, okey, 1<<20)
	if err != nil || !over.Overflow || len(over.Parts) != 0 {
		t.Fatalf("overflow listing = %+v, %v", over, err)
	}
	if err := small.remote.RemoveChunkStaging(small.ctx(), smallParent, okey); err != nil || exists(odir) {
		t.Fatalf("removing the overflowing staging: %v, exists=%v", err, exists(odir))
	}
}

// ScenarioChunkAssemblyAndPublication assembles parts of different sizes and
// checks order, the SHA-256 anchor, cleanup on failure and publication through
// the existing primitives.
func ScenarioChunkAssemblyAndPublication(t *testing.T) {
	g := newChunkRig(t, transfercore.DefaultLimits())
	ctx := g.ctx()
	parent := g.dir("assembly parent it's ü ñ")
	key := transferremote.StagingKey("assembly")
	dir := stageDir(parent, key)
	ensureCreated(t, g, parent, key)
	payload := fixture.SeedPayload(1000, 32)
	sum := sha256.Sum256(payload)
	ranges := []transferlink.Range{{Off: 0, Len: 300}, {Off: 300, Len: 200}, {Off: 500, Len: 500}}
	for _, i := range []int{2, 0, 1} {
		if res := uploadPart(t, g, parent, key, ranges[i], payload[ranges[i].Off:ranges[i].End()]); !res.Stored {
			t.Fatalf("part %+v not stored", ranges[i])
		}
	}
	listing, err := g.remote.ListStaging(ctx, parent, key, 1000)
	if err != nil || fmt.Sprint(listing.Parts) != fmt.Sprint(ranges) {
		t.Fatalf("listing = %+v, %v", listing, err)
	}

	first, err := g.remote.AssembleStaging(ctx, parent, key, listing.Parts, 1000, false)
	if err != nil {
		t.Fatal(err)
	}
	if first.Size != 1000 || first.SHA256 != sum || !bytes.Equal(readFile(t, first.Path), payload) {
		t.Fatalf("assembled file differs from the payload: %+v", first)
	}
	if info, err := os.Stat(first.Path); err != nil || info.Mode().Perm()&0o111 != 0 {
		t.Fatalf("assembled mode = %v, %v; want no execute bit", info, err)
	}
	for _, r := range ranges {
		if !exists(partFile(dir, r)) {
			t.Fatalf("assembly consumed part %+v", r)
		}
	}
	reversed := []transferlink.Range{ranges[2], ranges[0], ranges[1]}
	second, err := g.remote.AssembleStaging(ctx, parent, key, reversed, 1000, true)
	if err != nil {
		t.Fatal(err)
	}
	if second.Path == first.Path || second.SHA256 != sum || !bytes.Equal(readFile(t, second.Path), payload) {
		t.Fatalf("second assembly = %+v (first %q)", second, first.Path)
	}
	if info, err := os.Stat(second.Path); err != nil || info.Mode().Perm()&0o100 == 0 {
		t.Fatalf("executable assembly mode = %v, %v; want the owner execute bit", info, err)
	}
	if !exists(first.Path) || countAssembled(t, dir) != 2 {
		t.Fatalf("assembled files = %d, want the earlier one kept", countAssembled(t, dir))
	}

	// A corrupted part of the right size still assembles; the digest is the
	// anchor that differs.
	corrupt := bytes.Repeat([]byte{0x5a}, 500)
	writeFile(t, partFile(dir, ranges[2]), corrupt)
	mixed, err := g.remote.AssembleStaging(ctx, parent, key, ranges, 1000, false)
	if err != nil {
		t.Fatal(err)
	}
	wantMixed := sha256.Sum256(append(append([]byte(nil), payload[:500]...), corrupt...))
	if mixed.SHA256 == sum || mixed.SHA256 != wantMixed {
		t.Fatalf("corrupted part digest = %x, want %x (payload %x)", mixed.SHA256, wantMixed, sum)
	}
	writeFile(t, partFile(dir, ranges[2]), payload[500:])

	// Failures delete nothing but their own half-written file.
	failed := func(name string, wantMissing bool, wantClass transfercore.Class) {
		before := countAssembled(t, dir)
		_, err := g.remote.AssembleStaging(ctx, parent, key, ranges, 1000, false)
		if err == nil {
			t.Fatalf("%s: assembly succeeded", name)
		}
		if transferremote.IsPartMissing(err) != wantMissing || transfercore.ClassOf(err) != wantClass {
			t.Fatalf("%s: error %v (class %s, part-missing %v), want class %s missing=%v", name, err, transfercore.ClassOf(err), transferremote.IsPartMissing(err), wantClass, wantMissing)
		}
		if after := countAssembled(t, dir); after != before {
			t.Fatalf("%s: a failed assembly left %d assembled files, had %d", name, after, before)
		}
		for _, r := range ranges {
			if !exists(partFile(dir, r)) && name != "missing part" {
				t.Fatalf("%s: part %+v disappeared", name, r)
			}
		}
	}
	must(t, os.Remove(partFile(dir, ranges[0])))
	failed("missing part", true, transfercore.ClassRemoteFailed)
	writeFile(t, partFile(dir, ranges[0]), payload[:300])

	must(t, os.Remove(partFile(dir, ranges[1])))
	must(t, os.Symlink(partFile(dir, ranges[2]), partFile(dir, ranges[1])))
	failed("symlinked part", true, transfercore.ClassRemoteFailed)
	must(t, os.Remove(partFile(dir, ranges[1])))
	writeFile(t, partFile(dir, ranges[1]), payload[300:500])

	writeFile(t, partFile(dir, ranges[0]), payload[:290])
	failed("short part on disk", false, transfercore.ClassIntegrity)
	writeFile(t, partFile(dir, ranges[0]), payload[:300])

	// Publication uses the existing primitives; the assembled file is
	// consumed by the no-overwrite hard-link sequence.
	dest := filepath.Join(parent, "published it's ü ñ.bin")
	third, err := g.remote.AssembleStaging(ctx, parent, key, ranges, 1000, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.remote.PublishFile(ctx, third.Path, dest, false); err != nil {
		t.Fatalf("PublishFile: %v", err)
	}
	if !bytes.Equal(readFile(t, dest), payload) || exists(third.Path) {
		t.Fatalf("publication left dest equal=%v, assembled file present=%v", bytes.Equal(readFile(t, dest), payload), exists(third.Path))
	}
	fourth, err := g.remote.AssembleStaging(ctx, parent, key, ranges, 1000, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.remote.PublishFile(ctx, fourth.Path, dest, false); transfercore.ClassOf(err) != transfercore.ClassExists {
		t.Fatalf("no-overwrite publication onto an existing file = %v, want exists", err)
	}
	writeFile(t, dest, []byte("old"))
	if err := g.remote.PublishFile(ctx, fourth.Path, dest, true); err != nil {
		t.Fatalf("overwrite publication: %v", err)
	}
	if !bytes.Equal(readFile(t, dest), payload) {
		t.Fatal("overwrite publication did not replace the destination")
	}

	// An empty file needs no parts.
	empty, err := g.remote.AssembleStaging(ctx, parent, key, nil, 0, false)
	if err != nil || empty.Size != 0 || empty.SHA256 != sha256.Sum256(nil) || len(readFile(t, empty.Path)) != 0 {
		t.Fatalf("empty assembly = %+v, %v", empty, err)
	}

	if err := g.remote.RemoveChunkStaging(ctx, parent, key); err != nil || exists(dir) {
		t.Fatalf("RemoveChunkStaging: %v, exists=%v", err, exists(dir))
	}
	if !bytes.Equal(readFile(t, dest), payload) {
		t.Fatal("removing the staging touched the published file")
	}
}

// ScenarioChunkGarbageCollection removes idle marked staging directories
// and nothing else.
func ScenarioChunkGarbageCollection(t *testing.T) {
	g := newChunkRig(t, transfercore.DefaultLimits())
	ctx := g.ctx()
	stale := time.Now().Add(-72 * time.Hour)
	young := time.Now().Add(-22 * time.Hour)

	mk := func(parent, dirName string, perm os.FileMode, marker string, mtime time.Time) {
		t.Helper()
		path := filepath.Join(parent, dirName)
		must(t, os.Mkdir(path, 0o700))
		if marker != "" {
			mp := filepath.Join(path, "marker")
			writeFile(t, mp, []byte(marker))
			must(t, os.Chtimes(mp, mtime, mtime))
		}
		writeFile(t, filepath.Join(path, "part-0-1"), []byte("x"))
		must(t, os.Chmod(path, perm))
	}
	name := func(label string) (dirName, key string) {
		key = transferremote.StagingKey("gc", label)
		return ".ssjack-transfer-" + key, key
	}

	parent := g.dir("gc parent it's ü ñ")
	var removed, kept []string
	for _, label := range []string{"stale-a", "stale-b"} {
		d, k := name(label)
		mk(parent, d, 0o700, chunkMarker(k), stale)
		removed = append(removed, d)
	}
	keepCase := func(label string, perm os.FileMode, withMarker bool, mtime time.Time) string {
		d, k := name(label)
		marker := ""
		if withMarker {
			marker = chunkMarker(k)
		}
		mk(parent, d, perm, marker, mtime)
		kept = append(kept, d)
		return k
	}
	keepCase("young", 0o700, true, young)
	excludedKey := keepCase("current", 0o700, true, stale)
	keepCase("unmarked", 0o700, false, stale)
	keepCase("mode-0755", 0o755, true, stale)
	{
		d, _ := name("other-key")
		mk(parent, d, 0o700, chunkMarker(strings.Repeat("b", 32)), stale)
		kept = append(kept, d)
	}
	{
		// A symlink with the right name pointing at an idle, valid staging.
		d, k := name("symlink")
		must(t, os.Mkdir(filepath.Join(parent, "gc-real-target"), 0o700))
		mp := filepath.Join(parent, "gc-real-target", "marker")
		writeFile(t, mp, []byte(chunkMarker(k)))
		must(t, os.Chtimes(mp, stale, stale))
		must(t, os.Symlink(filepath.Join(parent, "gc-real-target"), filepath.Join(parent, d)))
		kept = append(kept, d, "gc-real-target")
	}
	{
		// One-shot staging names (16 hex digits) are never collected.
		d := ".ssjack-transfer-0123456789abcdef"
		mk(parent, d, 0o700, "SSJACK-STAGING 1 0123456789abcdef\n", stale)
		kept = append(kept, d)
	}
	{
		d, _ := name("regular-file")
		writeFile(t, filepath.Join(parent, d), []byte("not a directory"))
		kept = append(kept, d)
	}
	{
		upper := strings.ToUpper(transferremote.StagingKey("gc", "upper"))
		d := ".ssjack-transfer-" + upper
		mk(parent, d, 0o700, chunkMarker(upper), stale)
		kept = append(kept, d)
	}
	{
		must(t, os.Mkdir(filepath.Join(parent, "keepme"), 0o700))
		writeFile(t, filepath.Join(parent, "keepme", "marker"), []byte("x"))
		kept = append(kept, "keepme")
	}

	before := map[string]string{}
	for _, d := range kept {
		before[d] = describe(t, filepath.Join(parent, d))
	}
	n, err := g.remote.CollectStaging(ctx, parent, excludedKey)
	if err != nil || n != len(removed) {
		t.Fatalf("CollectStaging = %d, %v; want %d", n, err, len(removed))
	}
	for _, d := range removed {
		if exists(filepath.Join(parent, d)) {
			t.Fatalf("idle staging %q survived", d)
		}
	}
	for _, d := range kept {
		if got := describe(t, filepath.Join(parent, d)); got != before[d] {
			t.Fatal("kept staging changed")
		}
	}
	if n, err := g.remote.CollectStaging(ctx, parent, excludedKey); err != nil || n != 0 {
		t.Fatalf("second CollectStaging = %d, %v; want nothing left to collect", n, err)
	}
	if n, err := g.remote.CollectStaging(ctx, filepath.Join(parent, "absent"), ""); err != nil || n != 0 {
		t.Fatalf("CollectStaging on an absent parent = %d, %v; want a quiet zero", n, err)
	}

	// At most 16 per pass.
	bounded := g.dir("gc bound")
	for i := 0; i < 20; i++ {
		d, k := name("bound-" + strconv.Itoa(i))
		mk(bounded, d, 0o700, chunkMarker(k), stale)
	}
	if n, err := g.remote.CollectStaging(ctx, bounded, ""); err != nil || n != 16 {
		t.Fatalf("bounded CollectStaging = %d, %v; want 16", n, err)
	}
	if left := len(entryNames(t, bounded)); left != 4 {
		t.Fatalf("%d staging directories left, want 4", left)
	}
	if n, err := g.remote.CollectStaging(ctx, bounded, ""); err != nil || n != 4 {
		t.Fatalf("second bounded CollectStaging = %d, %v; want 4", n, err)
	}
}

// ScenarioChunkReadStatAndDisk covers the download-side primitives and the
// disk preflight.
func ScenarioChunkReadStatAndDisk(t *testing.T) {
	g := newChunkRig(t, transfercore.DefaultLimits())
	ctx := g.ctx()
	parent := g.dir("read parent it's ü ñ")
	payload := fixture.SeedPayload(10000, 33)
	file := filepath.Join(parent, "src it's ü ñ.bin")
	writeFile(t, file, payload)
	mtime := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	must(t, os.Chtimes(file, mtime, mtime))

	st, err := g.remote.StatSource(ctx, file)
	if err != nil || st.Size != 10000 || st.MTime != mtime.Unix() {
		t.Fatalf("StatSource = %+v, %v; want size 10000, mtime %d", st, err, mtime.Unix())
	}
	must(t, os.Symlink(file, filepath.Join(parent, "link.bin")))
	for _, path := range []string{filepath.Join(parent, "link.bin"), parent} {
		if _, err := g.remote.StatSource(ctx, path); transfercore.ClassOf(err) != transfercore.ClassRefusedPath {
			t.Fatalf("StatSource(%s) = %v, want refused_path", filepath.Base(path), err)
		}
	}

	avail, ok, err := g.remote.DiskAvailable(ctx, parent)
	if err != nil || !ok || avail <= 0 {
		t.Fatalf("DiskAvailable = %d, %v, %v; want a parsed positive size", avail, ok, err)
	}
	if _, _, err := g.remote.DiskAvailable(ctx, filepath.Join(parent, "absent")); transfercore.ClassOf(err) != transfercore.ClassRefusedPath {
		t.Fatalf("DiskAvailable on a missing parent = %v, want refused_path", err)
	}

	cases := []struct {
		name string
		part transferlink.Range
		grid int64
	}{
		{"aligned block (dd)", transferlink.Range{Off: 2048, Len: 1024}, 1024},
		{"aligned first block (dd)", transferlink.Range{Off: 0, Len: 1024}, 1024},
		{"aligned tail shorter than the block (dd)", transferlink.Range{Off: 9216, Len: 784}, 1024},
		{"off the grid (tail/head)", transferlink.Range{Off: 1500, Len: 700}, 1024},
		{"short mid-file part on the grid (tail/head)", transferlink.Range{Off: 1024, Len: 100}, 1024},
		{"longer than a block (tail/head)", transferlink.Range{Off: 1024, Len: 2048}, 1024},
		{"whole file without a grid (tail/head)", transferlink.Range{Off: 0, Len: 10000}, 0},
		{"first byte", transferlink.Range{Off: 0, Len: 1}, 1024},
		{"last byte", transferlink.Range{Off: 9999, Len: 1}, 1024},
	}
	for _, tc := range cases {
		var buf bytes.Buffer
		n, err := g.remote.ReadRange(ctx, file, tc.part, tc.grid, 10000, &buf)
		if err != nil || n != tc.part.Len {
			t.Fatalf("%s: ReadRange = %d, %v", tc.name, n, err)
		}
		if !bytes.Equal(buf.Bytes(), payload[tc.part.Off:tc.part.End()]) {
			t.Fatalf("%s: bytes differ from the source range", tc.name)
		}
	}

	// A source that shrank after it was measured is an integrity error.
	writeFile(t, file, payload[:5000])
	var buf bytes.Buffer
	n, err := g.remote.ReadRange(ctx, file, transferlink.Range{Off: 9216, Len: 784}, 1024, 10000, &buf)
	if err == nil || n != 0 {
		t.Fatalf("read past a shrunk source = %d, %v; want a failure with no bytes", n, err)
	}
	if _, err := g.remote.ReadRange(ctx, filepath.Join(parent, "link.bin"), transferlink.Range{Off: 0, Len: 10}, 1024, 10000, &buf); transfercore.ClassOf(err) != transfercore.ClassRefusedPath {
		t.Fatalf("ReadRange through a symlink = %v, want refused_path", err)
	}
}

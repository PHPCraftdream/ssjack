package ownerarchive

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/ktav-lang/golang/pure"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
)

func fixture(t *testing.T) (*Archive, appstoreref.Ref) {
	t.Helper()
	ref, err := appstoreref.New([16]byte{1}, [16]byte{2}, [16]byte{3}, [16]byte{4})
	noErr(t, err)
	encoded, err := appstoreplaceholder.Encode(ref)
	noErr(t, err)
	database, err := pure.EmitCanonical(map[string]any{"version": 2, "targets": map[string]any{}, "servers": map[string]any{}, "secrets": map[string]any{"01000000000000000000000000000000": map[string]string{"name": "token", "server_id": "", "ref": string(encoded)}}})
	noErr(t, err)
	archive, err := New([]byte(database))
	noErr(t, err)
	t.Cleanup(archive.Close)
	return archive, ref
}

func TestArchiveRequiresExactCompleteSelectedValues(t *testing.T) {
	a, ref := fixture(t)
	path := filepath.Join(t.TempDir(), "export.zip")
	fatalIf(t, a.WritePlaintext(context.Background(), path, "EXPORT PLAINTEXT") == nil, "metadata-only export pretended to include values")
	_, err := os.Stat(path)
	fatalIf(t, !os.IsNotExist(err), "incomplete export touched destination")
	fatalIf(t, a.Add("02000000000000000000000000000000", ref, []byte("synthetic")) == nil, "export accepted an unselected alias")
	noErr(t, a.Add("01000000000000000000000000000000", ref, []byte("synthetic")))
	fatalIf(t, a.Add("01000000000000000000000000000000", ref, []byte("replacement")) == nil, "export silently replaced a selected value")
	fatalIf(t, a.WriteEncrypted(context.Background(), path, nil) == nil, "encrypted export accepted no authenticated key")
}

func TestPlaintextArchivePreservesBytesAndNeverOverwrites(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("private-file runtime unavailable")
	}
	a, ref := fixture(t)
	value := []byte{'a', 0, '\n', 255, 'z'}
	noErr(t, a.Add("01000000000000000000000000000000", ref, value))
	clear(value)
	path := filepath.Join(t.TempDir(), "export.zip")
	fatalIf(t, a.WritePlaintext(context.Background(), path, "yes") == nil, "plaintext export accepted implicit confirmation")
	noErr(t, a.WritePlaintext(context.Background(), path, "EXPORT PLAINTEXT"))
	info, err := os.Stat(path)
	noErr(t, err)
	file, err := os.Open(path)
	noErr(t, err)
	privateErr := checkPrivateFile(file, info)
	file.Close()
	noErr(t, privateErr)
	before, err := os.ReadFile(path)
	noErr(t, err)
	files := make(map[string][]byte)
	for _, e := range unzip(before) {
		files[e.name] = e.body
	}
	fatalIf(t, len(files) != 3 || !bytes.Equal(files["secrets/01000000000000000000000000000000.bin"], []byte{'a', 0, '\n', 255, 'z'}) || !bytes.Equal(files["database.ktav"], a.database), "export lost selected metadata or exact value bytes")
	var index manifest
	err = json.Unmarshal(files["manifest.json"], &index)
	fatalIf(t, err != nil || index.Format != "ssjack-owner-export-v1" || len(index.Secrets) != 1, "export omitted its complete inventory")
	for _, record := range []fileRecord{index.Database, index.Secrets["01000000000000000000000000000000"]} {
		body, exists := files[record.Name]
		digest := sha256.Sum256(body)
		fatalIf(t, !exists || record.Length != len(body) || record.SHA256 != hex.EncodeToString(digest[:]), "manifest did not bind the actual exported file bytes")
	}
	fatalIf(t, a.WritePlaintext(context.Background(), path, "EXPORT PLAINTEXT") == nil, "export overwrote an existing artifact")
	after, err := os.ReadFile(path)
	fatalIf(t, err != nil || !bytes.Equal(before, after), "refused overwrite changed the existing artifact")
}

func TestArchiveCancellationAndCleanup(t *testing.T) {
	a, ref := fixture(t)
	noErr(t, a.Add("01000000000000000000000000000000", ref, []byte("synthetic")))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	path := filepath.Join(t.TempDir(), "cancelled.zip")
	fatalIf(t, a.WritePlaintext(ctx, path, "EXPORT PLAINTEXT") == nil, "cancelled export succeeded")
	_, err := os.Stat(path)
	fatalIf(t, !os.IsNotExist(err), "pre-cancelled export created output")
	owned := a.values["01000000000000000000000000000000"]
	a.Close()
	fatalIf(t, !bytes.Equal(owned, make([]byte, len(owned))), "archive close retained owned values")
	fatalIf(t, a.Add("01000000000000000000000000000000", ref, nil) == nil, "closed export accepted new material")
}

func TestArchiveRejectsLinkedUnlockMaterial(t *testing.T) {
	encoded, err := pure.EmitCanonical(map[string]any{"version": 2, "targets": map[string]any{}, "servers": map[string]any{}, "secrets": map[string]any{}, "owner_store": map[string]any{"master": "synthetic"}})
	noErr(t, err)
	_, err = New([]byte(encoded))
	fatalIf(t, err == nil, "export accepted linked store unlock material")
}

type entry struct {
	name   string
	body   []byte
	method uint16
}

const id1 = "01000000000000000000000000000000"

var structural = []byte("structural-test-only:")

func noErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// fatalIf keeps single-line assertions compact (file line cap).
func fatalIf(t *testing.T, failed bool, message string) {
	t.Helper()
	if failed {
		t.Fatal(message)
	}
}

// must is only for helpers that have no *testing.T.
func must(err error) {
	if err != nil {
		panic(err)
	}
}

func fakeOpen(b []byte) ([]byte, error) {
	if p, ok := bytes.CutPrefix(b, structural); ok {
		return append([]byte(nil), p...), nil
	}
	return nil, errors.New("not structural")
}

func fakeUnlock(m []byte) ([]byte, func([]byte) ([]byte, error), func(), error) {
	plain, err := fakeOpen(m)
	return plain, fakeOpen, func() {}, err
}

func unzip(data []byte) (es []entry) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	must(err)
	for _, f := range zr.File {
		in, err := f.Open()
		must(err)
		body, err := io.ReadAll(in)
		must(err)
		es = append(es, entry{name: f.Name, body: body})
	}
	return es
}

func rezip(es []entry) []byte {
	var out bytes.Buffer
	w := zip.NewWriter(&out)
	for _, e := range es {
		f, err := w.CreateHeader(&zip.FileHeader{Name: e.name, Method: e.method})
		must(err)
		_, err = f.Write(e.body)
		must(err)
	}
	must(w.Close())
	return out.Bytes()
}

func export(t *testing.T, encrypted bool, value []byte) (string, []byte) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("private-file runtime unavailable")
	}
	a, ref := fixture(t)
	noErr(t, a.Add(id1, ref, value))
	path := filepath.Join(t.TempDir(), "w.zip")
	if encrypted {
		noErr(t, a.write(context.Background(), path, func(v []byte) ([]byte, error) { return append(append([]byte(nil), structural...), v...), nil }, true))
	} else {
		noErr(t, a.WritePlaintext(context.Background(), path, "EXPORT PLAINTEXT"))
	}
	data, err := os.ReadFile(path)
	noErr(t, err)
	return path, data
}

func TestEncryptedValueFramingPreservesEmptyValues(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("private-file runtime unavailable")
	}
	a, ref := fixture(t)
	noErr(t, a.Add(id1, ref, nil))
	frames := 0
	inspectFrame := func(payload []byte) ([]byte, error) {
		if len(payload) == 0 {
			t.Fatal("empty value reached a sealer that requires a nonempty payload")
		}
		if bytes.Equal(payload, []byte{1}) {
			frames++
		}
		return append([]byte("structural-test-only:"), payload...), nil
	}
	noErr(t, a.write(context.Background(), filepath.Join(t.TempDir(), "framing-only.zip"), inspectFrame, true))
	if frames != 1 {
		t.Fatal("empty selected value did not retain its versioned value frame")
	}
}

func TestReadEnforcesMemoryBoundOnEveryPath(t *testing.T) {
	if o, err := Read(context.Background(), make([]byte, maxArchiveFile+1), nil); o != nil || !errors.Is(err, ErrArchive) {
		t.Fatalf("oversize in-memory archive accepted: %v", err)
	}
	path, _ := export(t, false, []byte("v"))
	o, err := ReadFile(context.Background(), path, nil)
	noErr(t, err)
	o.Close()
}

func TestReadRoundTripPreservesExactValuesAndSource(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		for _, value := range [][]byte{{'a', 0, '\n', 255, 'z'}, {}} {
			path, data := export(t, encrypted, value)
			o, err := ReadFile(context.Background(), path, nil) // encrypted: empty password, no KDF
			if encrypted {
				o, err = read(context.Background(), data, fakeUnlock)
			}
			noErr(t, err)
			got, ok := o.Value(id1)
			if o.Encrypted() != encrypted || !ok || !bytes.Equal(got, value) || len(o.SecretIDs()) != 1 || len(o.Database()) == 0 {
				t.Fatalf("round trip lost data (encrypted=%v)", encrypted)
			}
			o.Close()
			after, err := os.ReadFile(path)
			if _, ok := o.Value(id1); ok || err != nil || !bytes.Equal(after, data) {
				t.Fatal("close retained data or the source file changed")
			}
		}
	}
}

func TestReadRejectsMalformedAndTamperedArchives(t *testing.T) {
	edit := func(i int, from, to string) func([]entry) []entry {
		return func(es []entry) []entry {
			es[i].body = bytes.Replace(es[i].body, []byte(from), []byte(to), 1)
			return es
		}
	}
	cases := []struct {
		name      string
		encrypted bool
		want      error
		change    func([]entry) []entry
	}{
		{"missing manifest", false, ErrArchive, func(es []entry) []entry { return es[:2] }},
		{"unlisted entry", false, ErrArchive, func(es []entry) []entry {
			return append(es, entry{name: "secrets/02000000000000000000000000000000.bin"})
		}},
		{"duplicate name", false, ErrArchive, func(es []entry) []entry { return append(es, es[0]) }},
		{"traversal", false, ErrArchive, func(es []entry) []entry { es[0].name = "../database.ktav"; return es }},
		{"deflate", false, ErrArchive, func(es []entry) []entry { es[0].method = zip.Deflate; return es }},
		{"mode mixing", false, ErrArchive, func(es []entry) []entry { es[0].name = "database.ssjack.ktav"; return es }},
		{"oversized entry", false, ErrArchive, func(es []entry) []entry { es[1].body = make([]byte, 16385); return es }},
		{"tampered digest", false, ErrArchive, edit(1, "v", "w")},
		{"duplicate JSON key", false, ErrArchive, edit(2, `"format":"ssjack-owner-export-v1"`, `"format":"ssjack-owner-export-v1","format":"x"`)},
		{"unknown manifest field", false, ErrArchive, edit(2, `{"format"`, `{"extra":1,"format"`)},
		{"tampered ciphertext", true, ErrAuthentication, edit(1, "v", "w")},
		{"wrong password", true, ErrAuthentication, edit(2, "structural", "different")},
	}
	for _, c := range cases {
		_, data := export(t, c.encrypted, []byte("v"))
		if o, err := read(context.Background(), rezip(c.change(unzip(data))), fakeUnlock); o != nil || !errors.Is(err, c.want) {
			t.Fatalf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
}

func TestReadFileRejectsUnsafePathsAndOversize(t *testing.T) {
	path, _ := export(t, false, []byte("v"))
	dir, big := filepath.Dir(path), filepath.Join(filepath.Dir(path), "big.zip")
	noErr(t, os.WriteFile(big, nil, 0o600))
	noErr(t, os.Truncate(big, maxArchiveFile+1))
	paths := []string{"", dir, big, path + "\n"}
	if link := filepath.Join(dir, "link.zip"); os.Symlink(path, link) == nil {
		paths = append(paths, link)
	}
	for _, p := range paths {
		if o, err := ReadFile(context.Background(), p, nil); o != nil || !errors.Is(err, ErrArchive) {
			t.Fatalf("unsafe path accepted: %q %v", p, err)
		}
	}
}

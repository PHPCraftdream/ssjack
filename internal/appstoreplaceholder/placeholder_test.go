package appstoreplaceholder

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
)

func fixture(t *testing.T) (appstoreref.Ref, string) {
	t.Helper()
	var ids [4][16]byte
	for i, value := range []byte{0x1a, 0x2b, 0x3c, 0x4d} {
		for j := range ids[i] {
			ids[i][j] = value
		}
	}
	ref, err := appstoreref.New(ids[0], ids[1], ids[2], ids[3])
	if err != nil {
		t.Fatal(err)
	}
	canonical := `{"$ssjack":{"format":"ssjack-secret-ref-v1","object_id":"` + strings.Repeat("2b", 16) + `","snapshot_id":"` + strings.Repeat("4d", 16) + `","store_id":"` + strings.Repeat("1a", 16) + `","version_id":"` + strings.Repeat("3c", 16) + `"}}`
	return ref, canonical
}

func TestDocumentedPlaceholderIsCanonical(t *testing.T) {
	txt, err := os.ReadFile(filepath.Join("..", "..", "docs", "application-store", "PLACEHOLDERS.md"))
	if err != nil {
		t.Fatal(err)
	}
	parts := bytes.SplitN(txt, []byte("```json\n"), 2)
	if len(parts) != 2 {
		t.Fatal("missing documented JSON example")
	}
	block := bytes.SplitN(parts[1], []byte("```"), 2)
	if len(block) != 2 {
		t.Fatal("unterminated documented example")
	}
	example := bytes.TrimSpace(block[0])
	ref, err := Parse(example)
	if err != nil {
		t.Fatalf("documented placeholder: %v", err)
	}
	canonical, err := Encode(ref)
	if err != nil || !bytes.Equal(canonical, example) {
		t.Fatalf("noncanonical documented placeholder: %v", err)
	}
}

func TestCanonicalExactReferenceRoundTrip(t *testing.T) {
	ref, want := fixture(t)
	raw, err := Encode(ref)
	if err != nil || string(raw) != want {
		t.Fatalf("canonical reference: %v", err)
	}
	decoded, err := Parse(raw)
	if err != nil || decoded != ref {
		t.Fatalf("exact round trip: %v", err)
	}
	clear(raw)
	fresh, err := Encode(decoded)
	if err != nil || string(fresh) != want {
		t.Fatalf("owned decoded IDs: %v", err)
	}
	if _, err := Encode(appstoreref.Ref{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero reference: %v", err)
	}
	spaced := " \n" + strings.ReplaceAll(want, ":", " : ") + "\n "
	parsed, err := Parse([]byte(spaced))
	if err != nil || parsed != ref {
		t.Fatalf("JSON presentation changed identity: %v", err)
	}
	escapedKey := `"store_` + string(rune(92)) + `u0069d"`
	escaped := strings.Replace(want, `"store_id"`, escapedKey, 1)
	if escaped == want {
		t.Fatal("escaped-key fixture did not change input")
	}
	parsed, err = Parse([]byte(escaped))
	if err != nil || parsed != ref {
		t.Fatalf("decoded key: %v", err)
	}
}

func TestRejectAmbiguousAndNonExactPlaceholders(t *testing.T) {
	_, valid := fixture(t)
	escapedKey := `"store_` + string(rune(92)) + `u0069d"`
	store := `"store_id":"` + strings.Repeat("1a", 16) + `"`
	version := `"version_id":"` + strings.Repeat("3c", 16) + `"`
	snapshot := `,"snapshot_id":"` + strings.Repeat("4d", 16) + `"`
	cases := map[string]string{
		"unknown-format":    strings.Replace(valid, Format, "ssjack-secret-ref-v2", 1),
		"missing-format":    strings.Replace(valid, `"format":"`+Format+`",`, "", 1),
		"missing-snapshot":  strings.Replace(valid, snapshot, "", 1),
		"latest":            strings.Replace(valid, version, `"version_id":"latest"`, 1),
		"wildcard":          strings.Replace(valid, version, `"version_id":"*"`, 1),
		"zero-id":           strings.Replace(valid, strings.Repeat("1a", 16), strings.Repeat("00", 16), 1),
		"uppercase-id":      strings.Replace(valid, strings.Repeat("1a", 16), strings.Repeat("1A", 16), 1),
		"short-id":          strings.Replace(valid, strings.Repeat("1a", 16), strings.Repeat("1a", 15), 1),
		"nonhex-id":         strings.Replace(valid, strings.Repeat("1a", 16), strings.Repeat("zz", 16), 1),
		"null-id":           strings.Replace(valid, store, `"store_id":null`, 1),
		"number-id":         strings.Replace(valid, store, `"store_id":1`, 1),
		"array-id":          strings.Replace(valid, store, `"store_id":[]`, 1),
		"duplicate-id":      strings.Replace(valid, store, store+","+store, 1),
		"escaped-duplicate": strings.Replace(valid, store, store+`,`+strings.Replace(store, `"store_id"`, escapedKey, 1), 1),
		"unknown-inner":     strings.Replace(valid, `"format":`, `"secret_value":"synthetic-sensitive-marker","format":`, 1),
		"unknown-outer":     strings.Replace(valid, `{"$ssjack":`, `{"other":{},"$ssjack":`, 1),
		"wrong-marker":      strings.Replace(valid, "$ssjack", "ssjack", 1),
		"null-root":         "null", "array-root": "[]", "null-body": `{"$ssjack":null}`,
		"trailing-value": valid + "{}", "trailing-text": valid + "x", "truncated": valid[:len(valid)-1],
		"bad-surrogate": strings.Replace(valid, strings.Repeat("1a", 16), `\ud800`, 1),
		"oversized":     strings.Repeat(" ", MaxInput+1) + valid,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if raw == valid {
				t.Fatal("negative fixture did not change input")
			}
			ref, err := Parse([]byte(raw))
			if !errors.Is(err, ErrInvalid) || ref.Valid() || ref != (appstoreref.Ref{}) {
				t.Fatalf("invalid placeholder accepted: %v", err)
			}
			if strings.Contains(err.Error(), "synthetic-sensitive-marker") {
				t.Fatal("error echoed a supplied value")
			}
		})
	}
	for _, raw := range [][]byte{nil, {}, bytes.Repeat([]byte{' '}, MaxInput+1), {0xff, 0xfe}} {
		if ref, err := Parse(raw); !errors.Is(err, ErrInvalid) || ref.Valid() {
			t.Fatalf("invalid bytes accepted: %v", err)
		}
	}
}

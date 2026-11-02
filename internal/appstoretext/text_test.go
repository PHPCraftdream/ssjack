package appstoretext

import (
	"bytes"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
)

func fixture(t *testing.T, first byte) appstoreref.Ref {
	t.Helper()
	var ids [4][16]byte
	for i := range ids {
		for j := range ids[i] {
			ids[i][j] = first + byte(i)
		}
	}
	r, err := appstoreref.New(ids[0], ids[1], ids[2], ids[3])
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func placeholder(t *testing.T, ref appstoreref.Ref) []byte {
	t.Helper()
	p, err := appstoreplaceholder.Encode(ref)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBidirectionalLiteralReplacement(t *testing.T) {
	r := fixture(t, 1)
	p := placeholder(t, r)
	m := []Mapping{{Reference: r, Value: []byte("päss\nword")}}
	input := append(append([]byte("keep="), p...), []byte(";again=")...)
	input = append(input, p...)
	want := []byte("keep=päss\nword;again=päss\nword")
	got, err := Replace(input, m, false)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("forward: %q %v", got, err)
	}
	back, err := Replace(got, m, true)
	if err != nil || !bytes.Equal(back, input) {
		t.Fatalf("reverse: %q %v", back, err)
	}
}

func TestUnknownMalformedAndArbitraryBytesPreserved(t *testing.T) {
	r := fixture(t, 1)
	input := []byte{0, 0xff, '$', 's', 's', 'j', 'a', 'c', 'k', '-', '?', '\n'}
	got, err := Replace(input, []Mapping{{Reference: r, Value: []byte("secret")}}, true)
	if err != nil || !bytes.Equal(got, input) {
		t.Fatalf("got %v, err %v", got, err)
	}
}

func TestOverlappingValuesLeftmostLongest(t *testing.T) {
	a, b := fixture(t, 1), fixture(t, 9)
	m := []Mapping{{Reference: a, Value: []byte("aba")}, {Reference: b, Value: []byte("ab")}}
	got, err := Replace([]byte("ababa"), m, true)
	want := append(append([]byte{}, placeholder(t, a)...), []byte("ba")...)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("got %q, want %q, err %v", got, want, err)
	}
	got, err = Replace([]byte("abaab"), m, true)
	want = append(append([]byte{}, placeholder(t, a)...), placeholder(t, b)...)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("adjacent: %q, err %v", got, err)
	}
}

func TestAmbiguousEqualValuesRejectedBothDirections(t *testing.T) {
	m := []Mapping{{Reference: fixture(t, 1), Value: []byte("same")}, {Reference: fixture(t, 9), Value: []byte("same")}}
	for _, reverse := range []bool{false, true} {
		if out, err := Replace([]byte("same"), m, reverse); err == nil || out != nil {
			t.Fatalf("reverse=%v accepted equal values", reverse)
		}
	}
}

func TestRegisteredPlaceholderCollisionRejected(t *testing.T) {
	r := fixture(t, 1)
	p := placeholder(t, r)
	m := []Mapping{{Reference: r, Value: []byte("secret")}}
	if out, err := Replace(p, m, true); err == nil || out != nil {
		t.Fatal("registered literal placeholder accepted")
	}
}

func TestOutputBoundsAndValues(t *testing.T) {
	r := fixture(t, 1)
	p := placeholder(t, r)
	m := []Mapping{{Reference: r, Value: bytes.Repeat([]byte("x"), MaxText)}}
	if out, err := Replace(p, m, false); err != nil || len(out) != MaxText {
		t.Fatalf("maximum expansion: len=%d err=%v", len(out), err)
	}
	if out, err := Replace(append(bytes.Clone(p), 'x'), m, false); err == nil || out != nil {
		t.Fatal("oversized expansion accepted")
	}
	m[0].Value = bytes.Repeat([]byte("x"), MaxText+1)
	if out, err := Replace([]byte("x"), m, false); err == nil || out != nil {
		t.Fatal("oversized value accepted")
	}
}

func TestMappingLimitAndNoRescan(t *testing.T) {
	m := make([]Mapping, MaxMappings+1)
	for i := range m {
		m[i] = Mapping{Reference: fixture(t, byte(i+1)), Value: []byte{byte(i + 1)}}
	}
	if out, err := Replace([]byte("x"), m, false); err == nil || out != nil {
		t.Fatal("mapping limit accepted")
	}
	a, b := fixture(t, 1), fixture(t, 9)
	pa := placeholder(t, a)
	got, err := Replace([]byte("aa"), []Mapping{{Reference: a, Value: []byte("a")}}, true)
	want := append(append([]byte{}, pa...), pa...)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("replacement output was rescanned: %q, want %q, err %v", got, want, err)
	}
	pb := placeholder(t, b)
	if out, err := Replace(pb, []Mapping{{Reference: a, Value: []byte("synthetic credential")}}, true); err != nil || !bytes.Equal(out, pb) {
		t.Fatalf("unknown canonical placeholder: %q, err %v", out, err)
	}
	m = []Mapping{{Reference: a, Value: []byte("secret")}}
	got, err = Replace(pb, m, true)
	want = bytes.ReplaceAll(pb, []byte("secret"), placeholder(t, a))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("canonical token value replacement: got %q want %q err %v", got, want, err)
	}
}

func TestWholeBufferBoundaryAndRoundTripLimitation(t *testing.T) {
	r := fixture(t, 1)
	p := placeholder(t, r)
	m := []Mapping{{Reference: r, Value: []byte("secret")}}
	input := append(bytes.Repeat([]byte{'x'}, 16383), p...)
	got, err := Replace(input, m, false)
	if err != nil || !bytes.Equal(got[16383:], []byte("secret")) {
		t.Fatalf("cross-boundary token: err=%v", err)
	}
	back, err := Replace(got, m, true)
	if err != nil || !bytes.Equal(back, input) {
		t.Fatalf("round trip: err=%v", err)
	}
	// Adjacent matches can still lose distinctions on reverse replacement:
	// A followed by literal "b" hydrates to "ab", which reverse maps as B.
	a, b := fixture(t, 9), fixture(t, 17)
	pa := placeholder(t, a)
	m = []Mapping{{Reference: a, Value: []byte("a")}, {Reference: b, Value: []byte("ab")}}
	input = append(bytes.Clone(pa), 'b')
	forward, err := Replace(input, m, false)
	if err != nil || !bytes.Equal(forward, []byte("ab")) {
		t.Fatalf("ambiguous forward output: %q, err %v", forward, err)
	}
	back, err = Replace(forward, m, true)
	if err != nil || !bytes.Equal(back, placeholder(t, b)) {
		t.Fatalf("reverse should select longest value: %q, err %v", back, err)
	}
}

func TestRejectsInvalidMappings(t *testing.T) {
	valid := Mapping{Reference: fixture(t, 1), Value: []byte("x")}
	cases := []struct {
		input    []byte
		mappings []Mapping
	}{
		{nil, nil},
		{make([]byte, MaxText+1), []Mapping{valid}},
		{[]byte("x"), []Mapping{{Reference: appstoreref.Ref{}, Value: []byte("x")}}},
		{[]byte("x"), []Mapping{{Reference: fixture(t, 2), Value: nil}}},
		{[]byte("x"), []Mapping{{Reference: fixture(t, 3), Value: []byte("$ssjack")}}},
		{[]byte("x"), []Mapping{valid, valid}},
	}
	for i, tc := range cases {
		if out, err := Replace(tc.input, tc.mappings, false); err == nil || out != nil {
			t.Fatalf("case %d accepted", i)
		}
	}
}

func TestCapturedReferencesKeepExactVersionAndSnapshotIdentity(t *testing.T) {
	store := fixture(t, 1).StoreID()
	var object, oldVersion, newVersion, oldSnapshot, newSnapshot [16]byte
	object[0], oldVersion[0], newVersion[0], oldSnapshot[0], newSnapshot[0] = 40, 41, 42, 43, 44
	oldRef, err := appstoreref.New(store, object, oldVersion, oldSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	newRef, err := appstoreref.New(store, object, newVersion, newSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	oldToken, newToken := placeholder(t, oldRef), placeholder(t, newRef)
	m := []Mapping{{Reference: oldRef, Value: []byte("old secret")}}
	input := append(append(bytes.Clone(oldToken), '|'), newToken...)
	got, err := Replace(input, m, false)
	want := append([]byte("old secret|"), newToken...)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("forward=%q want=%q err=%v", got, want, err)
	}
	back, err := Replace(got, m, true)
	if err != nil || !bytes.Equal(back, input) {
		t.Fatalf("reverse=%q want=%q err=%v", back, input, err)
	}
}

func TestDerivedEscapedAndUnknownTextIsNotDetected(t *testing.T) {
	r := fixture(t, 1)
	m := []Mapping{{Reference: r, Value: []byte("known secret")}}
	unchanged := [][]byte{
		[]byte(`known\\ secret`),
		[]byte(`known\u0020secret`),
		[]byte("KNOWN SECRET"),
		[]byte("other-credential-hash-7f3a"),
		[]byte("ordinary text"),
		[]byte("$ssjack-secret-ref-v1 unknown"),
	}
	for _, input := range unchanged {
		for _, reverse := range []bool{false, true} {
			got, err := Replace(input, m, reverse)
			if err != nil || !bytes.Equal(got, input) {
				t.Fatalf("reverse=%v input=%q got=%q err=%v", reverse, input, got, err)
			}
		}
	}

	replaced := [][]byte{
		[]byte(`{"value":"known secret"}`),
		[]byte("known secret-suffix"),
	}
	for _, input := range replaced {
		got, err := Replace(input, m, true)
		want := bytes.ReplaceAll(input, []byte("known secret"), placeholder(t, r))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("input=%q got=%q want=%q err=%v", input, got, want, err)
		}
	}
}

func TestMalformedReferenceTextIsPreservedInBothDirections(t *testing.T) {
	input := []byte("$ssjack-secret-ref-v1{not-json")
	m := []Mapping{{Reference: fixture(t, 1), Value: []byte("synthetic credential")}}
	for _, reverse := range []bool{false, true} {
		got, err := Replace(input, m, reverse)
		if err != nil || !bytes.Equal(got, input) {
			t.Fatalf("reverse=%v got=%q err=%v", reverse, got, err)
		}
	}
}

func TestInputAndMappingBuffersAreNotMutated(t *testing.T) {
	r := fixture(t, 1)
	input, value := placeholder(t, r), []byte("secret")
	inputBefore, valueBefore := bytes.Clone(input), bytes.Clone(value)
	m := []Mapping{{Reference: r, Value: value}}
	if _, err := Replace(input, m, false); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(input, inputBefore) || !bytes.Equal(value, valueBefore) || m[0].Reference != r {
		t.Fatal("input or mapping was mutated")
	}
}

func TestMaximumOrdinaryInputAndReverseExpansionOverflow(t *testing.T) {
	r := fixture(t, 1)
	m := []Mapping{{Reference: r, Value: []byte("x")}}
	input := bytes.Repeat([]byte{'z'}, MaxText)
	got, err := Replace(input, m, false)
	if err != nil || !bytes.Equal(got, input) {
		t.Fatalf("maximum ordinary input: len=%d err=%v", len(got), err)
	}
	input = bytes.Repeat([]byte{'x'}, MaxText)
	if out, err := Replace(input, m, true); err == nil || out != nil {
		t.Fatal("reverse expansion beyond maximum accepted")
	}
}

func TestMappingReorderKeepsLongestOutcome(t *testing.T) {
	a, b := fixture(t, 1), fixture(t, 9)
	m := []Mapping{{Reference: a, Value: []byte("aba")}, {Reference: b, Value: []byte("ab")}}
	input := []byte("ababa")
	first, err := Replace(input, m, true)
	if err != nil {
		t.Fatal(err)
	}
	reversed := []Mapping{m[1], m[0]}
	second, err := Replace(input, reversed, true)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("mapping order changed outcome: %q != %q, err=%v", first, second, err)
	}
}

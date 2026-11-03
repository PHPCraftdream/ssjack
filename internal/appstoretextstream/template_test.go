package appstoretextstream

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/appstoreref"
)

func templateReference(t *testing.T, version byte) (appstoreref.Ref, []byte) {
	t.Helper()
	ref, err := appstoreref.New([16]byte{1}, [16]byte{2}, [16]byte{version}, [16]byte{4})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := appstoreplaceholder.Encode(ref)
	if err != nil {
		t.Fatal(err)
	}
	return ref, encoded
}

func TestTemplateValidationCrossesPlaceholderAndUnicodeBoundaries(t *testing.T) {
	ref, placeholder := templateReference(t, 3)
	input := append(bytes.Repeat([]byte("synthetic \xe2\x82\xac text\n"), 70000), placeholder...)
	input = append(input, []byte(" trailing \xe2\x82\xac")...)
	for _, step := range []int{1, 2, 7, ChunkSize} {
		count, err := ValidateTemplate(context.Background(), tinyReader{input: bytes.NewReader(input), step: step}, []appstoreref.Ref{ref}, uint64(len(input)))
		if err != nil || count != uint64(len(input)) {
			t.Fatal("valid template was changed by chunk boundaries")
		}
	}
}

func TestTemplateValidationRejectsReservedUnknownNoncanonicalAndInvalidText(t *testing.T) {
	ref, placeholder := templateReference(t, 3)
	_, other := templateReference(t, 5)
	for _, input := range [][]byte{
		other,
		bytes.Replace(placeholder, []byte(`{"$ssjack":`), []byte(`{ "$ssjack":`), 1),
		[]byte("prefix $ssjack suffix"),
		[]byte("nul\x00text"),
		[]byte{'a', 0xc3},
		[]byte{0xed, 0xa0, 0x80},
	} {
		if _, err := ValidateTemplate(context.Background(), tinyReader{input: bytes.NewReader(input), step: 1}, []appstoreref.Ref{ref}, 4096); err == nil {
			t.Fatal("template preparation accepted an unknown marker or invalid text")
		}
	}
	if _, err := ValidateTemplate(context.Background(), strings.NewReader("over"), []appstoreref.Ref{ref}, 3); err == nil {
		t.Fatal("template preparation exceeded quota")
	}
	if _, err := ValidateTemplate(context.Background(), bytes.NewReader(placeholder), []appstoreref.Ref{ref, ref}, 4096); err == nil {
		t.Fatal("template preparation accepted duplicate selected references")
	}
}

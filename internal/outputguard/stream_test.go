package outputguard

import (
	"bytes"
	"testing"
)

func reference(patterns [][]byte, data []byte) []byte {
	var result []byte
	for len(data) != 0 {
		longest := 0
		for _, pattern := range patterns {
			if len(pattern) > longest && bytes.HasPrefix(data, pattern) {
				longest = len(pattern)
			}
		}
		if longest == 0 {
			result = append(result, data[0])
			data = data[1:]
		} else {
			result = append(result, Marker...)
			data = data[longest:]
		}
	}
	return result
}

func TestEveryChunkSplitPreservesByteExactLeftmostLongest(t *testing.T) {
	cases := []struct {
		patterns [][]byte
		data     []byte
	}{
		{[][]byte{[]byte("secret")}, []byte("prefix secret suffix secret")},
		{[][]byte{[]byte("ab"), []byte("abc"), []byte("bc"), []byte("cd")}, []byte("abcdabc")},
		{[][]byte{[]byte("aa"), []byte("aaa"), []byte("aaaa")}, []byte("aaaaaaaaaaab")},
		{[][]byte{[]byte("abcd"), []byte("bc"), []byte("def")}, []byte("abcdefbc")},
		{[][]byte{[]byte{0xff, 0, 0xc0}, []byte("pásswörd")}, append([]byte{0xff, 0, 0xc0}, []byte(" pásswörd!")...)},
		{[][]byte{[]byte("secret"), []byte("x"), []byte("[REDACTED]")}, []byte("secret x")},
		{[][]byte{[]byte("secret"), nil, []byte("secret")}, []byte("secre")},
		{nil, []byte("unchanged bytes\x00\xff")},
	}
	for _, tc := range cases {
		snapshot, err := New(tc.patterns)
		if err != nil {
			t.Fatal(err)
		}
		want := reference(tc.patterns, tc.data)
		for split := 0; split <= len(tc.data); split++ {
			var output bytes.Buffer
			writer, err := NewWriter(snapshot, &output)
			if err != nil {
				t.Fatal(err)
			}
			for _, chunk := range [][]byte{tc.data[:split], tc.data[split:]} {
				if n, err := writer.Write(chunk); err != nil || n != len(chunk) {
					t.Fatal("guard did not consume its exact chunk")
				}
			}
			if err := writer.Close(); err != nil || !bytes.Equal(output.Bytes(), want) {
				t.Fatalf("chunk split changed masking: split=%d", split)
			}
			if writer.pending != nil || writer.matches != nil || writer.output != nil {
				t.Fatal("closed stream retained private tail buffers")
			}
			if writer.Close() != nil {
				t.Fatal("joined close was not idempotent")
			}
		}
	}
}

func TestSnapshotOwnsInputsAndWithholdsPrefixUntilStreamEnd(t *testing.T) {
	pattern := []byte("abcdef")
	snapshot, err := New([][]byte{pattern})
	if err != nil {
		t.Fatal(err)
	}
	clear(pattern)
	var output bytes.Buffer
	writer, err := NewWriter(snapshot, &output)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range []byte("abcde") {
		if _, err := writer.Write([]byte{b}); err != nil || output.Len() != 0 {
			t.Fatal("a potential secret prefix escaped before an explicit stream end")
		}
	}
	if _, err := writer.Write([]byte("f")); err != nil || output.String() != Marker {
		t.Fatal("snapshot lost input ownership or reprocessed the marker")
	}
	if writer.Close() != nil {
		t.Fatal("complete guarded stream did not join")
	}
	if _, err := writer.Write([]byte("later")); err != ErrGuard {
		t.Fatal("closed stream accepted more output")
	}
}

func TestAllSmallStreamsAgreeWithIndependentReference(t *testing.T) {
	patterns := [][]byte{[]byte("a"), []byte("aba"), []byte("bab"), []byte("bb"), []byte("baab")}
	snapshot, err := New(patterns)
	if err != nil {
		t.Fatal(err)
	}
	for bits := 0; bits < 256; bits++ {
		data := make([]byte, 8)
		for i := range data {
			data[i] = byte('a' + (bits>>i)&1)
		}
		var output bytes.Buffer
		writer, err := NewWriter(snapshot, &output)
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range data {
			if _, err := writer.Write([]byte{b}); err != nil {
				t.Fatal(err)
			}
		}
		if writer.Close() != nil || !bytes.Equal(output.Bytes(), reference(patterns, data)) {
			t.Fatal("failure links, overlapping suffixes or ring reuse changed masking")
		}
	}
}

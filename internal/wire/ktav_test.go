package wire

import (
	"bytes"
	"math"
	"testing"
)

func TestKtavPreservesCommandBytesAndIntegers(t *testing.T) {
	type payload struct {
		Command string `json:"command"`
		Stdout  []byte `json:"stdout"`
		Offset  int64  `json:"offset"`
	}
	want := payload{
		Command: "printf '%s\\n' 'https://example.test/a:b'\n## this is shell content, not a Ktav comment\nprintf '\\u3042'",
		Stdout:  []byte{0, 255, 128, '\n', 'x'},
		Offset:  math.MaxInt64,
	}
	encoded, err := Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	var framed bytes.Buffer
	if err := Write(&framed, Request{Operation: "start", Data: encoded}); err != nil {
		t.Fatal(err)
	}
	var req Request
	if err := Read(&framed, &req); err != nil {
		t.Fatal(err)
	}
	var got payload
	if err := Decode(req.Data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Command != want.Command || got.Offset != want.Offset || !bytes.Equal(got.Stdout, want.Stdout) {
		t.Fatalf("Ktav round trip changed data: got %+v", got)
	}
}

func TestFrameContainsKtavRatherThanJSON(t *testing.T) {
	var framed bytes.Buffer
	if err := Write(&framed, Auth{Session: "session", EnvToken: "a", DiskToken: "b"}); err != nil {
		t.Fatal(err)
	}
	body := framed.Bytes()[4:]
	if bytes.HasPrefix(bytes.TrimSpace(body), []byte("{")) || !bytes.Contains(body, []byte("session:")) {
		t.Fatalf("expected a Ktav object frame: %q", body)
	}
}

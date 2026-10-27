package driverprotocol

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/driverframe"
)

var tid = base64.RawURLEncoding.EncodeToString(make([]byte, 16))

func request(a, d, r, p, effects, op string) []byte {
	return []byte(`{"protocol":1,"request_id":"` + tid + `","action":"` + a + `","target":"host","kind":"cache","schema_id":"cache.v1","resource_id":"r1","desired":` + d + `,"expected_revision":` + r + `,"plan_digest":` + p + `,"allowed_effects":` + effects + `,"deadline_unix_ms":1,"max_response_bytes":65536,"operation_id":` + op + `}`)
}
func validStructuralRequest(a string) []byte {
	d, rev, digest, op := "null", "null", "null", "null"
	if a == "plan" {
		d, rev = `{}`, `"rev1"`
	}
	if a == "apply" {
		d, rev, digest, op = `{}`, `"rev1"`, `"`+strings.Repeat("a", 64)+`"`, `"`+tid+`"`
	}
	if a == "cancel" || a == "reconcile" {
		digest, op = `"`+strings.Repeat("b", 64)+`"`, `"`+tid+`"`
	}
	return request(a, d, rev, digest, "[]", op)
}
func TestValidStructuralRequests(t *testing.T) {
	for _, a := range []string{"observe", "plan", "apply", "cancel", "reconcile"} {
		if _, e := ValidateStructuralRequest(validStructuralRequest(a)); e != nil {
			t.Errorf("%s: %v", a, e)
		}
	}
}
func TestInvalidStructuralRequests(t *testing.T) {
	b := validStructuralRequest("observe")
	bad := [][]byte{
		request("unknown", "null", "null", "null", "[]", "null"), request("observe", "{}", "null", "null", "[]", "null"),
		request("plan", "null", "null", "null", "[]", "null"), request("apply", "[]", "null", "null", "[]", "null"), request("cancel", "null", "null", "null", "[]", "null"),
		request("observe", "null", "null", "null", `[{"class":"x"}]`, `null`),
		request("observe", "null", "null", "null", `[{"class":"x","summary_id":"y","destructive":false},{"class":"x","summary_id":"y","destructive":false}]`, `null`),
		bytes.Replace(b, []byte(`"protocol":1`), []byte(`"protocol":"1"`), 1),
		bytes.Replace(b, []byte(`"request_id":"`+tid+`"`), []byte(`"request_id":"bad"`), 1),
		bytes.Replace(b, []byte(`"target":"host"`), []byte(`"target":"Bad"`), 1), bytes.Replace(b, []byte(`"resource_id":"r1"`), []byte(`"resource_id":"!"`), 1),
		bytes.Replace(b, []byte(`"max_response_bytes":65536`), []byte(`"max_response_bytes":0`), 1),
		[]byte(`{"x":1,"x":2}`),
	}
	for _, x := range bad {
		if _, e := ValidateStructuralRequest(x); e == nil {
			t.Errorf("accepted %s", x)
		}
	}
}
func response(data string) []byte {
	return []byte(`{"protocol":1,"request_id":"` + tid + `","outcome":"ok","error_code":null,"data":` + data + `}`)
}
func TestAllActionStructuralResponseShapes(t *testing.T) {
	fixtures := map[string]string{
		"observe":   `{"state":"present","revision":null,"projection":{}}`,
		"plan":      `{"effects":[{"class":"file.write","summary_id":"written","destructive":false}],"precondition":null}`,
		"apply":     `{"state":"absent","applied_revision":null,"verified":true,"projection":{}}`,
		"cancel":    `{"cancellation":"pending"}`,
		"reconcile": `{"state":"unknown","applied_revision":null,"delivered_revision":null,"observed_revision":null,"adopted_revision":null,"verified":false,"projection":{}}`,
	}
	for a, data := range fixtures {
		q, e := ValidateStructuralRequest(validStructuralRequest(a))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = ValidateStructuralResponse(q, response(data)); e != nil {
			t.Errorf("%s: %v", a, e)
		}
	}
}
func TestStructuralResponseAdversarial(t *testing.T) {
	q, e := ValidateStructuralRequest(validStructuralRequest("plan"))
	if e != nil {
		t.Fatal(e)
	}
	good := response(`{"effects":[],"precondition":null}`)
	bad := [][]byte{
		bytes.Replace(good, []byte(tid), []byte("bad"), 1),
		bytes.Replace(good, []byte(`"effects":[]`), []byte(`"effects":[{"class":"x","summary_id":"y"}]`), 1),
		bytes.Replace(good, []byte(`"outcome":"ok"`), []byte(`"outcome":"ok","extra":null`), 1),
		[]byte(`{"protocol":1,"request_id":"` + tid + `","outcome":"ok","error_code":null,"data":{"effects":[],"effects":[]}}`),
		[]byte(`{"protocol":1,"request_id":"` + tid + `","outcome":"unsupported","error_code":"wrong","data":null}`),
	}
	for _, b := range bad {
		if _, e = ValidateStructuralResponse(q, b); e == nil {
			t.Errorf("accepted %s", b)
		}
	}
	q.maxStructuralResponse = 1
	if _, e = ValidateStructuralResponse(q, good); e == nil {
		t.Fatal("response cap")
	}
}
func TestDesiredProjectionBounds(t *testing.T) {
	exact := `{"x":"` + strings.Repeat("a", MaxDesired-8) + `"}`
	if len(exact) > MaxDesired {
		t.Fatalf("fixture exceeds desired limit: %d", len(exact))
	}
	if _, e := ValidateStructuralRequest(request("plan", exact, `"rev1"`, `null`, `[]`, `null`)); e != nil {
		t.Fatalf("desired boundary rejected: %v", e)
	}
	over := `{"x":"` + strings.Repeat("a", MaxDesired) + `"}`
	if _, e := ValidateStructuralRequest(request("plan", over, `"rev1"`, `null`, `[]`, `null`)); e == nil {
		t.Fatal("oversize desired accepted")
	}
	q, e := ValidateStructuralRequest(validStructuralRequest("observe"))
	if e != nil {
		t.Fatal(e)
	}
	good := response(`{"state":"present","revision":null,"projection":{"x":"` + strings.Repeat("a", MaxProjection-8) + `"}}`)
	if _, e = ValidateStructuralResponse(q, good); e != nil {
		t.Fatalf("projection boundary rejected: %v", e)
	}
	overStructuralResponse := response(`{"state":"present","revision":null,"projection":{"x":"` + strings.Repeat("a", MaxProjection) + `"}}`)
	if _, e = ValidateStructuralResponse(q, overStructuralResponse); e == nil {
		t.Fatal("oversize projection accepted")
	}
}
func TestParserStructuralBoundsAndEscapes(t *testing.T) {
	for _, b := range [][]byte{[]byte(`{"a":1,"\u0061":2}`), []byte(`"\ud800"`), []byte(strings.Repeat("[", MaxDepth+1) + "0" + strings.Repeat("]", MaxDepth+1)), []byte("[" + strings.Repeat("0,", 256) + "0]")} {
		if _, e := ParseJSON(b); e == nil {
			t.Errorf("accepted structural adversary %q", b)
		}
	}
	makeNested := func(lastSize int) []byte {
		arrays := make([]string, 16)
		for i := range arrays {
			size := 255
			if i == len(arrays)-1 {
				size = lastSize
			}
			arrays[i] = "[" + strings.TrimSuffix(strings.Repeat("0,", size), ",") + "]"
		}
		return []byte("[" + strings.Join(arrays, ",") + "]")
	}
	if _, e := ParseJSON(makeNested(254)); e != nil {
		t.Fatalf("4096-node boundary rejected: %v", e)
	}
	if _, e := ParseJSON(makeNested(255)); e == nil {
		t.Fatal("4097-node fixture accepted")
	}
}
func TestInvalidEachStructuralResponseAction(t *testing.T) {
	fixtures := map[string]string{"observe": `{"state":"present","revision":null,"projection":{}}`, "plan": `{"effects":[],"precondition":null}`, "apply": `{"state":"present","applied_revision":null,"verified":true,"projection":{}}`, "cancel": `{"cancellation":"pending"}`, "reconcile": `{"state":"unknown","applied_revision":null,"delivered_revision":null,"observed_revision":null,"adopted_revision":null,"verified":false,"projection":{}}`}
	for action, data := range fixtures {
		q, e := ValidateStructuralRequest(validStructuralRequest(action))
		if e != nil {
			t.Fatal(e)
		}
		wrong := `null`
		if action != "cancel" {
			wrong = `{"wrong":null}`
		}
		if _, e = ValidateStructuralResponse(q, response(wrong)); e == nil {
			t.Errorf("%s accepted wrong DTO", action)
		}
		badType := strings.Replace(data, ":null", `:false`, 1)
		if action == "cancel" {
			badType = `{"cancellation":null}`
		}
		if _, e = ValidateStructuralResponse(q, response(badType)); e == nil {
			t.Errorf("%s accepted wrong/null type", action)
		}
		unknown := strings.TrimSuffix(data, "}") + `,"unexpected":null}`
		if _, e = ValidateStructuralResponse(q, response(unknown)); e == nil {
			t.Errorf("%s accepted unknown field", action)
		}
	}
}
func TestStructuralResponseOutcomes(t *testing.T) {
	q, e := ValidateStructuralRequest(validStructuralRequest("observe"))
	if e != nil {
		t.Fatal(e)
	}
	for outcome, code := range map[string]string{"conflict": "PRECONDITION_FAILED", "unsupported": "POLICY_DENIED", "no_effect_failure": "BACKEND_FAILED", "unknown": "OUTCOME_UNKNOWN"} {
		b := []byte(`{"protocol":1,"request_id":"` + tid + `","outcome":"` + outcome + `","error_code":"` + code + `","data":null}`)
		if _, e = ValidateStructuralResponse(q, b); e != nil {
			t.Errorf("%s: %v", outcome, e)
		}
	}
}
func TestStructuralResponseFrameDuplicates(t *testing.T) {
	q, e := ValidateStructuralRequest(validStructuralRequest("observe"))
	if e != nil {
		t.Fatal(e)
	}
	good := response(`{"state":"present","revision":null,"projection":{}}`)
	var w bytes.Buffer
	if e = driverframe.Write(&w, good); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadStructuralResponse(q, &w); e != nil {
		t.Fatal(e)
	}
	w.Reset()
	_ = driverframe.Write(&w, good)
	_ = driverframe.Write(&w, good)
	if _, e = ReadStructuralResponse(q, &w); !errors.Is(e, driverframe.ErrTrailing) {
		t.Fatalf("duplicate frame accepted: %v", e)
	}
}
func TestParserCanonicalAndFrames(t *testing.T) {
	bad := [][]byte{[]byte(`{"x":1,"x":2}`), []byte(`{"x":1.0}`), []byte(`{"x":1e2}`), []byte(`{"x":-0}`), []byte(`{"x":9007199254740992}`), []byte(`{"x":"é"}`), []byte(`{"x":"\ud800"}`), []byte(`{} false`), []byte{0xff}, make([]byte, driverframe.MaxPayload+1)}
	for _, b := range bad {
		if _, e := ParseJSON(b); e == nil {
			t.Errorf("accepted %q", b)
		}
	}
	v, e := ParseJSON([]byte(`{"z":1,"a":"x"}`))
	if e != nil {
		t.Fatal(e)
	}
	c, e := canonicalBytes(v)
	if e != nil || string(c) != `{"a":"x","z":1}` {
		t.Fatalf("canonical %q %v", c, e)
	}
	b := validStructuralRequest("observe")
	var w bytes.Buffer
	if e = driverframe.Write(&w, b); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadStructuralRequest(&w); e != nil {
		t.Fatal(e)
	}
	w.Reset()
	_ = driverframe.Write(&w, b)
	w.WriteByte(0)
	if _, e = ReadStructuralRequest(&w); !errors.Is(e, driverframe.ErrTrailing) {
		t.Fatalf("extra noise: %v", e)
	}
	if _, e = ReadStructuralRequest(bytes.NewReader([]byte{0, 0})); e != io.ErrUnexpectedEOF {
		t.Fatalf("truncated: %v", e)
	}
	w.Reset()
	if e = WriteStructuralFrame(&w, b); e != nil {
		t.Fatal(e)
	}
}

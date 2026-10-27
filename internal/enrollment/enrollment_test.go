package enrollment

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func validJSON() string {
	return `{"format":"` + Format + `","enrollment_id":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 16)) + `","driver_id":"driver.one-v1","driver_protocol":1}`
}

func TestParseValid(t *testing.T) {
	m, err := Parse([]byte(validJSON()))
	if err != nil {
		t.Fatal(err)
	}
	if m.EnrollmentID() != base64.RawURLEncoding.EncodeToString(make([]byte, 16)) || m.DriverID() != "driver.one-v1" || m.DriverProtocol() != 1 {
		t.Fatalf("unexpected metadata: %#v", m)
	}
}

func TestParseAdversarial(t *testing.T) {
	base := validJSON()
	id := base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	cases := []struct{ name, input string }{
		{"unknown", strings.TrimSuffix(base, "}") + `,"extra":true}`}, {"duplicate", strings.TrimSuffix(base, "}") + `,"format":"` + Format + `"}`}, {"missing", `{"format":"` + Format + `"}`},
		{"null-format", strings.Replace(base, `"format":"`+Format+`"`, `"format":null`, 1)}, {"null-id", strings.Replace(base, `"enrollment_id":"`+id+`"`, `"enrollment_id":null`, 1)}, {"null-driver", strings.Replace(base, `"driver_id":"driver.one-v1"`, `"driver_id":null`, 1)}, {"null-protocol", strings.Replace(base, `"driver_protocol":1`, `"driver_protocol":null`, 1)},
		{"quoted-protocol", strings.Replace(base, `"driver_protocol":1`, `"driver_protocol":"1"`, 1)}, {"float", strings.Replace(base, `"driver_protocol":1`, `"driver_protocol":1.0`, 1)}, {"noncanonical-id", strings.Replace(base, id, base64.URLEncoding.EncodeToString(make([]byte, 16)), 1)}, {"bad-name", strings.Replace(base, "driver.one-v1", "../driver", 1)}, {"uppercase-name", strings.Replace(base, "driver.one-v1", "Driver.one-v1", 1)},
		{"trailing", base + ` {}`}, {"invalid-json", strings.Replace(base, `"driver_protocol":1`, `"driver_protocol":01`, 1)}, {"invalid-utf8", base + string([]byte{0xff})}, {"oversize", base + strings.Repeat(" ", MaxSize)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse([]byte(tc.input)); err == nil {
				t.Fatal("accepted invalid input")
			}
		})
	}
}

func TestPolicySnapshotStrictBinding(t *testing.T) {
	const good = `{"format":"ssjack-policy-subset-v1","enrollment_id":"AAAAAAAAAAAAAAAAAAAAAA","driver_id":"before","driver_protocol":1,"revision":"rev-1"}`
	metadata, err := Parse([]byte(`{"format":"ssjack-enrollment-metadata-v1","enrollment_id":"AAAAAAAAAAAAAAAAAAAAAA","driver_id":"before","driver_protocol":1}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		good,
		strings.Replace(good, `"revision":"rev-1"`, `"revision":"rev-\u0031"`, 1),
	} {
		if _, err := ParsePolicy([]byte(raw), metadata); err != nil {
			t.Fatalf("rejected valid snapshot %s: %v", raw, err)
		}
	}
	invalid := []string{
		`null`, `[]`,
		`{"format":null,"enrollment_id":"AAAAAAAAAAAAAAAAAAAAAA","driver_id":"before","driver_protocol":1,"revision":"rev-1"}`,
		`{"format":"ssjack-policy-subset-v1","enrollment_id":null,"driver_id":"before","driver_protocol":1,"revision":"rev-1"}`,
		`{"format":"ssjack-policy-subset-v1","enrollment_id":"AAAAAAAAAAAAAAAAAAAAAA","driver_id":null,"driver_protocol":1,"revision":"rev-1"}`,
		`{"format":"ssjack-policy-subset-v1","enrollment_id":"AAAAAAAAAAAAAAAAAAAAAA","driver_id":"before","driver_protocol":null,"revision":"rev-1"}`,
		`{"format":"ssjack-policy-subset-v1","enrollment_id":"AAAAAAAAAAAAAAAAAAAAAA","driver_id":"before","driver_protocol":1,"revision":null}`,
		strings.Replace(good, `"driver_protocol":1`, `"driver_protocol":"1"`, 1),
		strings.Replace(good, `"format":"ssjack-policy-subset-v1",`, ``, 1),
		strings.Replace(good, `,"enrollment_id":"AAAAAAAAAAAAAAAAAAAAAA"`, ``, 1),
		strings.Replace(good, `,"driver_id":"before"`, ``, 1),
		strings.Replace(good, `,"driver_protocol":1`, ``, 1),
		strings.Replace(good, `,"revision":"rev-1"`, ``, 1),
		strings.Replace(good, `"revision":"rev-1"`, `"revision":"rev-1","revision":"r2"`, 1),
		strings.Replace(good, `"revision":"rev-1"`, `"revision":"rev-1","\u0072evision":"r2"`, 1),
		strings.Replace(good, `"driver_protocol":1`, `"driver_protocol":1.0`, 1),
		strings.Replace(good, `"driver_id":"before"`, `"driver_id":"after"`, 1),
		strings.Replace(good, `"enrollment_id":"AAAAAAAAAAAAAAAAAAAAAA"`, `"enrollment_id":"BBBBBBBBBBBBBBBBBBBBBB"`, 1),
		`{"format":"ssjack-policy-subset-v1","enrollment_id":"AAAAAAAAAAAAAAAAAAAAAA","driver_id":"before","driver_protocol":1,"revision":"\uD800"}`,
		good + ` {}`,
	}
	for _, raw := range invalid {
		if _, err := ParsePolicy([]byte(raw), metadata); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	if _, err := ParsePolicy([]byte(good), Metadata{}); err == nil {
		t.Fatal("accepted invalid metadata identity")
	}
	if _, err := ParsePolicy(make([]byte, MaxPolicySize+1), metadata); err == nil {
		t.Fatal("accepted oversized snapshot")
	}
}
func TestLoadPathAndNoFollow(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "metadata.json")
	if err := os.WriteFile(file, []byte(validJSON()), 0600); err != nil {
		t.Fatal(err)
	}
	switch runtime.GOOS {
	case "linux", "darwin", "freebsd", "openbsd", "netbsd", "dragonfly", "solaris":
	default:
		if _, err := Load(file); err == nil || !strings.Contains(err.Error(), "unsupported") {
			t.Fatalf("expected unsupported error, got %v", err)
		}
		return
	}
	if _, err := Load(file); err != nil {
		t.Fatal(err)
	}
	traversal := dir + string(os.PathSeparator) + ".." + string(os.PathSeparator) + "escape.json"
	for _, p := range []string{traversal, dir} {
		if _, err := Load(p); err == nil {
			t.Fatalf("accepted unsafe path %q", p)
		}
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(file, link); err != nil {
		t.Fatalf("create leaf symlink: %v", err)
	}
	if _, err := Load(link); err == nil {
		t.Fatal("accepted leaf symlink")
	}
	parent := filepath.Join(dir, "parent-link")
	if err := os.Symlink(dir, parent); err != nil {
		t.Fatalf("create parent symlink: %v", err)
	}
	if _, err := Load(filepath.Join(parent, "metadata.json")); err == nil {
		t.Fatal("accepted parent symlink")
	}
	large := filepath.Join(dir, "large.json")
	if err := os.WriteFile(large, []byte(validJSON()+strings.Repeat(" ", MaxSize)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(large); err == nil {
		t.Fatal("accepted oversized file")
	}
	fifo := filepath.Join(dir, "pipe")
	if err := makeFIFO(fifo); err == nil {
		if _, err := Load(fifo); err == nil {
			t.Fatal("accepted special file")
		}
	}
}

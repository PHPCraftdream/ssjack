package enrollment

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"
)

const PolicyFormat = "ssjack-policy-subset-v1"
const MaxPolicySize = 4096

var revisionPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// Policy is a human-installed, non-authorizing deny-all snapshot.
type Policy struct {
	enrollmentID, driverID, revision, digest string
	protocol                                 int
}

func (p Policy) EnrollmentID() string { return p.enrollmentID }
func (p Policy) DriverID() string     { return p.driverID }
func (p Policy) DriverProtocol() int  { return p.protocol }
func (p Policy) Revision() string     { return p.revision }
func (p Policy) Digest() string       { return p.digest }

// ParsePolicy accepts exactly the closed schema; null is not a valid value.
// Digest is SHA-256 of the exact input bytes (raw byte identity), not a v1 canonical digest.
func ParsePolicy(data []byte, metadata Metadata) (Policy, error) {
	var p Policy
	if len(data) > MaxPolicySize {
		return p, errors.New("policy exceeds size limit")
	}
	if !utf8.Valid(data) {
		return p, errors.New("policy must use valid UTF-8")
	}
	d := json.NewDecoder(strings.NewReader(string(data)))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return p, errors.New("policy must be an object")
	}
	values := map[string]json.RawMessage{}
	for d.More() {
		tok, e := d.Token()
		if e != nil {
			return p, e
		}
		key, ok := tok.(string)
		if !ok {
			return p, errors.New("invalid policy key")
		}
		switch key {
		case "format", "enrollment_id", "driver_id", "driver_protocol", "revision":
		default:
			return p, fmt.Errorf("unknown policy field %q", key)
		}
		if _, ok := values[key]; ok {
			return p, fmt.Errorf("duplicate policy field %q", key)
		}
		var raw json.RawMessage
		if e = d.Decode(&raw); e != nil {
			return p, e
		}
		values[key] = raw
	}
	if _, err = d.Token(); err != nil {
		return p, err
	}
	if _, err = d.Token(); err != io.EOF {
		return p, errors.New("trailing policy JSON")
	}
	for _, k := range []string{"format", "enrollment_id", "driver_id", "driver_protocol", "revision"} {
		if _, ok := values[k]; !ok {
			return p, fmt.Errorf("missing policy field %q", k)
		}
	}
	var format, id, driver, rev string
	for k, dst := range map[string]*string{"format": &format, "enrollment_id": &id, "driver_id": &driver, "revision": &rev} {
		if err = json.Unmarshal(values[k], dst); err != nil {
			return p, fmt.Errorf("%s must be a string", k)
		}
	}
	if string(values["driver_protocol"]) != "1" {
		return p, errors.New("driver_protocol must be integer 1")
	}
	if format != PolicyFormat {
		return p, errors.New("unsupported policy format")
	}
	if id != metadata.EnrollmentID() || driver != metadata.DriverID() || metadata.DriverProtocol() != 1 {
		return p, errors.New("policy identity does not match enrollment metadata")
	}
	if !revisionPattern.MatchString(rev) {
		return p, errors.New("invalid policy revision")
	}
	sum := sha256.Sum256(data)
	return Policy{id, driver, rev, hex.EncodeToString(sum[:]), 1}, nil
}

// LoadPolicy reads a bounded file using the same safe-open policy as enrollment metadata.
func LoadPolicy(path string, metadata Metadata) (Policy, error) {
	f, err := openSafeFile(path)
	if err != nil {
		return Policy{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxPolicySize+1))
	if err != nil {
		return Policy{}, err
	}
	return ParsePolicy(data, metadata)
}

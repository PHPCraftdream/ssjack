// Package enrollment parses explicitly supplied, non-authorizing driver metadata.
package enrollment

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"
)

const Format = "ssjack-enrollment-metadata-v1"
const MaxSize = 4096

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)

// Metadata is validated descriptive data only; it grants no authority.
// Its fields are private and its accessors return immutable scalar values.
type Metadata struct {
	enrollmentID   string
	driverID       string
	driverProtocol int
}

func (m Metadata) EnrollmentID() string { return m.enrollmentID }
func (m Metadata) DriverID() string     { return m.driverID }
func (m Metadata) DriverProtocol() int  { return m.driverProtocol }

// Parse validates one closed v1 metadata JSON object.
func Parse(data []byte) (Metadata, error) {
	var zero Metadata
	if len(data) > MaxSize {
		return zero, errors.New("enrollment metadata exceeds size limit")
	}
	if !utf8.Valid(data) {
		return zero, errors.New("enrollment metadata is not valid UTF-8")
	}
	d := json.NewDecoder(strings.NewReader(string(data)))
	t, err := d.Token()
	if err != nil {
		return zero, err
	}
	if t != json.Delim('{') {
		return zero, errors.New("metadata must be an object")
	}
	values := map[string]json.RawMessage{}
	for d.More() {
		keyToken, err := d.Token()
		if err != nil {
			return zero, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return zero, errors.New("invalid object key")
		}
		switch key {
		case "format", "enrollment_id", "driver_id", "driver_protocol":
		default:
			return zero, fmt.Errorf("unknown metadata field %q", key)
		}
		if _, exists := values[key]; exists {
			return zero, fmt.Errorf("duplicate metadata field %q", key)
		}
		var raw json.RawMessage
		if err := d.Decode(&raw); err != nil {
			return zero, err
		}
		values[key] = raw
	}
	if _, err := d.Token(); err != nil {
		return zero, err
	}
	if _, err := d.Token(); err != io.EOF {
		return zero, errors.New("trailing JSON data")
	}
	for _, key := range []string{"format", "enrollment_id", "driver_id", "driver_protocol"} {
		if _, ok := values[key]; !ok {
			return zero, fmt.Errorf("missing metadata field %q", key)
		}
	}
	var format, id, driver string
	if err := json.Unmarshal(values["format"], &format); err != nil {
		return zero, errors.New("format must be a string")
	}
	if err := json.Unmarshal(values["enrollment_id"], &id); err != nil {
		return zero, errors.New("enrollment_id must be a string")
	}
	if err := json.Unmarshal(values["driver_id"], &driver); err != nil {
		return zero, errors.New("driver_id must be a string")
	}
	if string(values["driver_protocol"]) != "1" {
		return zero, errors.New("driver_protocol must be integer 1")
	}
	if format != Format {
		return zero, errors.New("unsupported metadata format")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(id)
	if err != nil || len(decoded) != 16 || base64.RawURLEncoding.EncodeToString(decoded) != id {
		return zero, errors.New("enrollment_id must be canonical 16-byte unpadded base64url")
	}
	if !namePattern.MatchString(driver) {
		return zero, errors.New("invalid driver_id")
	}
	return Metadata{id, driver, 1}, nil
}

// Load opens an absolute file through a platform-specific no-follow routine.
// The implementation rejects symlinks at every path component on supported
// Unix systems. Unsupported platforms fail closed.
func Load(path string) (Metadata, error) {
	var zero Metadata
	f, err := openSafeFile(path)
	if err != nil {
		return zero, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxSize+1))
	if err != nil {
		return zero, err
	}
	return Parse(data)
}

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

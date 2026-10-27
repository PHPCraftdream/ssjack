// Package enrollment parses explicitly supplied, non-authorizing driver metadata.
package enrollment

import (
	"encoding/base64"
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

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

const SnapshotFormat = "ssjack-enrollment-identity-subset-v1"
const MaxSnapshotSize = 16384
const maxSnapshotDepth = 16

var snapshotDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var snapshotNamePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)

type Snapshot struct {
	enrollmentID, driverID, executablePath, executableDigest string
	configurationDigest, issuer, subject                     string
	policyRevision, policyDigest, digest                     string
	artifacts, dependencies                                  map[string]string
}

func (s Snapshot) EnrollmentID() string                 { return s.enrollmentID }
func (s Snapshot) DriverID() string                     { return s.driverID }
func (s Snapshot) ExecutablePath() string               { return s.executablePath }
func (s Snapshot) ExecutableSHA256() string             { return s.executableDigest }
func (s Snapshot) ConfigurationDigest() string          { return s.configurationDigest }
func (s Snapshot) Issuer() string                       { return s.issuer }
func (s Snapshot) Subject() string                      { return s.subject }
func (s Snapshot) PolicyRevision() string               { return s.policyRevision }
func (s Snapshot) PolicyDigest() string                 { return s.policyDigest }
func (s Snapshot) Digest() string                       { return s.digest }
func (s Snapshot) ArtifactDigests() map[string]string   { return cloneDigests(s.artifacts) }
func (s Snapshot) DependencyDigests() map[string]string { return cloneDigests(s.dependencies) }

// Artifact/dependency map keys are conservative opaque labels, not v1-defined semantic bindings.
func cloneDigests(m map[string]string) map[string]string {
	n := make(map[string]string, len(m))
	for k, v := range m {
		n[k] = v
	}
	return n
}

// ParseSnapshot validates a bounded identity subset only; it is not v1 enrollment validation, authorization, or artifact verification.
func ParseSnapshot(data []byte, metadata Metadata, policy Policy) (Snapshot, error) {
	var z Snapshot
	if len(data) > MaxSnapshotSize {
		return z, errors.New("snapshot exceeds size limit")
	}
	if !utf8.Valid(data) {
		return z, errors.New("snapshot is not valid UTF-8")
	}
	d := json.NewDecoder(strings.NewReader(string(data)))
	if err := checkUniqueJSON(d); err != nil {
		return z, err
	}
	var root map[string]json.RawMessage
	d = json.NewDecoder(strings.NewReader(string(data)))
	if err := d.Decode(&root); err != nil {
		return z, err
	}
	if err := ensureEOF(d); err != nil {
		return z, err
	}
	if !asciiStrings(data) {
		return z, errors.New("snapshot strings must be printable ASCII")
	}
	allowed := map[string]bool{"format": true, "enrollment_id": true, "driver_id": true, "driver_protocol": true, "executable": true, "artifact_digests": true, "dependency_digests": true, "configuration_digest": true, "principal": true}
	if len(root) > 128 || len(root) != len(allowed) {
		return z, errors.New("snapshot has missing or invalid fields")
	}
	for k := range root {
		if !allowed[k] {
			return z, fmt.Errorf("unknown snapshot field %q", k)
		}
	}
	var format, id, driver string
	if err := json.Unmarshal(root["format"], &format); err != nil || json.Unmarshal(root["enrollment_id"], &id) != nil || json.Unmarshal(root["driver_id"], &driver) != nil {
		return z, errors.New("identity fields must be strings")
	}
	if format != SnapshotFormat || id != metadata.EnrollmentID() || driver != metadata.DriverID() || metadata.DriverProtocol() != 1 || policy.EnrollmentID() != id || policy.DriverID() != driver || policy.DriverProtocol() != 1 || policy.Revision() == "" || !revisionPattern.MatchString(policy.Revision()) || !snapshotDigestPattern.MatchString(policy.Digest()) {
		return z, errors.New("snapshot identity or policy mismatch")
	}
	if string(root["driver_protocol"]) != "1" {
		return z, errors.New("driver_protocol must be integer 1")
	}
	var executable, principal map[string]json.RawMessage
	if json.Unmarshal(root["executable"], &executable) != nil || len(executable) != 2 || json.Unmarshal(root["principal"], &principal) != nil || len(principal) != 2 {
		return z, errors.New("invalid executable or principal record")
	}
	for k := range executable {
		if k != "path" && k != "sha256" {
			return z, errors.New("unknown executable field")
		}
	}
	for k := range principal {
		if k != "issuer" && k != "subject" {
			return z, errors.New("unknown principal field")
		}
	}
	var path, exhash, cfg, issuer, subject string
	for k, dst := range map[string]*string{"path": &path, "sha256": &exhash} {
		if json.Unmarshal(executable[k], dst) != nil {
			return z, errors.New("invalid executable value")
		}
	}
	for k, dst := range map[string]*string{"issuer": &issuer, "subject": &subject} {
		if json.Unmarshal(principal[k], dst) != nil {
			return z, errors.New("invalid principal value")
		}
	}
	if json.Unmarshal(root["configuration_digest"], &cfg) != nil {
		return z, errors.New("invalid configuration digest")
	}
	if !safeAbsolutePath(path) || !snapshotDigestPattern.MatchString(exhash) || !snapshotDigestPattern.MatchString(cfg) || len(issuer) == 0 || len(issuer) > 256 || len(subject) == 0 || len(subject) > 256 {
		return z, errors.New("invalid path, digest, or principal")
	}
	artifacts, err := parseDigestMap(root["artifact_digests"])
	if err != nil || len(artifacts) == 0 {
		return z, errors.New("invalid artifact digest map")
	}
	dependencies, err := parseDigestMap(root["dependency_digests"])
	if err != nil {
		return z, errors.New("invalid dependency digest map")
	}
	sum := sha256.Sum256(data)
	return Snapshot{enrollmentID: id, driverID: driver, executablePath: path, executableDigest: exhash, configurationDigest: cfg, issuer: issuer, subject: subject, policyRevision: policy.Revision(), policyDigest: policy.Digest(), artifacts: artifacts, dependencies: dependencies, digest: hex.EncodeToString(sum[:])}, nil
}
func LoadSnapshot(path string, metadata Metadata, policy Policy) (Snapshot, error) {
	f, err := openSafeFile(path)
	if err != nil {
		return Snapshot{}, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxSnapshotSize+1))
	if err != nil {
		return Snapshot{}, err
	}
	return ParseSnapshot(b, metadata, policy)
}
func checkUniqueJSON(d *json.Decoder) error {
	var walk func(int) error
	walk = func(depth int) error {
		if depth > maxSnapshotDepth {
			return errors.New("snapshot JSON nesting exceeds limit")
		}
		t, e := d.Token()
		if e != nil {
			return e
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		if delim == '{' {
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				key, ok := k.(string)
				if !ok || seen[key] {
					return errors.New("duplicate or invalid JSON object key")
				}
				seen[key] = true
				if e = walk(depth + 1); e != nil {
					return e
				}
			}
			_, e = d.Token()
			return e
		}
		if delim == '[' {
			for d.More() {
				if e := walk(depth + 1); e != nil {
					return e
				}
			}
			_, e = d.Token()
			return e
		}
		return errors.New("invalid JSON delimiter")
	}
	if e := walk(0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return errors.New("trailing snapshot JSON")
	}
	return nil
}
func ensureEOF(d *json.Decoder) error {
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return errors.New("trailing snapshot JSON")
	}
	return nil
}
func parseDigestMap(raw json.RawMessage) (map[string]string, error) {
	var rawMap map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &rawMap) != nil || rawMap == nil || len(rawMap) > 128 {
		return nil, errors.New("invalid digest map")
	}
	out := make(map[string]string, len(rawMap))
	for k, v := range rawMap {
		var digest string
		if !snapshotNamePattern.MatchString(k) || json.Unmarshal(v, &digest) != nil || !snapshotDigestPattern.MatchString(digest) {
			return nil, errors.New("invalid digest entry")
		}
		out[k] = digest
	}
	return out, nil
}
func asciiStrings(b []byte) bool {
	var x any
	if json.Unmarshal(b, &x) != nil {
		return false
	}
	var check func(any) bool
	check = func(v any) bool {
		switch t := v.(type) {
		case string:
			for _, r := range t {
				if r < 0x20 || r > 0x7e {
					return false
				}
			}
		case []any:
			for _, e := range t {
				if !check(e) {
					return false
				}
			}
		case map[string]any:
			for k, e := range t {
				for _, r := range k {
					if r < 0x20 || r > 0x7e {
						return false
					}
				}
				if !check(e) {
					return false
				}
			}
		}
		return true
	}
	return check(x)
}
func safeAbsolutePath(p string) bool {
	if p == "" || len(p) > 4096 || p == "/" || strings.HasSuffix(p, "/") || strings.ContainsAny(p, "\\\x00") || !strings.HasPrefix(p, "/") || strings.Contains(p, "//") {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if part == "." || part == ".." {
			return false
		}
		for _, r := range part {
			if r < 0x20 || r > 0x7e {
				return false
			}
		}
	}
	return true
}

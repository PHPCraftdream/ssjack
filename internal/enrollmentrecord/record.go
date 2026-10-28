package enrollmentrecord

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"

	"github.com/PHPCraftdream/ssjack/internal/driverprotocol"
	"github.com/PHPCraftdream/ssjack/internal/enrollment"
)

// RecordFormat identifies a deliberately incomplete enrollment subset.
const RecordFormat = "ssjack-enrollment-record-subset-v1"
const MaxRecordSize = 65536

var recordDigestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
var recordKindRE = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)

// SchemaPin is an exact embedded desired/projection document pin.
type SchemaPin struct {
	id, digest string
	document   []byte
}

func (s SchemaPin) ID() string       { return s.id }
func (s SchemaPin) Digest() string   { return s.digest }
func (s SchemaPin) Document() []byte { return append([]byte(nil), s.document...) }

// Record is an immutable descriptive subset; construction grants no authority.
type KindPin struct{ name, desiredSchemaID, projectionSchemaID string }

func (k KindPin) Name() string               { return k.name }
func (k KindPin) DesiredSchemaID() string    { return k.desiredSchemaID }
func (k KindPin) ProjectionSchemaID() string { return k.projectionSchemaID }

type Record struct {
	id, driver, executablePath, executableDigest, configurationDigest string
	issuer, subject, digest                                           string
	protocol                                                          int
	schemas                                                           map[string]SchemaPin
	kinds                                                             []KindPin
	metadata                                                          enrollment.Metadata
	policy                                                            enrollment.Policy
}

func (r Record) EnrollmentID() string        { return r.id }
func (r Record) DriverID() string            { return r.driver }
func (r Record) ExecutablePath() string      { return r.executablePath }
func (r Record) ExecutableSHA256() string    { return r.executableDigest }
func (r Record) ConfigurationSHA256() string { return r.configurationDigest }
func (r Record) Principal() (string, string) { return r.issuer, r.subject }
func (r Record) Digest() string              { return r.digest }
func (r Record) PolicyRevision() string      { return r.policy.Revision() }
func (r Record) PolicyDigest() string        { return r.policy.Digest() }
func (r Record) Kinds() []KindPin {
	out := make([]KindPin, 0, len(r.kinds))
	for _, k := range r.kinds {
		out = append(out, k)
	}
	return out
}
func (r Record) Schema(id string) (SchemaPin, bool) {
	s, ok := r.schemas[id]
	s.document = append([]byte(nil), s.document...)
	return s, ok
}

// ParseRecord accepts only its closed ASCII-only subset, binding metadata and deny-only policy.
// Embedded schemas are checked against supplied digests; provenance is external.
func ParseRecord(data []byte, metadata enrollment.Metadata, snapshot enrollment.Snapshot, policy enrollment.Policy) (Record, error) {
	var zero Record
	if len(data) == 0 || len(data) > MaxRecordSize || metadata.DriverProtocol() != 1 || snapshot.EnrollmentID() != metadata.EnrollmentID() || snapshot.DriverID() != metadata.DriverID() || policy.EnrollmentID() != metadata.EnrollmentID() || policy.DriverID() != metadata.DriverID() || policy.DriverProtocol() != 1 || policy.Digest() == "" || snapshot.PolicyRevision() != policy.Revision() || snapshot.PolicyDigest() != policy.Digest() {
		return zero, errors.New("invalid record bounds or identity binding")
	}
	return parseRecord(data, metadata, snapshot, policy, zero)
}

func parseRecord(data []byte, metadata enrollment.Metadata, snapshot enrollment.Snapshot, policy enrollment.Policy, zero Record) (Record, error) {
	v, err := driverprotocol.ParseJSON(data)
	if err != nil {
		return zero, err
	}
	root, ok := v.(map[string]any)
	if !ok || !closed(root, "format", "enrollment_id", "driver_id", "driver_protocol", "executable", "configuration_digest", "principal", "schemas", "kinds") {
		return zero, errors.New("record fields do not match closed subset")
	}
	format, fok := root["format"].(string)
	id, iok := root["enrollment_id"].(string)
	driver, dok := root["driver_id"].(string)
	protocol, pok := root["driver_protocol"].(int64)
	if !fok || !iok || !dok || !pok || format != RecordFormat || id != metadata.EnrollmentID() || driver != metadata.DriverID() || protocol != 1 {
		return zero, errors.New("record metadata identity mismatch")
	}
	exe, ok := root["executable"].(map[string]any)
	if !ok || !closed(exe, "path", "sha256") {
		return zero, errors.New("invalid executable record")
	}
	path, ok := exe["path"].(string)
	if !ok || path != snapshot.ExecutablePath() {
		return zero, errors.New("unsupported executable path")
	}
	exhash, ok := exe["sha256"].(string)
	if !ok || !recordDigestRE.MatchString(exhash) || exhash != snapshot.ExecutableSHA256() {
		return zero, errors.New("invalid executable digest")
	}
	cfg, ok := root["configuration_digest"].(string)
	if !ok || !recordDigestRE.MatchString(cfg) || cfg != snapshot.ConfigurationDigest() {
		return zero, errors.New("invalid configuration digest")
	}
	principal, ok := root["principal"].(map[string]any)
	if !ok || !closed(principal, "issuer", "subject") {
		return zero, errors.New("invalid principal record")
	}
	issuer, iok := principal["issuer"].(string)
	subject, sok := principal["subject"].(string)
	if !iok || !sok || issuer == "" || subject == "" || issuer != snapshot.Issuer() || subject != snapshot.Subject() {
		return zero, errors.New("invalid principal values")
	}
	schemaList, ok := root["schemas"].([]any)
	if !ok || len(schemaList) < 1 || len(schemaList) > 256 {
		return zero, errors.New("invalid schema list")
	}
	schemas := make(map[string]SchemaPin, len(schemaList))
	for _, item := range schemaList {
		entry, ok := item.(map[string]any)
		if !ok || !closed(entry, "id", "digest", "document") {
			return zero, errors.New("invalid schema entry")
		}
		sid, sok := entry["id"].(string)
		digest, dok := entry["digest"].(string)
		doc, bok := entry["document"].(map[string]any)
		if !sok || !dok || !bok || !recordDigestRE.MatchString(digest) || !recordName(sid) {
			return zero, errors.New("invalid schema identity")
		}
		if _, exists := schemas[sid]; exists {
			return zero, errors.New("duplicate schema id")
		}
		canonical, e := json.Marshal(doc)
		if e == nil {
			canonical, e = driverprotocol.CanonicalSchemaDocument(canonical)
		}
		if e != nil {
			return zero, e
		}
		if e := driverprotocol.ValidateSchemaDocument(canonical, sid, digest); e != nil {
			return zero, e
		}
		schemas[sid] = SchemaPin{id: sid, digest: digest, document: append([]byte(nil), canonical...)}
	}
	kindItems, ok := root["kinds"].([]any)
	if !ok || len(kindItems) < 1 || len(kindItems) > 128 {
		return zero, errors.New("invalid kind list")
	}
	kinds := make([]KindPin, 0, len(kindItems))
	seenKinds := map[string]bool{}
	for i, item := range kindItems {
		km, ok := item.(map[string]any)
		if !ok || !closed(km, "name", "desired_schema_id", "projection_schema_id") {
			return zero, errors.New("invalid kind record")
		}
		name, nok := km["name"].(string)
		desired, dok := km["desired_schema_id"].(string)
		projection, pok := km["projection_schema_id"].(string)
		if !nok || !dok || !pok || !recordKindRE.MatchString(name) || seenKinds[name] {
			return zero, errors.New("invalid or duplicate kind")
		}
		if i > 0 && kinds[i-1].name >= name {
			return zero, errors.New("kinds must be sorted and unique")
		}
		if _, ok := schemas[desired]; !ok {
			return zero, errors.New("unresolved desired schema")
		}
		if _, ok := schemas[projection]; !ok {
			return zero, errors.New("unresolved projection schema")
		}
		seenKinds[name] = true
		kinds = append(kinds, KindPin{name, desired, projection})
	}
	h := sha256.Sum256(data)
	return Record{id: id, driver: driver, protocol: 1, executablePath: path, executableDigest: exhash, configurationDigest: cfg, issuer: issuer, subject: subject, schemas: schemas, kinds: kinds, digest: hex.EncodeToString(h[:]), metadata: metadata, policy: policy}, nil
}
func recordName(s string) bool {
	return recordKindRE.MatchString(s)
}
func closed(m map[string]any, keys ...string) bool {
	if len(m) != len(keys) {
		return false
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	return true
}

//go:build linux && amd64

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/appstoreplaceholder"
	"github.com/PHPCraftdream/ssjack/internal/driverframe"
	"github.com/PHPCraftdream/ssjack/internal/driverprotocol"
	"golang.org/x/sys/unix"
)

const maxState = 4096

type request struct {
	Protocol         int            `json:"protocol"`
	RequestID        string         `json:"request_id"`
	Action           string         `json:"action"`
	Target           string         `json:"target"`
	Kind             string         `json:"kind"`
	SchemaID         string         `json:"schema_id"`
	ResourceID       string         `json:"resource_id"`
	Desired          map[string]any `json:"desired"`
	ExpectedRevision *string        `json:"expected_revision"`
	PlanDigest       *string        `json:"plan_digest"`
	AllowedEffects   []any          `json:"allowed_effects"`
	DeadlineUnixMS   int64          `json:"deadline_unix_ms"`
	MaxResponseBytes int            `json:"max_response_bytes"`
	OperationID      *string        `json:"operation_id"`
}
type state struct {
	Enabled     bool   `json:"enabled"`
	Ref         string `json:"ref"`
	Revision    string `json:"revision"`
	OperationID string `json:"operation_id"`
	PlanDigest  string `json:"plan_digest"`
}

func main() {
	if len(os.Args) != 1 || !allowedEnvironment(os.Environ()) {
		return
	}
	payload, err := driverframe.Read(os.Stdin)
	if err != nil || driverframe.RequireEOF(os.Stdin) != nil {
		return
	}
	q, err := driverprotocol.ValidateStructuralRequest(payload)
	if err != nil {
		return
	}
	var r request
	if json.Unmarshal(payload, &r) != nil || r.Target != "target" || r.Kind != "cache" || r.SchemaID != "cache.desired" || r.ResourceID != "synthetic" || r.DeadlineUnixMS < time.Now().UnixMilli() {
		return
	}
	out := dispatch(r)
	if len(out) > r.MaxResponseBytes {
		return
	}
	if _, err = driverprotocol.ValidateStructuralResponse(q, out); err != nil {
		return
	}
	_ = writeReply(&r, out)
}
func dispatch(r request) []byte {
	switch r.Action {
	case "observe":
		d, e := openStateDir()
		if e != nil {
			return failure(r, "unknown", "OUTCOME_UNKNOWN")
		}
		defer unix.Close(d)
		s, e := readStateAt(d)
		if e != nil {
			return failure(r, "unknown", "OUTCOME_UNKNOWN")
		}
		return success(r, map[string]any{"state": "present", "revision": s.Revision, "projection": project(s)})
	case "apply":
		return apply(r)
	case "reconcile":
		return reconcile(r)
	default:
		return failure(r, "unsupported", "POLICY_DENIED")
	}
}
func apply(r request) []byte {
	if r.ExpectedRevision == nil || r.PlanDigest == nil || r.OperationID == nil || len(r.AllowedEffects) != 0 || !validDesired(r.Desired) || !digest(*r.PlanDigest) {
		return failure(r, "unsupported", "POLICY_DENIED")
	}
	d, e := openStateDir()
	if e != nil {
		return failure(r, "unknown", "OUTCOME_UNKNOWN")
	}
	defer unix.Close(d)
	lock, e := openRegular(d, ".lock", unix.O_RDWR)
	if e != nil {
		return failure(r, "unknown", "OUTCOME_UNKNOWN")
	}
	defer lock.Close()
	if !acquire(lock, r.DeadlineUnixMS) {
		return failure(r, "unknown", "OUTCOME_UNKNOWN")
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	s, e := readStateAt(d)
	if e != nil {
		return failure(r, "unknown", "OUTCOME_UNKNOWN")
	}
	if s.OperationID == *r.OperationID {
		if s.PlanDigest != *r.PlanDigest || s.Enabled != r.Desired["enabled"].(bool) || s.Ref != r.Desired["ref"].(string) {
			return failure(r, "unsupported", "POLICY_DENIED")
		}
		return success(r, map[string]any{"state": "present", "applied_revision": s.Revision, "verified": true, "projection": project(s)})
	}
	if s.Revision != *r.ExpectedRevision {
		return failure(r, "conflict", "PRECONDITION_FAILED")
	}
	if time.Now().UnixMilli() >= r.DeadlineUnixMS {
		return failure(r, "unknown", "OUTCOME_UNKNOWN")
	}
	s.Enabled = r.Desired["enabled"].(bool)
	s.Ref = r.Desired["ref"].(string)
	s.OperationID = *r.OperationID
	s.PlanDigest = *r.PlanDigest
	s.Revision = nextRevision(s.Revision)
	if s.Revision == "" || writeStateAt(d, s) != nil {
		return failure(r, "unknown", "OUTCOME_UNKNOWN")
	}
	return success(r, map[string]any{"state": "present", "applied_revision": s.Revision, "verified": true, "projection": project(s)})
}
func reconcile(r request) []byte {
	if r.OperationID == nil || r.PlanDigest == nil || !digest(*r.PlanDigest) {
		return failure(r, "unsupported", "POLICY_DENIED")
	}
	d, e := openStateDir()
	if e != nil {
		return failure(r, "unknown", "OUTCOME_UNKNOWN")
	}
	defer unix.Close(d)
	s, e := readStateAt(d)
	if e != nil || s.OperationID != *r.OperationID || s.PlanDigest != *r.PlanDigest {
		return failure(r, "unknown", "OUTCOME_UNKNOWN")
	}
	return success(r, map[string]any{"state": "present", "applied_revision": s.Revision, "delivered_revision": nil, "observed_revision": s.Revision, "adopted_revision": nil, "verified": true, "projection": project(s)})
}
func validDesired(v map[string]any) bool {
	if len(v) != 2 {
		return false
	}
	if _, ok := v["enabled"].(bool); !ok {
		return false
	}
	ref, ok := v["ref"].(string)
	if !ok || len(ref) > appstoreplaceholder.MaxInput {
		return false
	}
	r, e := appstoreplaceholder.Parse([]byte(ref))
	if e != nil {
		return false
	}
	b, e := appstoreplaceholder.Encode(r)
	return e == nil && bytes.Equal(b, []byte(ref))
}
func digest(v string) bool {
	b, e := hex.DecodeString(v)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == v
}
func project(s state) map[string]any { return map[string]any{"enabled": s.Enabled, "ref": s.Ref} }
func nextRevision(old string) string {
	if len(old) < 2 || old[0] != 'r' {
		return ""
	}
	n, e := strconv.ParseUint(old[1:], 10, 64)
	if e != nil || n == ^uint64(0) {
		return ""
	}
	return "r" + strconv.FormatUint(n+1, 10)
}
func allowedEnvironment(env []string) bool {
	seen := map[string]bool{}
	for _, entry := range env {
		k, v, ok := strings.Cut(entry, "=")
		if !ok || k != "LANG" && k != "LC_ALL" || v != "C" || seen[k] {
			return false
		}
		seen[k] = true
	}
	return len(seen) == 2
}
func success(r request, d any) []byte       { return envelope(r, "ok", nil, d) }
func failure(r request, o, c string) []byte { return envelope(r, o, c, nil) }
func envelope(r request, o string, c, d any) []byte {
	b, _ := json.Marshal(map[string]any{"protocol": 1, "request_id": r.RequestID, "outcome": o, "error_code": c, "data": d})
	return b
}

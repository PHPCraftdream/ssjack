//go:build linux && amd64

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
	"github.com/PHPCraftdream/ssjack/internal/declarativeauthority"
)

type labTargetState struct {
	Enabled     bool   `json:"enabled"`
	Ref         string `json:"ref"`
	Revision    string `json:"revision"`
	OperationID string `json:"operation_id"`
	PlanDigest  string `json:"plan_digest"`
}

func (l *deliveryLab) resetGenesis(path string) error {
	raw, e := canonicaljson.Canonicalize([]byte(`{"enabled":false,"ref":"","revision":"r0","operation_id":"","plan_digest":"0000000000000000000000000000000000000000000000000000000000000000"}`))
	if e != nil {
		return e
	}
	if e = os.WriteFile(path, raw, 0600); e != nil {
		return e
	}
	if e = os.Chown(path, labUID, labUID); e != nil {
		return e
	}
	if e = os.Chmod(path, 0600); e != nil {
		return e
	}
	got, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	if !bytes.Equal(got, raw) {
		return errors.New("genesis mismatch")
	}
	return nil
}
func (l *deliveryLab) verifyPositiveState(path string) error {
	raw, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	var s labTargetState
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&s) != nil || dec.Decode(new(any)) != io.EOF {
		return errors.New("state framing invalid")
	}
	canonical, e := canonicaljson.Canonicalize(raw)
	if e != nil || !bytes.Equal(raw, canonical) || !s.Enabled || s.Ref != l.ref || s.Revision == "" || s.Revision == "r0" || s.OperationID == "" || len(s.PlanDigest) != 64 {
		return errors.New("positive state invalid")
	}
	digest, e := hex.DecodeString(s.PlanDigest)
	if e != nil || hex.EncodeToString(digest) != s.PlanDigest || bytes.Equal(digest, make([]byte, 32)) {
		return errors.New("positive state digest invalid")
	}
	return nil
}
func statePath() string { return filepath.Join(declarativeauthority.StatePath, "state.json") }

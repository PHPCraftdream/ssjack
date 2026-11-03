package planbinding

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/canonicaljson"
)

func TestExplicitPlanWindowBoundaries(t *testing.T) {
	raw := encode(t, fixture(t))
	expected, err := Validate(raw)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(time.Minute)
	for _, tc := range []struct {
		name  string
		now   time.Time
		valid bool
	}{
		{"before-created", start.Add(-time.Nanosecond), false},
		{"at-created", start, true},
		{"inside", start.Add(30 * time.Second), true},
		{"before-expiry", end.Add(-time.Nanosecond), true},
		{"at-expiry", end, false},
		{"after-expiry", end.Add(time.Nanosecond), false},
		{"same-instant-other-zone", start.In(time.FixedZone("test-offset", 3600)), true},
		{"uninitialized-clock", time.Time{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			digest, err := ValidateAt(raw, tc.now)
			if tc.valid {
				if err != nil || digest != expected {
					t.Fatalf("valid observation: %v", err)
				}
			} else if !errors.Is(err, ErrInvalid) || digest != "" {
				t.Fatalf("invalid observation exposed digest: %v", err)
			}
		})
	}
}

func TestPlanWindowRejectsInvertedOrEqualTimestamps(t *testing.T) {
	for _, expiry := range []string{"2025-12-31T23:59:59.999Z", "2026-01-01T00:00:00.000Z"} {
		m := fixture(t)
		m["expires_at"] = expiry
		raw := encode(t, m)
		if _, err := Validate(raw); err != nil {
			t.Fatal("structural API behavior changed", err)
		}
		if digest, err := ValidateAt(raw, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)); !errors.Is(err, ErrInvalid) || digest != "" {
			t.Fatal("empty/reversed interval accepted")
		}
	}
}

func TestPlanWindowStillValidatesWholeBinding(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 30, 0, time.UTC)
	valid := encode(t, fixture(t))
	m := fixture(t)
	m["effect_digest"] = strings.Repeat("0", 64)
	for _, raw := range [][]byte{
		nil,
		[]byte(`{"created_at":"2026-01-01T00:00:00.000Z","expires_at":"2026-01-01T00:01:00.000Z"}`),
		append(append([]byte(nil), valid...), []byte(" {}")...),
		bytes.Replace(valid, []byte(`"protocol":1`), []byte(`"protocol":1,"protocol":1`), 1),
		bytes.Replace(valid, []byte(`"created_at":"2026-01-01T00:00:00.000Z"`), []byte(`"created_at":"2026-02-30T00:00:00.000Z"`), 1),
		encode(t, m),
		bytes.Repeat([]byte{' '}, canonicaljson.MaxInput+1),
	} {
		if digest, err := ValidateAt(raw, now); !errors.Is(err, ErrInvalid) || digest != "" {
			t.Fatalf("invalid whole binding accepted: %v", err)
		}
	}
	pretty := bytes.NewBuffer(nil)
	// Alternate whitespace must retain the same canonical plan identity.
	pretty.WriteString(" \n\t")
	pretty.Write(valid)
	pretty.WriteString("\n")
	before := append([]byte(nil), pretty.Bytes()...)
	expected, err := Validate(valid)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ValidateAt(pretty.Bytes(), now)
	if err != nil || got != expected || !bytes.Equal(before, pretty.Bytes()) {
		t.Fatal("identity/input changed", err)
	}
}

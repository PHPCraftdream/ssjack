package outputguard

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

func unionSnapshot(t *testing.T, values ...string) *Snapshot {
	t.Helper()
	patterns := make([][]byte, len(values))
	for i, value := range values {
		patterns[i] = []byte(value)
	}
	snapshot, err := New(patterns)
	if err != nil {
		t.Fatal("synthetic snapshot construction failed")
	}
	return snapshot
}

func unionRender(t *testing.T, snapshot *Snapshot, input string) string {
	t.Helper()
	var result bytes.Buffer
	writer, err := NewWriter(snapshot, &result)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []byte(input) {
		if _, err := writer.Write([]byte{value}); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return result.String()
}

func TestUnionRetainsOldAndNewLiteralsWithoutChangingCapturedSnapshots(t *testing.T) {
	old := unionSnapshot(t, "old", "prefix", "\x00\xff")
	current := unionSnapshot(t, "new", "prefix-longer", "suffix")
	combined, err := Union(old, current)
	if err != nil {
		t.Fatal(err)
	}
	input := "old|new|prefix-longer|prefix|suffix|\x00\xff"
	if unionRender(t, combined, input) != "[REDACTED]|[REDACTED]|[REDACTED]|[REDACTED]|[REDACTED]|[REDACTED]" {
		t.Fatal("union lost a literal, overlap or binary match")
	}
	if unionRender(t, old, "new|prefix-longer") != "new|[REDACTED]-longer" || unionRender(t, current, "old|prefix") != "old|prefix" {
		t.Fatal("union mutated a previously captured capability")
	}
	for range MaxPatterns + 1 {
		combined, err = Union(combined, current)
		if err != nil {
			t.Fatal("unchanged refresh exhausted historical bounds")
		}
	}
	if unionRender(t, combined, "old|new") != "[REDACTED]|[REDACTED]" {
		t.Fatal("refresh discarded historical coverage")
	}
}

func TestUnionRefusesInvalidCapabilitiesAndWholeBoundOverflow(t *testing.T) {
	empty := unionSnapshot(t)
	for _, invalid := range []*Snapshot{nil, {}} {
		if result, err := Union(empty, invalid); result != nil || !errors.Is(err, ErrGuard) {
			t.Fatal("union accepted an invalid capability")
		}
		if result, err := Union(invalid, empty); result != nil || !errors.Is(err, ErrGuard) {
			t.Fatal("union accepted an invalid historical capability")
		}
	}
	patterns := make([][]byte, MaxPatterns)
	for i := range patterns {
		patterns[i] = fmt.Appendf(nil, "synthetic-%04d", i)
	}
	full, err := New(patterns)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := Union(full, unionSnapshot(t, "extra")); result != nil || !errors.Is(err, ErrGuard) {
		t.Fatal("union truncated count overflow")
	}
	long := bytes.Repeat([]byte{'a'}, MaxPatternSize)
	a, err := New([][]byte{long})
	if err != nil {
		t.Fatal(err)
	}
	for i := range long {
		long[i] = 'b'
	}
	b, err := New([][]byte{long})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := Union(a, b); result != nil || !errors.Is(err, ErrGuard) {
		t.Fatal("union truncated trie-node overflow")
	}
	var halves [2]*Snapshot
	for half := range halves {
		values := make([][]byte, MaxPatterns/2)
		for i := range values {
			value := bytes.Repeat([]byte{'p'}, 1023)
			number := half*len(values) + i
			values[i] = append(value, byte(number>>8), byte(number))
		}
		halves[half], err = New(values)
		if err != nil {
			t.Fatal(err)
		}
	}
	if result, err := Union(halves[0], halves[1]); result != nil || err != ErrGuard {
		t.Fatal("union truncated total-byte overflow with shared trie prefixes")
	}
}

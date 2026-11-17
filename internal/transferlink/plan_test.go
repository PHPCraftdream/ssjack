package transferlink

import (
	"errors"
	"math"
	"reflect"
	"strconv"
	"testing"
)

func rs(pairs ...int64) []Range {
	out := make([]Range, 0, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, Range{Off: pairs[i], Len: pairs[i+1]})
	}
	return out
}

func TestNormalizeGapsCovered(t *testing.T) {
	tests := []struct {
		name        string
		size        int64
		ranges      []Range
		wantNorm    []Range
		wantGaps    []Range
		wantCovered int64
	}{
		{"empty set", 100, nil, nil, rs(0, 100), 0},
		{"full cover", 100, rs(0, 100), rs(0, 100), nil, 100},
		{"hole in the middle", 100, rs(0, 10, 20, 80), rs(0, 10, 20, 80), rs(10, 10), 90},
		{"leading gap", 100, rs(10, 90), rs(10, 90), rs(0, 10), 90},
		{"trailing gap", 100, rs(0, 90), rs(0, 90), rs(90, 10), 90},
		{"unsorted input", 100, rs(50, 10, 0, 10), rs(0, 10, 50, 10), rs(10, 40, 60, 40), 20},
		{"adjacent merge", 100, rs(0, 10, 10, 10), rs(0, 20), rs(20, 80), 20},
		{"adjacent unsorted merge", 100, rs(20, 10, 0, 10, 10, 10), rs(0, 30), rs(30, 70), 30},
		{"overlap merge", 100, rs(0, 30, 20, 30), rs(0, 50), rs(50, 50), 50},
		{"nested", 100, rs(0, 50, 10, 5), rs(0, 50), rs(50, 50), 50},
		{"nested unsorted", 100, rs(10, 5, 0, 50), rs(0, 50), rs(50, 50), 50},
		{"duplicate", 100, rs(5, 10, 5, 10), rs(5, 10), rs(0, 5, 15, 85), 10},
		{"different sizes tile", 100, rs(0, 1, 1, 9, 10, 40, 50, 50), rs(0, 100), nil, 100},
		{"chain of overlaps", 100, rs(0, 10, 5, 10, 12, 10), rs(0, 22), rs(22, 78), 22},
		{"size zero", 0, nil, nil, nil, 0},
		{"size one", 1, nil, nil, rs(0, 1), 0},
		{"huge size uncovered", math.MaxInt64, nil, nil, rs(0, math.MaxInt64), 0},
		{"huge size almost covered", math.MaxInt64, rs(0, math.MaxInt64-1), rs(0, math.MaxInt64-1), rs(math.MaxInt64-1, 1), math.MaxInt64 - 1},
		{"huge size full", math.MaxInt64, rs(0, math.MaxInt64), rs(0, math.MaxInt64), nil, math.MaxInt64},
		{"huge size tail range", math.MaxInt64, rs(math.MaxInt64-1, 1), rs(math.MaxInt64-1, 1), rs(0, math.MaxInt64-1), 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := append([]Range(nil), tc.ranges...)
			norm, err := Normalize(tc.size, tc.ranges)
			if err != nil {
				t.Fatalf("Normalize: %v", err)
			}
			if !reflect.DeepEqual(norm, tc.wantNorm) && !(len(norm) == 0 && len(tc.wantNorm) == 0) {
				t.Fatalf("Normalize = %v, want %v", norm, tc.wantNorm)
			}
			gaps, err := Gaps(tc.size, tc.ranges)
			if err != nil {
				t.Fatalf("Gaps: %v", err)
			}
			if !reflect.DeepEqual(gaps, tc.wantGaps) && !(len(gaps) == 0 && len(tc.wantGaps) == 0) {
				t.Fatalf("Gaps = %v, want %v", gaps, tc.wantGaps)
			}
			cov, err := Covered(tc.size, tc.ranges)
			if err != nil {
				t.Fatalf("Covered: %v", err)
			}
			if cov != tc.wantCovered {
				t.Fatalf("Covered = %d, want %d", cov, tc.wantCovered)
			}
			if !reflect.DeepEqual(in, tc.ranges) && !(len(in) == 0 && len(tc.ranges) == 0) {
				t.Fatalf("input modified: %v -> %v", in, tc.ranges)
			}
			// covered + gaps always add up to size
			var gapSum int64
			for _, g := range gaps {
				gapSum += g.Len
			}
			if cov+gapSum != tc.size {
				t.Fatalf("covered %d + gaps %d != size %d", cov, gapSum, tc.size)
			}
		})
	}
}

func TestMalformedRangesAreRejected(t *testing.T) {
	tests := []struct {
		name   string
		size   int64
		ranges []Range
	}{
		{"negative size", -1, nil},
		{"negative offset", 100, rs(-1, 10)},
		{"zero length", 100, rs(10, 0)},
		{"negative length", 100, rs(10, -5)},
		{"past the end", 100, rs(95, 10)},
		{"offset at size", 100, rs(100, 1)},
		{"offset beyond size", 100, rs(200, 1)},
		{"longer than size", 100, rs(0, 101)},
		{"any range in empty file", 0, rs(0, 1)},
		{"overflow offset plus length", math.MaxInt64, rs(math.MaxInt64, 1)},
		{"overflow wraparound", math.MaxInt64, rs(math.MaxInt64-1, math.MaxInt64)},
		{"max length at offset one", math.MaxInt64, rs(1, math.MaxInt64)},
		{"one bad range spoils the set", 100, rs(0, 10, 50, -1, 20, 10)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Normalize(tc.size, tc.ranges); !errors.Is(err, ErrBadRange) {
				t.Fatalf("Normalize err = %v", err)
			}
			if _, err := Gaps(tc.size, tc.ranges); !errors.Is(err, ErrBadRange) {
				t.Fatalf("Gaps err = %v", err)
			}
			if _, err := Covered(tc.size, tc.ranges); !errors.Is(err, ErrBadRange) {
				t.Fatalf("Covered err = %v", err)
			}
			if _, _, err := NextRange(tc.size, tc.ranges, MinChunk); !errors.Is(err, ErrBadRange) {
				t.Fatalf("NextRange err = %v", err)
			}
			if err := ValidateTiling(tc.size, tc.ranges); !errors.Is(err, ErrBadRange) {
				t.Fatalf("ValidateTiling err = %v", err)
			}
		})
	}
}

func TestNextRange(t *testing.T) {
	tests := []struct {
		name   string
		size   int64
		ranges []Range
		chunk  int64
		want   Range
		wantOK bool
	}{
		{"empty cut by chunk", 1000, nil, 100, Range{0, 100}, true},
		{"chunk larger than gap", 50, nil, 100, Range{0, 50}, true},
		{"chunk equals gap", 100, nil, 100, Range{0, 100}, true},
		{"zero chunk means whole gap", 1000, nil, 0, Range{0, 1000}, true},
		{"negative chunk means whole gap", 1000, nil, -1, Range{0, 1000}, true},
		{"first gap wins", 1000, rs(0, 100, 300, 100), 50, Range{100, 50}, true},
		{"first gap shorter than chunk", 1000, rs(0, 100, 150, 100), 500, Range{100, 50}, true},
		{"leading gap", 1000, rs(10, 990), 100, Range{0, 10}, true},
		{"resume after prefix", 1000, rs(0, 600), 300, Range{600, 300}, true},
		{"resume tail shorter than chunk", 1000, rs(0, 900), 300, Range{900, 100}, true},
		{"unsorted coverage", 1000, rs(500, 500, 0, 250), 1000, Range{250, 250}, true},
		{"overlapping coverage", 1000, rs(0, 600, 400, 300), 1000, Range{700, 300}, true},
		{"fully covered", 1000, rs(0, 1000), 100, Range{}, false},
		{"fully covered by pieces", 1000, rs(500, 500, 0, 500), 100, Range{}, false},
		{"empty file", 0, nil, 100, Range{}, false},
		{"huge size", math.MaxInt64, nil, MaxChunk, Range{0, MaxChunk}, true},
		{"huge size last byte", math.MaxInt64, rs(0, math.MaxInt64-1), MaxChunk, Range{math.MaxInt64 - 1, 1}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok, err := NextRange(tc.size, tc.ranges, tc.chunk)
			if err != nil {
				t.Fatal(err)
			}
			if ok != tc.wantOK || got != tc.want {
				t.Fatalf("NextRange = %v,%v want %v,%v", got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestNextRangeWalksToCompletion(t *testing.T) {
	const size = 1_000_003
	var covered []Range
	chunks := []int64{100_000, 7, 333_333, 1, 250_000}
	for i := 0; ; i++ {
		r, ok, err := NextRange(size, covered, chunks[i%len(chunks)])
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			break
		}
		if r.Len <= 0 || r.Len > chunks[i%len(chunks)] {
			t.Fatalf("bad piece %v", r)
		}
		covered = append(covered, r)
		if i > 1_000_000 {
			t.Fatal("does not terminate")
		}
	}
	if err := ValidateTiling(size, covered); err != nil {
		t.Fatalf("pieces do not tile: %v", err)
	}
}

func TestValidateTiling(t *testing.T) {
	tests := []struct {
		name  string
		size  int64
		parts []Range
		want  error
	}{
		{"exact", 100, rs(0, 40, 40, 60), nil},
		{"exact unsorted", 100, rs(40, 60, 0, 40), nil},
		{"single part", 100, rs(0, 100), nil},
		{"many parts", 10, rs(9, 1, 8, 1, 7, 1, 6, 1, 5, 1, 4, 1, 3, 1, 2, 1, 1, 1, 0, 1), nil},
		{"empty file no parts", 0, nil, nil},
		{"huge exact", math.MaxInt64, rs(0, 1<<62, 1<<62, math.MaxInt64-(1<<62)), nil},
		{"gap in the middle", 100, rs(0, 40, 50, 50), ErrGap},
		{"missing head", 100, rs(10, 90), ErrGap},
		{"missing tail", 100, rs(0, 90), ErrGap},
		{"no parts", 100, nil, ErrGap},
		{"one byte gap", 100, rs(0, 49, 50, 50), ErrGap},
		{"overlap by one", 100, rs(0, 51, 50, 50), ErrOverlap},
		{"duplicate part", 100, rs(0, 50, 0, 50, 50, 50), ErrOverlap},
		{"nested part", 100, rs(0, 100, 10, 10), ErrOverlap},
		{"same offset different length", 100, rs(0, 50, 0, 60, 60, 40), ErrOverlap},
		{"part beyond size", 100, rs(0, 50, 50, 51), ErrBadRange},
		{"zero length part", 100, rs(0, 100, 100, 0), ErrBadRange},
		{"negative offset part", 100, rs(-5, 105), ErrBadRange},
		{"part in empty file", 0, rs(0, 1), ErrBadRange},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := append([]Range(nil), tc.parts...)
			err := ValidateTiling(tc.size, tc.parts)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if !reflect.DeepEqual(in, tc.parts) && !(len(in) == 0 && len(tc.parts) == 0) {
				t.Fatalf("input modified")
			}
		})
	}
}

func TestPartNameRoundTrip(t *testing.T) {
	tests := []struct {
		r    Range
		want string
	}{
		{Range{0, 1}, "part-0-1"},
		{Range{0, 65536}, "part-0-65536"},
		{Range{10, 20}, "part-10-20"},
		{Range{1 << 40, MaxChunk}, "part-1099511627776-67108864"},
		{Range{0, math.MaxInt64}, "part-0-9223372036854775807"},
		{Range{math.MaxInt64 - 1, 1}, "part-9223372036854775806-1"},
	}
	for _, tc := range tests {
		name, err := PartName(tc.r)
		if err != nil {
			t.Fatalf("PartName(%v): %v", tc.r, err)
		}
		if name != tc.want {
			t.Fatalf("PartName(%v) = %q, want %q", tc.r, name, tc.want)
		}
		back, err := ParsePartName(name)
		if err != nil || back != tc.r {
			t.Fatalf("ParsePartName(%q) = %v, %v", name, back, err)
		}
	}
}

func TestPartNameRejectsBadRanges(t *testing.T) {
	for _, r := range []Range{
		{-1, 5}, {0, 0}, {5, 0}, {0, -1}, {math.MaxInt64, 1}, {1, math.MaxInt64}, {math.MaxInt64 - 1, 2},
	} {
		if name, err := PartName(r); !errors.Is(err, ErrBadRange) || name != "" {
			t.Fatalf("PartName(%v) = %q, %v", r, name, err)
		}
	}
}

func TestParsePartNameMalformed(t *testing.T) {
	bad := []string{
		"",
		"part",
		"part-",
		"part--",
		"part-1",
		"part-1-",
		"part--1",
		"part-1-2-3",
		"part-1--2",
		"part-01-2",
		"part-1-02",
		"part-00-1",
		"part-0-00",
		"part-+1-2",
		"part-1-+2",
		"part--1-2",
		"part-1--2",
		"part- 1-2",
		"part-1- 2",
		"part-1-2 ",
		" part-1-2",
		"part-1-2\n",
		"part-1-2\x00",
		"Part-1-2",
		"PART-1-2",
		"part_1_2",
		"part-1_2",
		"xpart-1-2",
		"part-1-2.tmp",
		"part-1-2-",
		"part-0x1-2",
		"part-1e3-2",
		"part-1.5-2",
		"part-a-2",
		"part-1-b",
		"part-1-0",
		"part-0-0",
		"part-9223372036854775808-1",
		"part-1-9223372036854775808",
		"part-9223372036854775807-1",
		"part-1-9223372036854775807",
		"part-99999999999999999999-1",
		"part-1-99999999999999999999",
		"part-١-2",
		"part-1-٢",
		"part-１-2",
		"../part-1-2",
		"part-1-2/x",
		"dir/part-1-2",
	}
	for _, name := range bad {
		if r, err := ParsePartName(name); !errors.Is(err, ErrBadPartName) {
			t.Errorf("ParsePartName(%q) = %v, %v; want ErrBadPartName", name, r, err)
		}
	}
}

func TestParsePartNameValid(t *testing.T) {
	good := map[string]Range{
		"part-0-1":                   {0, 1},
		"part-1-1":                   {1, 1},
		"part-10-20":                 {10, 20},
		"part-0-9223372036854775807": {0, math.MaxInt64},
		"part-9223372036854775806-1": {math.MaxInt64 - 1, 1},
	}
	for name, want := range good {
		got, err := ParsePartName(name)
		if err != nil || got != want {
			t.Errorf("ParsePartName(%q) = %v, %v; want %v", name, got, err, want)
		}
	}
}

func TestPartNameLongGarbageIsBounded(t *testing.T) {
	long := make([]byte, 10_000)
	for i := range long {
		long[i] = 'x'
	}
	_, err := ParsePartName(string(long))
	if !errors.Is(err, ErrBadPartName) {
		t.Fatalf("err = %v", err)
	}
	if len(err.Error()) > 200 {
		t.Fatalf("error echoes unbounded input (%d bytes)", len(err.Error()))
	}
}

func TestPartNameRoundTripGrid(t *testing.T) {
	vals := []int64{0, 1, 9, 10, 99, 100, 255, 256, 1 << 20, 1<<31 - 1, 1 << 31, 1<<62 - 1, math.MaxInt64 - 1}
	for _, off := range vals {
		for _, n := range vals {
			r := Range{Off: off, Len: n}
			name, err := PartName(r)
			valid := n > 0 && n <= math.MaxInt64-off
			if (err == nil) != valid {
				t.Fatalf("PartName(%v) err = %v, valid = %v", r, err, valid)
			}
			if !valid {
				continue
			}
			back, err := ParsePartName(name)
			if err != nil || back != r {
				t.Fatalf("round trip %v -> %q -> %v, %v", r, name, back, err)
			}
			if name != "part-"+strconv.FormatInt(off, 10)+"-"+strconv.FormatInt(n, 10) {
				t.Fatalf("non canonical name %q", name)
			}
		}
	}
}

// FuzzParsePartName runs its seeds in a normal test run; any accepted name
// must be the canonical rendering of a valid range.
func FuzzParsePartName(f *testing.F) {
	for _, s := range []string{"part-0-1", "part-10-20", "", "part-", "part-01-2", "part-1-2-3", "part-9223372036854775807-1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		r, err := ParsePartName(name)
		if err != nil {
			if !errors.Is(err, ErrBadPartName) {
				t.Fatalf("unexpected error class: %v", err)
			}
			return
		}
		if r.Off < 0 || r.Len <= 0 || r.Len > math.MaxInt64-r.Off {
			t.Fatalf("accepted invalid range %v from %q", r, name)
		}
		canon, err := PartName(r)
		if err != nil || canon != name {
			t.Fatalf("accepted non-canonical %q (canonical %q, %v)", name, canon, err)
		}
	})
}

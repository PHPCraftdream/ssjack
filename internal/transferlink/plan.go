package transferlink

import (
	"cmp"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
)

var (
	// ErrBadRange marks a malformed range: negative offset or size, zero or
	// negative length, or a range that does not lie inside [0, size).
	ErrBadRange = errors.New("transferlink: invalid range")
	// ErrOverlap marks overlapping parts in a tiling.
	ErrOverlap = errors.New("transferlink: overlapping parts")
	// ErrGap marks a gap (including a missing head or tail) in a tiling.
	ErrGap = errors.New("transferlink: gap between parts")
	// ErrBadPartName marks a part name that is not the canonical
	// part-<offset>-<len>.
	ErrBadPartName = errors.New("transferlink: invalid part name")
)

// Range is the half-open byte range [Off, Off+Len).
type Range struct {
	Off, Len int64
}

// End returns Off+Len. It is only meaningful for ranges that passed
// validation (no overflow).
func (r Range) End() int64 { return r.Off + r.Len }

func checkRange(size int64, r Range) error {
	if size < 0 {
		return fmt.Errorf("%w: negative size %d", ErrBadRange, size)
	}
	if r.Off < 0 || r.Len <= 0 {
		return fmt.Errorf("%w: off=%d len=%d", ErrBadRange, r.Off, r.Len)
	}
	// size-Off cannot overflow: 0 <= Off, size >= 0. An Off beyond size
	// makes it negative, so Len > size-Off rejects it as well.
	if r.Len > size-r.Off {
		return fmt.Errorf("%w: off=%d len=%d beyond size %d", ErrBadRange, r.Off, r.Len, size)
	}
	return nil
}

func sortedCopy(size int64, ranges []Range) ([]Range, error) {
	if size < 0 {
		return nil, fmt.Errorf("%w: negative size %d", ErrBadRange, size)
	}
	out := make([]Range, 0, len(ranges))
	for _, r := range ranges {
		if err := checkRange(size, r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b Range) int {
		if c := cmp.Compare(a.Off, b.Off); c != 0 {
			return c
		}
		return cmp.Compare(a.Len, b.Len)
	})
	return out, nil
}

// Normalize returns the union of ranges as sorted, disjoint, non-adjacent
// ranges inside [0, size). Overlapping, nested, duplicate and adjacent
// ranges are merged (a resumed transfer may find parts of different sizes
// from earlier chunk sizes). A malformed range (see ErrBadRange) rejects the
// whole set. The input is not modified.
func Normalize(size int64, ranges []Range) ([]Range, error) {
	sorted, err := sortedCopy(size, ranges)
	if err != nil {
		return nil, err
	}
	var out []Range
	for _, r := range sorted {
		if n := len(out); n > 0 && r.Off <= out[n-1].End() {
			if r.End() > out[n-1].End() {
				out[n-1].Len = r.End() - out[n-1].Off
			}
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

// Covered returns how many bytes of [0, size) the ranges cover (the union,
// so overlaps count once).
func Covered(size int64, ranges []Range) (int64, error) {
	norm, err := Normalize(size, ranges)
	if err != nil {
		return 0, err
	}
	var sum int64
	for _, r := range norm {
		sum += r.Len // the union never exceeds size
	}
	return sum, nil
}

// Gaps returns the uncovered ranges of [0, size) in ascending order.
func Gaps(size int64, ranges []Range) ([]Range, error) {
	norm, err := Normalize(size, ranges)
	if err != nil {
		return nil, err
	}
	var gaps []Range
	var cursor int64
	for _, r := range norm {
		if r.Off > cursor {
			gaps = append(gaps, Range{Off: cursor, Len: r.Off - cursor})
		}
		cursor = r.End()
	}
	if cursor < size {
		gaps = append(gaps, Range{Off: cursor, Len: size - cursor})
	}
	return gaps, nil
}

// NextRange returns the next range to transfer: the first uncovered gap cut
// to at most chunk bytes. chunk <= 0 means the whole gap (stream mode). ok is
// false when [0, size) is fully covered.
func NextRange(size int64, ranges []Range, chunk int64) (r Range, ok bool, err error) {
	gaps, err := Gaps(size, ranges)
	if err != nil {
		return Range{}, false, err
	}
	if len(gaps) == 0 {
		return Range{}, false, nil
	}
	r = gaps[0]
	if chunk > 0 && chunk < r.Len {
		r.Len = chunk
	}
	return r, true, nil
}

// ValidateTiling checks that parts tile [0, size) exactly, in any order: no
// gap (ErrGap), no overlap or duplicate (ErrOverlap) and no malformed or
// out-of-bounds part (ErrBadRange). It is the assembly-step check; unlike
// Normalize it never merges. size 0 needs no parts.
func ValidateTiling(size int64, parts []Range) error {
	sorted, err := sortedCopy(size, parts)
	if err != nil {
		return err
	}
	var cursor int64
	for _, r := range sorted {
		switch {
		case r.Off < cursor:
			return fmt.Errorf("%w: part at %d starts before %d", ErrOverlap, r.Off, cursor)
		case r.Off > cursor:
			return fmt.Errorf("%w: [%d,%d) is not covered", ErrGap, cursor, r.Off)
		}
		cursor = r.End()
	}
	if cursor < size {
		return fmt.Errorf("%w: [%d,%d) is not covered", ErrGap, cursor, size)
	}
	return nil
}

// Listed is one entry of a part directory whose name is a strict part name:
// the range the name denotes and the size the entry really has.
type Listed struct {
	Name  string
	Range Range
	Size  int64
}

// AcceptListed builds the coverage of a part directory of a file of fileSize
// bytes. Entries are ordered by offset and, at one offset, longer first; an
// entry whose size differs from its length, that overlaps an already accepted
// entry or that ends past fileSize is rejected. accepted is ascending by
// offset and pairwise disjoint; rejected holds the names of the rejected
// entries in that order. The remote listing parser (internal/transferremote)
// and the local listing of a chunked download both build their coverage with
// this function.
func AcceptListed(fileSize int64, entries []Listed) (accepted []Range, rejected []string) {
	if fileSize < 0 {
		fileSize = 0
	}
	sorted := append([]Listed(nil), entries...)
	slices.SortFunc(sorted, func(a, b Listed) int {
		if c := cmp.Compare(a.Range.Off, b.Range.Off); c != 0 {
			return c
		}
		return cmp.Compare(b.Range.Len, a.Range.Len)
	})
	var cursor int64
	for _, c := range sorted {
		if c.Size != c.Range.Len || c.Range.Off < cursor || c.Range.Len > fileSize-c.Range.Off || c.Range.Off > fileSize {
			rejected = append(rejected, c.Name)
			continue
		}
		accepted = append(accepted, c.Range)
		cursor = c.Range.End()
	}
	return accepted, rejected
}

const partPrefix = "part-"

// PartName formats the canonical name part-<offset>-<len> of a part. The
// range must have Off >= 0, Len > 0 and Off+Len without overflow.
func PartName(r Range) (string, error) {
	if r.Off < 0 || r.Len <= 0 || r.Len > math.MaxInt64-r.Off {
		return "", fmt.Errorf("%w: off=%d len=%d", ErrBadRange, r.Off, r.Len)
	}
	return partPrefix + strconv.FormatInt(r.Off, 10) + "-" + strconv.FormatInt(r.Len, 10), nil
}

// ParsePartName parses a name produced by PartName. Parsing is strict: the
// exact prefix "part-", two decimal fields separated by one "-", ASCII digits
// only, no sign, no leading zeros except the single digit "0", values that fit
// int64, Len > 0 and Off+Len without overflow. Anything else, including
// trailing garbage, is ErrBadPartName.
func ParsePartName(name string) (Range, error) {
	rest, ok := strings.CutPrefix(name, partPrefix)
	if !ok {
		return Range{}, badPartName(name)
	}
	offS, lenS, ok := strings.Cut(rest, "-")
	if !ok {
		return Range{}, badPartName(name)
	}
	off, ok := parseDecimal(offS)
	if !ok {
		return Range{}, badPartName(name)
	}
	n, ok := parseDecimal(lenS)
	if !ok || n == 0 || n > math.MaxInt64-off {
		return Range{}, badPartName(name)
	}
	return Range{Off: off, Len: n}, nil
}

func badPartName(name string) error {
	if len(name) > 64 {
		name = name[:64] + "..."
	}
	return fmt.Errorf("%w: %q", ErrBadPartName, name)
}

func parseDecimal(s string) (int64, bool) {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

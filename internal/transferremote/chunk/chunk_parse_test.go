package chunk

import (
	"fmt"
	"math"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlink"
	"github.com/PHPCraftdream/ssjack/internal/transferremote/core"
)

func TestParseCanonical(t *testing.T) {
	good := map[string]int64{"0": 0, "7": 7, "10": 10, "9223372036854775807": math.MaxInt64}
	for in, want := range good {
		if got, ok := parseCanonical(in); !ok || got != want {
			t.Errorf("parseCanonical(%q) = %d, %v; want %d, true", in, got, ok, want)
		}
	}
	bad := []string{
		"", "00", "01", "-1", "+1", " 1", "1 ", "1\n", "0x10", "1e3", "１２", "9223372036854775808",
		"99999999999999999999", "12345678901234567890", "1_0", "\x001",
	}
	for _, in := range bad {
		if got, ok := parseCanonical(in); ok {
			t.Errorf("parseCanonical(%q) = %d, true; want rejection", in, got)
		}
	}
}

func TestParseStageEnsure(t *testing.T) {
	for line, want := range map[string]StagingState{
		"SSJACK-STAGE created\n": StagingCreated, "SSJACK-STAGE reused\n": StagingReused, "SSJACK-STAGE foreign\n": StagingForeign,
	} {
		if got, err := parseStageEnsure([]byte(line)); err != nil || got != want {
			t.Errorf("parseStageEnsure(%q) = %v, %v; want %v", line, got, err, want)
		}
	}
	for _, line := range []string{
		"", "\n", "SSJACK-STAGE created", "SSJACK-STAGE created\n\n", "SSJACK-STAGE created\nSSJACK-STAGE reused\n",
		"SSJACK-STAGE other\n", "SSJACK-STAGE  created\n", "SSJACK-STAGE created \n", "ssjack-stage created\n", "created\n",
		"SSJACK-STAGE created\x00\n", "SSJACK-STAGE created\r\n",
	} {
		_, err := parseStageEnsure([]byte(line))
		expectClass(t, err, transfercore.ClassIntegrity)
	}
}

func TestParsePartResult(t *testing.T) {
	good := []struct {
		line   string
		length int64
		want   PartResult
	}{
		{"SSJACK-PART 100 stored\n", 100, PartResult{Count: 100, Stored: true}},
		{"SSJACK-PART 0 short\n", 100, PartResult{Count: 0}},
		{"SSJACK-PART 99 short\n", 100, PartResult{Count: 99}},
		{"SSJACK-PART 101 short\n", 100, PartResult{Count: 101}},
		{"SSJACK-PART 9223372036854775807 stored\n", math.MaxInt64, PartResult{Count: math.MaxInt64, Stored: true}},
	}
	for _, tc := range good {
		got, err := parsePartResult([]byte(tc.line), tc.length)
		if err != nil || got != tc.want {
			t.Errorf("parsePartResult(%q, %d) = %+v, %v; want %+v", tc.line, tc.length, got, err, tc.want)
		}
	}
	bad := []struct {
		line   string
		length int64
	}{
		{"SSJACK-PART 100 short\n", 100},  // short with the right count
		{"SSJACK-PART 99 stored\n", 100},  // stored with the wrong count
		{"SSJACK-PART 101 stored\n", 100}, // stored with an excess count
		{"SSJACK-PART 100 stored", 100},
		{"SSJACK-PART 100 stored\n\n", 100},
		{"SSJACK-PART 100\n", 100},
		{"SSJACK-PART  100 stored\n", 100},
		{"SSJACK-PART 100 stored extra\n", 100},
		{"SSJACK-PART 0100 stored\n", 100},
		{"SSJACK-PART -1 short\n", 100},
		{"SSJACK-PART 1e2 stored\n", 100},
		{"SSJACK-PART 99999999999999999999 short\n", 100},
		{"SSJACK-PART 100 STORED\n", 100},
		{"SSJACK-PART 100 stored\nSSJACK-PART 100 stored\n", 100},
		{"SSJACK-PART \x00 stored\n", 100},
		{"", 100},
		{"garbage\n", 100},
	}
	for _, tc := range bad {
		_, err := parsePartResult([]byte(tc.line), tc.length)
		expectClass(t, err, transfercore.ClassIntegrity)
	}
}

func TestMaxListedParts(t *testing.T) {
	if got := MaxListedParts(transfercore.DefaultLimits()); got != 8192+64 {
		t.Errorf("MaxListedParts(default) = %d, want 8256", got)
	}
	if got := MaxListedParts(transfercore.Limits{MaxBytes: 256<<10 + 1}); got != 2+64 {
		t.Errorf("MaxListedParts(256 KiB + 1) = %d, want 66", got)
	}
	if got := MaxListedParts(transfercore.Limits{MaxBytes: math.MaxInt64}); got != maxListedPartsCap+64 {
		t.Errorf("MaxListedParts(max) = %d, want %d", got, maxListedPartsCap+64)
	}
}

func listing(lines ...string) []byte {
	return []byte("SSJACK-LIST 1\n" + strings.Join(lines, "\n") + func() string {
		if len(lines) > 0 {
			return "\n"
		}
		return ""
	}())
}

func listingEnd(entries ...string) []byte {
	return append(listing(entries...), []byte(fmt.Sprintf("SSJACK-END %d\n", len(entries)))...)
}

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func TestParseStagingListingCoverage(t *testing.T) {
	data := listingEnd("100 part-0-100", "100 part-100-100", "50 part-0-50", "70 part-200-80", "300 part-900-300", "5 part-007-5", "9 part-9223372036854775807-1")
	got, err := parseStagingListing(data, 1000, 100)
	if err != nil {
		t.Fatal(err)
	}
	wantParts := []transferlink.Range{{Off: 0, Len: 100}, {Off: 100, Len: 100}}
	if !reflect.DeepEqual(got.Parts, wantParts) {
		t.Errorf("Parts = %v, want %v", got.Parts, wantParts)
	}
	wantRemove := sortedStrings([]string{"part-0-50", "part-200-80", "part-900-300", "part-007-5", "part-9223372036854775807-1"})
	if !reflect.DeepEqual(sortedStrings(got.Remove), wantRemove) || got.Overflow {
		t.Errorf("Remove = %v overflow=%v, want %v", sortedStrings(got.Remove), got.Overflow, wantRemove)
	}
}

func TestParseStagingListingOrderingRules(t *testing.T) {
	t.Run("longer first at one offset", func(t *testing.T) {
		got, err := parseStagingListing(listingEnd("50 part-0-50", "100 part-0-100", "30 part-0-30"), 1000, 10)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got.Parts, []transferlink.Range{{Off: 0, Len: 100}}) || len(got.Remove) != 2 {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("a wrong-size long entry does not shadow a good shorter one", func(t *testing.T) {
		got, err := parseStagingListing(listingEnd("99 part-0-100", "50 part-0-50"), 1000, 10)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got.Parts, []transferlink.Range{{Off: 0, Len: 50}}) || !reflect.DeepEqual(got.Remove, []string{"part-0-100"}) {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("adjacent parts are kept in offset order", func(t *testing.T) {
		got, err := parseStagingListing(listingEnd("10 part-20-10", "10 part-0-10", "10 part-10-10"), 30, 10)
		if err != nil {
			t.Fatal(err)
		}
		want := []transferlink.Range{{Off: 0, Len: 10}, {Off: 10, Len: 10}, {Off: 20, Len: 10}}
		if !reflect.DeepEqual(got.Parts, want) || len(got.Remove) != 0 {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("partial overlap removes the later part", func(t *testing.T) {
		got, err := parseStagingListing(listingEnd("100 part-0-100", "100 part-50-100"), 1000, 10)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got.Parts, []transferlink.Range{{Off: 0, Len: 100}}) || !reflect.DeepEqual(got.Remove, []string{"part-50-100"}) {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("part ending exactly at the file end is kept", func(t *testing.T) {
		got, err := parseStagingListing(listingEnd("10 part-90-10"), 100, 10)
		if err != nil || len(got.Parts) != 1 || len(got.Remove) != 0 {
			t.Fatalf("got %+v, %v", got, err)
		}
	})
	t.Run("empty listing", func(t *testing.T) {
		got, err := parseStagingListing(listingEnd(), 100, 10)
		if err != nil || len(got.Parts) != 0 || len(got.Remove) != 0 || got.Overflow {
			t.Fatalf("got %+v, %v", got, err)
		}
	})
	t.Run("zero-size file accepts nothing", func(t *testing.T) {
		got, err := parseStagingListing(listingEnd("1 part-0-1"), 0, 10)
		if err != nil || len(got.Parts) != 0 || !reflect.DeepEqual(got.Remove, []string{"part-0-1"}) {
			t.Fatalf("got %+v, %v", got, err)
		}
	})
	t.Run("negative file size accepts nothing", func(t *testing.T) {
		got, err := parseStagingListing(listingEnd("1 part-0-1"), -5, 10)
		if err != nil || len(got.Parts) != 0 {
			t.Fatalf("got %+v, %v", got, err)
		}
	})
}

func TestParseStagingListingOverflow(t *testing.T) {
	got, err := parseStagingListing([]byte("SSJACK-LIST 1\nSSJACK-OVERFLOW\n"), 100, 10)
	if err != nil || !got.Overflow || len(got.Parts) != 0 || len(got.Remove) != 0 {
		t.Fatalf("remote overflow = %+v, %v", got, err)
	}
	got, err = parseStagingListing([]byte("SSJACK-LIST 1\n1 part-0-1\n1 part-1-1\nSSJACK-OVERFLOW\n"), 100, 10)
	if err != nil || !got.Overflow || len(got.Parts) != 0 {
		t.Fatalf("remote overflow after entries = %+v, %v", got, err)
	}
	got, err = parseStagingListing(listingEnd("1 part-0-1", "1 part-1-1", "1 part-2-1"), 100, 2)
	if err != nil || !got.Overflow || len(got.Parts) != 0 || len(got.Remove) != 0 {
		t.Fatalf("more entries than the bound = %+v, %v", got, err)
	}
}

func TestParseStagingListingRejectsHostileOutput(t *testing.T) {
	long := "part-" + strings.Repeat("1", 46)
	cases := map[string]string{
		"empty":                   "",
		"only newline":            "\n",
		"no trailing newline":     "SSJACK-LIST 1\nSSJACK-END 0",
		"no header":               "SSJACK-END 0\n",
		"wrong header":            "SSJACK-LIST 2\nSSJACK-END 0\n",
		"header only":             "SSJACK-LIST 1\n",
		"no end":                  "SSJACK-LIST 1\n1 part-0-1\n",
		"end count too small":     "SSJACK-LIST 1\n1 part-0-1\nSSJACK-END 0\n",
		"end count too large":     "SSJACK-LIST 1\n1 part-0-1\nSSJACK-END 2\n",
		"end count padded":        "SSJACK-LIST 1\n1 part-0-1\nSSJACK-END 01\n",
		"end count negative":      "SSJACK-LIST 1\n1 part-0-1\nSSJACK-END -1\n",
		"end count huge":          "SSJACK-LIST 1\nSSJACK-END 99999999999999999999\n",
		"entry without space":     "SSJACK-LIST 1\npart-0-1\nSSJACK-END 1\n",
		"entry without size":      "SSJACK-LIST 1\n part-0-1\nSSJACK-END 1\n",
		"size with leading zero":  "SSJACK-LIST 1\n007 part-0-1\nSSJACK-END 1\n",
		"negative size":           "SSJACK-LIST 1\n-1 part-0-1\nSSJACK-END 1\n",
		"padded size":             "SSJACK-LIST 1\n 1 part-0-1\nSSJACK-END 1\n",
		"huge size":               "SSJACK-LIST 1\n99999999999999999999 part-0-1\nSSJACK-END 1\n",
		"hex size":                "SSJACK-LIST 1\n0x1 part-0-1\nSSJACK-END 1\n",
		"two spaces":              "SSJACK-LIST 1\n1  part-0-1\nSSJACK-END 1\n",
		"name not a part":         "SSJACK-LIST 1\n1 marker\nSSJACK-END 1\n",
		"name with dot":           "SSJACK-LIST 1\n1 part-0-1.tmp\nSSJACK-END 1\n",
		"name with slash":         "SSJACK-LIST 1\n1 part-0-1/../x\nSSJACK-END 1\n",
		"name with traversal":     "SSJACK-LIST 1\n1 ../part-0-1\nSSJACK-END 1\n",
		"name with space":         "SSJACK-LIST 1\n1 part-0-1 x\nSSJACK-END 1\n",
		"name with control":       "SSJACK-LIST 1\n1 part-0-1\x01\nSSJACK-END 1\n",
		"name with NUL":           "SSJACK-LIST 1\n1 part-0-1\x00\nSSJACK-END 1\n",
		"name with CR":            "SSJACK-LIST 1\n1 part-0-1\r\nSSJACK-END 1\n",
		"name with letters":       "SSJACK-LIST 1\n1 part-a-b\nSSJACK-END 1\n",
		"name with unicode digit": "SSJACK-LIST 1\n1 part-０-1\nSSJACK-END 1\n",
		"name empty rest":         "SSJACK-LIST 1\n1 part-\nSSJACK-END 1\n",
		"name too long":           "SSJACK-LIST 1\n1 " + long + "\nSSJACK-END 1\n",
		"blank line":              "SSJACK-LIST 1\n\nSSJACK-END 0\n",
		"duplicate end":           "SSJACK-LIST 1\nSSJACK-END 0\nSSJACK-END 0\n",
		"entry after end":         "SSJACK-LIST 1\nSSJACK-END 0\n1 part-0-1\n",
		"two headers":             "SSJACK-LIST 1\nSSJACK-LIST 1\nSSJACK-END 0\n",
		"CRLF":                    "SSJACK-LIST 1\r\nSSJACK-END 0\r\n",
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parseStagingListing([]byte(data), 1000, 100)
			expectClass(t, err, transfercore.ClassIntegrity)
		})
	}
	t.Run("duplicate names", func(t *testing.T) {
		_, err := parseStagingListing(listingEnd("1 part-0-1", "1 part-0-1"), 100, 10)
		expectClass(t, err, transfercore.ClassIntegrity)
	})
	t.Run("duplicate non-strict names", func(t *testing.T) {
		_, err := parseStagingListing(listingEnd("1 part-00-1", "2 part-00-1"), 100, 10)
		expectClass(t, err, transfercore.ClassIntegrity)
	})
}

func TestParseStagingListingHugeNumbersAreContained(t *testing.T) {
	got, err := parseStagingListing(listingEnd(
		"9223372036854775807 part-0-9223372036854775807",
		"9223372036854775807 part-9223372036854775807-9223372036854775807",
		"1 part-9223372036854775807-1",
	), 100, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Parts) != 0 || len(got.Remove) != 3 {
		t.Fatalf("got %+v, want everything removed", got)
	}
}

func TestParseGCResult(t *testing.T) {
	for line, want := range map[string]int{"SSJACK-GC 0\n": 0, "SSJACK-GC 16\n": 16, "SSJACK-GC 3\n": 3} {
		if got, err := parseGCResult([]byte(line)); err != nil || got != want {
			t.Errorf("parseGCResult(%q) = %d, %v; want %d", line, got, err, want)
		}
	}
	for _, line := range []string{
		"", "SSJACK-GC\n", "SSJACK-GC 17\n", "SSJACK-GC -1\n", "SSJACK-GC 03\n", "SSJACK-GC 3", "SSJACK-GC 3\n\n",
		"SSJACK-GC  3\n", "SSJACK-GC 3 4\n", "SSJACK-GC x\n", "SSJACK-GC 99999999999999999999\n", "SSJACK-GC 3\nSSJACK-GC 3\n",
	} {
		_, err := parseGCResult([]byte(line))
		expectClass(t, err, transfercore.ClassIntegrity)
	}
}

func TestParseDF(t *testing.T) {
	const gnuHeader = "Filesystem     1024-blocks     Used Available Capacity Mounted on\n"
	good := []struct {
		name string
		in   string
		want int64
	}{
		{"gnu", gnuHeader + "/dev/sda1           100000    40000     60000      41% /\n", 60000 * 1024},
		{"busybox header", "Filesystem           1024-blocks    Used Available Use% Mounted on\n/dev/root  100000 40000 60000 41% /\n", 60000 * 1024},
		{"macos", "Filesystem   1024-blocks      Used Available Capacity  Mounted on\n/dev/disk3s5   488245288 300000000 150000000    67%    /System/Volumes/Data\n", 150000000 * 1024},
		{"no trailing newline", gnuHeader + "tmpfs 10 5 5 50% /run", 5 * 1024},
		{"mount point with spaces", gnuHeader + "/dev/disk2 100 50 50 50% /Volumes/My Disk\n", 50 * 1024},
		{"filesystem with a space", gnuHeader + "map auto_home 0 0 0 100% /System/Volumes/Data/home\n", 0},
		{"dash capacity", gnuHeader + "none 0 0 0 - /mnt\n", 0},
		{"zero available", gnuHeader + "/dev/x 100 100 0 100% /\n", 0},
		{"overflow clamps", gnuHeader + "/dev/x 9223372036854775807 0 9223372036854775807 0% /\n", math.MaxInt64},
	}
	for _, tc := range good {
		got, ok := parseDF([]byte(tc.in))
		if !ok || got != tc.want {
			t.Errorf("%s: parseDF = %d, %v; want %d, true", tc.name, got, ok, tc.want)
		}
	}
	bad := map[string]string{
		"empty":             "",
		"header only":       gnuHeader,
		"data only":         "/dev/sda1 100000 40000 60000 41% /\n",
		"wrong header":      "Device 1024-blocks Used Available Capacity Mounted on\n/dev/x 1 1 1 1% /\n",
		"three lines":       gnuHeader + "/dev/a 1 1 1 1% /\n/dev/b 1 1 1 1% /b\n",
		"wrapped name":      gnuHeader + "/dev/mapper/very-long-name\n 1 1 1 1% /\n",
		"no capacity":       gnuHeader + "/dev/x 100 50 50 /\n",
		"letters":           gnuHeader + "/dev/x 100 50 abc 50% /\n",
		"negative":          gnuHeader + "/dev/x 100 50 -5 50% /\n",
		"huge number":       gnuHeader + "/dev/x 1 1 99999999999999999999 0% /\n",
		"no mount":          gnuHeader + "/dev/x 100 50 50 50%\n",
		"error text":        "df: /nonexistent: No such file or directory\n",
		"control character": gnuHeader + "/dev/x 100 50 5\x000 50% /\n",
	}
	for name, in := range bad {
		if got, ok := parseDF([]byte(in)); ok {
			t.Errorf("%s: parseDF accepted %q as %d", name, in, got)
		}
	}
}

func TestParseSourceStat(t *testing.T) {
	got, err := parseSourceStat([]byte("1234 1700000000\n"))
	if err != nil || got != (SourceStat{Size: 1234, MTime: 1700000000}) {
		t.Fatalf("got %+v, %v", got, err)
	}
	if got, err := parseSourceStat([]byte("0 0\n")); err != nil || got != (SourceStat{}) {
		t.Fatalf("zero stat = %+v, %v", got, err)
	}
	for _, in := range []string{
		"", "\n", "1234 1700000000", "1234 1700000000\n\n", "1234\n", "1234  1700000000\n", "1234 1700000000 5\n", " 1234 1700000000\n",
		"-1 5\n", "5 -1\n", "01 5\n", "5 01\n", "5 1700000000.123\n", "5 1.7e9\n", "x y\n", "5 9223372036854775808\n",
		"99999999999999999999 5\n", "5\t6\n", "5 6\r\n", "1 2\n3 4\n", "stat: cannot stat\n",
	} {
		_, err := parseSourceStat([]byte(in))
		expectClass(t, err, transfercore.ClassIntegrity)
	}
}

func TestStagingKey(t *testing.T) {
	key := StagingKey("target", "/srv/a b", "root/rel", "1024", "1700000000000000000")
	if !validStageKey(key) {
		t.Fatalf("StagingKey = %q is not 32 lowercase hex", key)
	}
	if key != StagingKey("target", "/srv/a b", "root/rel", "1024", "1700000000000000000") {
		t.Error("StagingKey is not deterministic")
	}
	if StagingKey("ab", "c") == StagingKey("a", "bc") || StagingKey("abc") == StagingKey("abc", "") || StagingKey("", "abc") == StagingKey("abc", "") {
		t.Error("StagingKey fields are not unambiguously separated")
	}
	if StagingKey("a", "b") == StagingKey("b", "a") {
		t.Error("StagingKey ignores field order")
	}
	for _, bad := range []string{"", strings.Repeat("a", 31), strings.Repeat("a", 33), strings.Repeat("A", 32), strings.Repeat("g", 32), strings.Repeat("a", 31) + "/", strings.Repeat("a", 31) + "\n"} {
		if validStageKey(bad) {
			t.Errorf("validStageKey(%q) accepted", bad)
		}
	}
	if name := chunkStageName(key); core.ValidStagingName(name) || len(name) != len(core.StagingPrefix)+32 {
		t.Errorf("chunk staging name %q collides with the one-shot staging pattern", name)
	}
}

func TestSafePartNameMatchesRemoteShape(t *testing.T) {
	for _, ok := range []string{"part-0-1", "part-007-5", "part-1-2-3", "part-1", "part--", "part-" + strings.Repeat("1", 45)} {
		if !safePartName(ok) {
			t.Errorf("safePartName(%q) = false", ok)
		}
	}
	for _, bad := range []string{"", "part-", "part", "part-a", "part-1.tmp", "part-1/2", "xpart-1", " part-1", "part-1\n", "part-" + strings.Repeat("1", 46)} {
		if safePartName(bad) {
			t.Errorf("safePartName(%q) = true", bad)
		}
	}
}

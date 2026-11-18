package chunk

import (
	"context"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlink"
	"github.com/PHPCraftdream/ssjack/internal/transferremote/core"
)

func TestParseStagingListingReportsStaleAssembledFiles(t *testing.T) {
	got, err := parseStagingListing([]byte("SSJACK-LIST 1\nSSJACK-STALE 3\n100 part-0-100\n5 part-9-9\nSSJACK-END 2\n"), 1000, 10)
	if err != nil {
		t.Fatal(err)
	}
	if got.StaleAssembled != 3 {
		t.Errorf("StaleAssembled = %d, want 3", got.StaleAssembled)
	}
	if !reflect.DeepEqual(got.Parts, []transferlink.Range{{Off: 0, Len: 100}}) || !reflect.DeepEqual(got.Remove, []string{"part-9-9"}) {
		t.Errorf("the stale line disturbed the coverage: %+v", got)
	}

	zero, err := parseStagingListing([]byte("SSJACK-LIST 1\nSSJACK-STALE 0\nSSJACK-END 0\n"), 1000, 10)
	if err != nil || zero.StaleAssembled != 0 || len(zero.Parts) != 0 {
		t.Errorf("empty listing with a zero stale count = %+v, %v", zero, err)
	}

	// The line is optional: output without it means nothing was reported.
	old, err := parseStagingListing(listingEnd("100 part-0-100"), 1000, 10)
	if err != nil || old.StaleAssembled != 0 || len(old.Parts) != 1 {
		t.Errorf("listing without the stale line = %+v, %v", old, err)
	}

	// An overflowing listing still reports what it removed.
	over, err := parseStagingListing([]byte("SSJACK-LIST 1\nSSJACK-STALE 1\n1 part-0-1\nSSJACK-OVERFLOW\n"), 100, 10)
	if err != nil || !over.Overflow || over.StaleAssembled != 1 || len(over.Parts) != 0 {
		t.Errorf("remote overflow with a stale line = %+v, %v", over, err)
	}
	bound, err := parseStagingListing([]byte("SSJACK-LIST 1\nSSJACK-STALE 2\n1 part-0-1\n1 part-1-1\n1 part-2-1\nSSJACK-END 3\n"), 100, 2)
	if err != nil || !bound.Overflow || bound.StaleAssembled != 2 {
		t.Errorf("entry bound with a stale line = %+v, %v", bound, err)
	}
}

func TestParseStagingListingRejectsHostileStaleLines(t *testing.T) {
	cases := map[string]string{
		"padded count":          "SSJACK-LIST 1\nSSJACK-STALE 01\nSSJACK-END 0\n",
		"negative count":        "SSJACK-LIST 1\nSSJACK-STALE -1\nSSJACK-END 0\n",
		"signed count":          "SSJACK-LIST 1\nSSJACK-STALE +1\nSSJACK-END 0\n",
		"hex count":             "SSJACK-LIST 1\nSSJACK-STALE 0x1\nSSJACK-END 0\n",
		"empty count":           "SSJACK-LIST 1\nSSJACK-STALE \nSSJACK-END 0\n",
		"text count":            "SSJACK-LIST 1\nSSJACK-STALE many\nSSJACK-END 0\n",
		"huge count":            "SSJACK-LIST 1\nSSJACK-STALE 99999999999999999999\nSSJACK-END 0\n",
		"count above the bound": "SSJACK-LIST 1\nSSJACK-STALE 1048577\nSSJACK-END 0\n",
		"trailing space":        "SSJACK-LIST 1\nSSJACK-STALE 1 \nSSJACK-END 0\n",
		"extra field":           "SSJACK-LIST 1\nSSJACK-STALE 1 2\nSSJACK-END 0\n",
		"duplicate line":        "SSJACK-LIST 1\nSSJACK-STALE 1\nSSJACK-STALE 1\nSSJACK-END 0\n",
		"after an entry":        "SSJACK-LIST 1\n1 part-0-1\nSSJACK-STALE 1\nSSJACK-END 1\n",
		"counted as an entry":   "SSJACK-LIST 1\nSSJACK-STALE 1\nSSJACK-END 1\n",
		"no end":                "SSJACK-LIST 1\nSSJACK-STALE 1\n",
		"lowercase tag":         "SSJACK-LIST 1\nssjack-stale 1\nSSJACK-END 0\n",
		"no separator":          "SSJACK-LIST 1\nSSJACK-STALE1\nSSJACK-END 0\n",
	}
	for name, out := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parseStagingListing([]byte(out), 1000, 10)
			expectClass(t, err, transfercore.ClassIntegrity)
		})
	}
}

func TestListScriptRemovesLeftoverAssembledFilesBeforeListing(t *testing.T) {
	// The glob is exactly the 16 hex digits of an assembly's random suffix, so
	// only names this layer creates match.
	glob := regexp.MustCompile(`for f in "\$stage"/assembled\.\?{16}\.tmp; do`)
	if !glob.MatchString(listBody) || strings.Contains(listBody, "assembled."+strings.Repeat("?", 17)) {
		t.Errorf("list body does not remove assembled.<16 digits>.tmp:\n%s", listBody)
	}
	suffix, err := core.NewRandomSuffix()
	if err != nil || len(suffix) != 16 {
		t.Fatalf("random suffix %q (%v) does not have the 16 digits the glob expects", suffix, err)
	}
	assembled := regexp.MustCompile(`asm="\$stage/assembled\.\$rnd\.tmp"`)
	if !assembled.MatchString(assembleBody) {
		t.Error("assembly no longer names its file assembled.$rnd.tmp")
	}
	// Removal, then the header and the count, then the entries.
	order := []string{
		`rm -f "$f" 2>/dev/null; then`,
		`printf 'SSJACK-LIST 1\n'`,
		`printf 'SSJACK-STALE %s\n' "$stale"`,
		`for f in "$stage"/part-*; do`,
		`printf 'SSJACK-END %s\n' "$listed"`,
	}
	pos := 0
	for _, want := range order {
		i := strings.Index(listBody[pos:], want)
		if i < 0 {
			t.Fatalf("list body lacks %q after offset %d:\n%s", want, pos, listBody)
		}
		pos += i + len(want)
	}
	// Only regular leftovers are removed, never anything outside the staging
	// directory, and no unquoted expansion reaches rm.
	for _, line := range strings.Split(listBody, "\n") {
		if strings.Contains(line, "rm ") && !strings.Contains(line, `"$f"`) {
			t.Errorf("an rm in the list body does not name the quoted loop variable: %q", line)
		}
	}
}

func TestListStagingReportsTheRemovedLeftovers(t *testing.T) {
	f := replyWith(0, "SSJACK-LIST 1\nSSJACK-STALE 2\n100 part-0-100\nSSJACK-END 1\n")
	listing, err := chunkRunner(f, gnuChunkCaps).ListStaging(context.Background(), "/srv/data", chunkTestKey, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if listing.StaleAssembled != 2 || len(listing.Parts) != 1 {
		t.Errorf("listing = %+v", listing)
	}
	if command := f.Recorded()[0]; !strings.HasSuffix(command, stageFuncs+stageHeader+listBody) {
		t.Errorf("command is not the fixed list template:\n%s", command)
	}
	// A hostile count is an error, not a silently accepted value.
	bad := replyWith(0, "SSJACK-LIST 1\nSSJACK-STALE x\nSSJACK-END 0\n")
	_, err = chunkRunner(bad, gnuChunkCaps).ListStaging(context.Background(), "/srv/data", chunkTestKey, 1000)
	expectClass(t, err, transfercore.ClassIntegrity)
}

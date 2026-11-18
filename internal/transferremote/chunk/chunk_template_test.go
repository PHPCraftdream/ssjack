package chunk

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferlink"
	"github.com/PHPCraftdream/ssjack/internal/transferremote/core"
	"github.com/PHPCraftdream/ssjack/internal/transferremote/probe"
)

const (
	hostileChunkParent = "/srv/it's a dir/ü ñ"
	chunkTestKey       = "0123456789abcdef0123456789abcdef"
)

var (
	gnuChunkCaps = core.Caps{
		Hash: core.HashSha256sum, MvT: true, TarGNU: true, WcNames: true,
		Chunk: core.ChunkCaps{Own: true, Read: core.ReadDD, Mtime: core.MtimeGNU, DF: true},
	}
	rndPattern = regexp.MustCompile(`\nrnd='([0-9a-f]{16})'\n`)
)

// chunkRunner builds a remoteRunner with fixed probed capabilities.
func chunkRunner(f *fakeRunner, caps core.Caps) *remoteRunner {
	r := newRemote(f.Run, "t", sampleLimits())
	r.SetCaps(caps)
	return r
}

// replyWith answers every command with the exit code and stdout text, after
// draining stdin.
func replyWith(code int, out string) *fakeRunner {
	return &fakeRunner{Respond: func(_ string, stdin io.Reader, stdout, _ io.Writer) (int, error) {
		if stdin != nil {
			_, _ = io.Copy(io.Discard, stdin)
		}
		_, _ = io.WriteString(stdout, out)
		return code, nil
	}}
}

func TestChunkProbeSection(t *testing.T) {
	probe := fmt.Sprintf(probe.ProbeTemplate, core.ShellQuote("/.ssjack-probe-0123456789abcdef"))
	if strings.Contains(probe, "%!") || strings.Contains(probe, "%(") {
		t.Fatalf("probe template has a formatting error:\n%s", probe)
	}
	for _, want := range []string{
		"chunk_caps() {",
		"\tset +e\n",
		`[ -O "$d" ] && [ ! -O "$d/absent-owner-probe" ]`,
		`find "$d" -prune -type d -perm 0700 -print`,
		`dd if="$d/rd" bs=4 skip=1 count=1`,
		`dd if="$d/rd" bs=4 skip=2 count=1`,
		`tail -c +4 "$d/rd"`,
		`tail -c +9 "$d/rd"`,
		`head -c 3`,
		`stat -c '%s %Y' "$d/rd"`,
		`stat -f '%z %m' "$d/rd"`,
		`df -P -k "$d"`,
		`*%|-) cdf=yes ;;`,
		`printf 'SSJACK-CHUNK %s %s %s %s\n' "$cown" "$crd" "$cmt" "$cdf"`,
		`chunk_line=$(chunk_caps 2>/dev/null) || chunk_line=`,
		`chunk_line='SSJACK-CHUNK no none none no'`,
		`printf 'SSJACK-CAPS %s %s gnu %s\n' "$hash" "$rename" "$wc"`,
		`printf '%s\n' "$chunk_line"`,
	} {
		if !strings.Contains(probe, want) {
			t.Errorf("probe lacks %q", want)
		}
	}
	// The chunk checks run before the scratch directory is removed, and the
	// caps line precedes the chunk line.
	order := []string{"chunk_caps() {", `rm -rf "$d" || exit 20`, "trap - 0\nprintf 'SSJACK-CAPS", `printf '%s\n' "$chunk_line"`}
	last := -1
	for _, marker := range order {
		i := strings.LastIndex(probe, marker)
		if i <= last {
			t.Fatalf("probe order wrong at %q (index %d, previous %d)", marker, i, last)
		}
		last = i
	}
	if strings.Count(probe, "SSJACK-CAPS") != 1 {
		t.Errorf("SSJACK-CAPS must appear exactly once, got %d", strings.Count(probe, "SSJACK-CAPS"))
	}
}

func TestProbeStoresChunkCaps(t *testing.T) {
	cases := []struct {
		name   string
		report string
		want   core.ChunkCaps
	}{
		{"old probe output", "SSJACK-CAPS sha256sum t gnu names\n", core.ChunkCaps{Read: core.ReadNone, Mtime: core.MtimeNone}},
		{"all available", "SSJACK-CAPS sha256sum t gnu names\nSSJACK-CHUNK yes dd c yes\n", core.ChunkCaps{Own: true, Read: core.ReadDD, Mtime: core.MtimeGNU, DF: true}},
		{"bsd", "SSJACK-CAPS shasum p gnu stdin\nSSJACK-CHUNK yes dd f yes\n", core.ChunkCaps{Own: true, Read: core.ReadDD, Mtime: core.MtimeBSD, DF: true}},
		{"nothing available", "SSJACK-CAPS sha256sum t gnu names\nSSJACK-CHUNK no none none no\n", core.ChunkCaps{Read: core.ReadNone, Mtime: core.MtimeNone}},
		{"garbled chunk line", "SSJACK-CAPS sha256sum t gnu names\nSSJACK-CHUNK ???\n", core.ChunkCaps{Read: core.ReadNone, Mtime: core.MtimeNone}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeRunner{Respond: func(command string, _ io.Reader, stdout, _ io.Writer) (int, error) {
				if strings.Contains(command, "SSJACK-CAPS") {
					_, _ = io.WriteString(stdout, tc.report)
				}
				return 0, nil
			}}
			r := newRemote(f.Run, "t", sampleLimits())
			if err := r.Probe(context.Background()); err != nil {
				t.Fatalf("Probe: %v", err)
			}
			if got := r.ChunkCaps(); got != tc.want {
				t.Fatalf("core.ChunkCaps = %+v, want %+v", got, tc.want)
			}
		})
	}
	t.Run("rejected trailer keeps previous caps unset", func(t *testing.T) {
		f := &fakeRunner{Respond: func(command string, _ io.Reader, stdout, _ io.Writer) (int, error) {
			_, _ = io.WriteString(stdout, "SSJACK-CAPS sha256sum t gnu names\nextra\n")
			return 0, nil
		}}
		err := newRemote(f.Run, "t", sampleLimits()).Probe(context.Background())
		expectClass(t, err, transfercore.ClassUnsupportedRemote)
		expectCode(t, err, 20)
	})
	t.Run("default before probe is GNU compatible", func(t *testing.T) {
		got := newRemote((&fakeRunner{}).Run, "t", sampleLimits()).ChunkCaps()
		if got != (core.ChunkCaps{Own: true, Read: core.ReadDD, Mtime: core.MtimeGNU, DF: true}) {
			t.Fatalf("default caps = %+v", got)
		}
	})
}

func TestChunkScriptsArePOSIXOnly(t *testing.T) {
	scripts := map[string]string{
		"funcs": stageFuncs, "header": stageHeader, "ensure": stageEnsureBody, "upload": partUploadBody, "list": listBody,
		"remove-entries": removeEntriesBody, "assemble": assembleBody + assembleExecSuffix + assembleCheckBody + assembleDoneBody,
		"remove": removeStagingBody, "gc": gcBody, "disk": diskBody, "stat": statSourceBody, "read": readRangeBody,
		"probe": probe.ProbeChunkSection,
	}
	forbidden := []string{
		"[[", "]]", "local ", "<<<", "$'", "${!", "&>", "function ", "mktemp", "realpath", "readlink", "xargs", "sed ", "awk ",
		"-print0", "-maxdepth", "-delete", "-quit", "-regex", "-printf", "date -d", "id -u", "stat --", "--no-", "set -o", "pipefail",
		"seq ", "test -", "`", "mapfile", "readarray", "declare ", "shopt", "\r",
	}
	for name, script := range scripts {
		for _, bad := range forbidden {
			if strings.Contains(script, bad) {
				t.Errorf("%s script contains non-portable construct %q", name, bad)
			}
		}
	}
	if !strings.Contains(stageFuncs, `-mmin +1440`) || !strings.Contains(stageFuncs, `-mtime +1`) || strings.Contains(stageFuncs, `-mtime +0`) {
		t.Error("stage_idle must try -mmin +1440 then -mtime +1 and never -mtime +0 (BSD find rounds ages up)")
	}
	// Only the part upload carries the publication primitive.
	for name, script := range scripts {
		if name != "upload" && strings.Contains(script, "mv -T") {
			t.Errorf("%s script names mv -T", name)
		}
	}
}

func TestChunkScriptVerdictsMatchParsers(t *testing.T) {
	for _, line := range []string{
		"printf 'SSJACK-STAGE created\\n'", "printf 'SSJACK-STAGE reused\\n'", "printf 'SSJACK-STAGE foreign\\n'",
	} {
		if !strings.Contains(stageEnsureBody, line) {
			t.Errorf("ensure body lacks %q", line)
		}
	}
	for _, line := range []string{"printf 'SSJACK-PART %s short\\n' \"$wc_n\"", "printf 'SSJACK-PART %s stored\\n' \"$wc_n\""} {
		if !strings.Contains(partUploadBody, line) {
			t.Errorf("upload body lacks %q", line)
		}
	}
	for _, line := range []string{"printf 'SSJACK-LIST 1\\n'", "printf 'SSJACK-OVERFLOW\\n'", "printf '%s %s\\n' \"$wc_n\" \"$base\"", "printf 'SSJACK-END %s\\n' \"$listed\""} {
		if !strings.Contains(listBody, line) {
			t.Errorf("list body lacks %q", line)
		}
	}
	if !strings.Contains(gcBody, "printf 'SSJACK-GC %s\\n' \"$removed\"") {
		t.Error("gc body lacks its verdict line")
	}
	if !strings.Contains(gcBody, `????????????????????????????????; do`) || strings.Contains(gcBody, `?????????????????????????????????`) {
		t.Error("gc glob must be exactly 32 question marks")
	}
	if got := strings.Count(stageMagic, " "); got != 2 || !strings.HasPrefix(stageHeader[strings.Index(stageHeader, "magic="):], `magic="SSJACK-STAGING 1 $key"`) {
		t.Errorf("stage magic %q does not match the header", stageMagic)
	}
}

// chunkOps lists every staging operation with a valid argument set, so the
// refusal tests below cover all of them.
func chunkOps() map[string]func(r *remoteRunner, parent, key string) error {
	ctx := context.Background()
	return map[string]func(r *remoteRunner, parent, key string) error{
		"ensure": func(r *remoteRunner, parent, key string) error {
			_, err := r.EnsureStaging(ctx, parent, key)
			return err
		},
		"upload": func(r *remoteRunner, parent, key string) error {
			_, err := r.UploadPart(ctx, parent, key, transferlink.Range{Off: 0, Len: 3}, strings.NewReader("abc"))
			return err
		},
		"list": func(r *remoteRunner, parent, key string) error {
			_, err := r.ListStaging(ctx, parent, key, 100)
			return err
		},
		"remove-entries": func(r *remoteRunner, parent, key string) error {
			return r.RemoveStagingEntries(ctx, parent, key, []string{"part-0-3"})
		},
		"assemble": func(r *remoteRunner, parent, key string) error {
			_, err := r.AssembleStaging(ctx, parent, key, []transferlink.Range{{Off: 0, Len: 3}}, 3, false)
			return err
		},
		"remove": func(r *remoteRunner, parent, key string) error { return r.RemoveChunkStaging(ctx, parent, key) },
	}
}

func TestChunkOperationsRefuseBadArgumentsWithoutRunning(t *testing.T) {
	bad := []struct {
		name        string
		parent, key string
	}{
		{"relative parent", "srv/data", chunkTestKey},
		{"root parent", "/", chunkTestKey},
		{"newline in parent", "/srv/a\nb", chunkTestKey},
		{"tab in parent", "/srv/a\tb", chunkTestKey},
		{"backslash in parent", "/srv/a\\b", chunkTestKey},
		{"dot-dot in parent", "/srv/../etc", chunkTestKey},
		{"empty key", "/srv/data", ""},
		{"short key", "/srv/data", chunkTestKey[:31]},
		{"long key", "/srv/data", chunkTestKey + "0"},
		{"uppercase key", "/srv/data", strings.ToUpper(chunkTestKey)},
		{"non-hex key", "/srv/data", strings.Repeat("g", 32)},
		{"path-like key", "/srv/data", "../../../../../../../../../../"},
		{"quote in key", "/srv/data", strings.Repeat("a", 31) + "'"},
	}
	for opName, op := range chunkOps() {
		for _, tc := range bad {
			t.Run(opName+"/"+tc.name, func(t *testing.T) {
				f := &fakeRunner{}
				err := op(chunkRunner(f, gnuChunkCaps), tc.parent, tc.key)
				expectClass(t, err, transfercore.ClassRefusedPath)
				if n := len(f.Recorded()); n != 0 {
					t.Fatalf("refused call ran %d commands", n)
				}
			})
		}
		t.Run(opName+"/target without own", func(t *testing.T) {
			f := &fakeRunner{}
			caps := gnuChunkCaps
			caps.Chunk = core.ChunkCaps{Read: core.ReadNone, Mtime: core.MtimeNone}
			err := op(chunkRunner(f, caps), "/srv/data", chunkTestKey)
			expectClass(t, err, transfercore.ClassUnsupportedRemote)
			expectCode(t, err, core.ExitUnsupported)
			if n := len(f.Recorded()); n != 0 {
				t.Fatalf("unsupported call ran %d commands", n)
			}
		})
	}
}

func TestChunkOperationsMapRemoteExitCodes(t *testing.T) {
	cases := []struct {
		code  int
		class transfercore.Class
	}{
		{20, transfercore.ClassUnsupportedRemote}, {21, transfercore.ClassRefusedPath}, {22, transfercore.ClassExists},
		{23, transfercore.ClassIntegrity}, {24, transfercore.ClassRemoteFailed}, {26, transfercore.ClassRemoteFailed},
		{27, transfercore.ClassRemoteFailed}, {28, transfercore.ClassRemoteFailed}, {127, transfercore.ClassUnsupportedRemote},
	}
	for opName, op := range chunkOps() {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("%s/%d", opName, tc.code), func(t *testing.T) {
				err := op(chunkRunner(replyWith(tc.code, ""), gnuChunkCaps), "/srv/data", chunkTestKey)
				expectClass(t, err, tc.class)
				expectCode(t, err, tc.code)
				if IsStageForeign(err) != (tc.code == ExitStageForeign) || IsStageMissing(err) != (tc.code == ExitStageMissing) || IsPartMissing(err) != (tc.code == ExitPartMissing) {
					t.Fatalf("exit %d: foreign=%v missing=%v part=%v", tc.code, IsStageForeign(err), IsStageMissing(err), IsPartMissing(err))
				}
			})
		}
	}
	if IsStageForeign(nil) || IsStageMissing(io.EOF) || IsPartMissing(transfercore.Fail(transfercore.ClassInternal, "x")) {
		t.Error("exit-code helpers must reject nil, foreign errors and errors without a code")
	}
}

func TestEnsureStagingCommand(t *testing.T) {
	f := replyWith(0, "SSJACK-STAGE created\n")
	state, err := chunkRunner(f, gnuChunkCaps).EnsureStaging(context.Background(), hostileChunkParent, chunkTestKey)
	if err != nil || state != StagingCreated {
		t.Fatalf("EnsureStaging = %v, %v", state, err)
	}
	commands := f.Recorded()
	if len(commands) != 1 {
		t.Fatalf("ran %d commands, want 1", len(commands))
	}
	want := "set -eu\nparent=" + core.ShellQuote(hostileChunkParent) + "\nname=" + core.ShellQuote(".ssjack-transfer-"+chunkTestKey) +
		"\nkey=" + core.ShellQuote(chunkTestKey) + "\n" + stageFuncs + stageHeader + stageEnsureBody
	if commands[0] != want {
		t.Fatalf("command differs from the fixed template:\n%s", commands[0])
	}
	quotedIn(t, commands[0], hostileChunkParent)
	if !strings.HasPrefix(commands[0], "set -eu\nparent='/srv/it'\\''s a dir/ü ñ'\nname='.ssjack-transfer-"+chunkTestKey+"'\n") {
		t.Errorf("prologue is not the quoted caller values:\n%s", commands[0])
	}
	for _, want := range []string{`mkdir -m 700 "$stage"`, `printf '%s\n' "$magic" > "$stage/marker"`, `.ssjack-transfer-$key`} {
		if !strings.Contains(commands[0], want) {
			t.Errorf("command lacks %q", want)
		}
	}
	for verdict, want := range map[string]StagingState{
		"SSJACK-STAGE reused\n": StagingReused, "SSJACK-STAGE foreign\n": StagingForeign,
	} {
		got, err := chunkRunner(replyWith(0, verdict), gnuChunkCaps).EnsureStaging(context.Background(), "/srv/data", chunkTestKey)
		if err != nil || got != want {
			t.Errorf("verdict %q = %v, %v", verdict, got, err)
		}
	}
	for _, out := range []string{"", "SSJACK-STAGE created", "SSJACK-STAGE nonsense\n", "created\n", strings.Repeat("x", 300)} {
		_, err := chunkRunner(replyWith(0, out), gnuChunkCaps).EnsureStaging(context.Background(), "/srv/data", chunkTestKey)
		if err == nil {
			t.Errorf("output %q accepted", out)
		}
	}
	_, err = chunkRunner(replyWith(0, strings.Repeat("x", 300)), gnuChunkCaps).EnsureStaging(context.Background(), "/srv/data", chunkTestKey)
	expectClass(t, err, transfercore.ClassLimit)
}

func TestUploadPartCommand(t *testing.T) {
	var stdinGot []byte
	f := &fakeRunner{Respond: func(_ string, stdin io.Reader, stdout, _ io.Writer) (int, error) {
		stdinGot = drainReader(t, stdin)
		_, _ = io.WriteString(stdout, "SSJACK-PART 5 stored\n")
		return 0, nil
	}}
	r := chunkRunner(f, gnuChunkCaps)
	res, err := r.UploadPart(context.Background(), hostileChunkParent, chunkTestKey, transferlink.Range{Off: 7, Len: 5}, strings.NewReader("0123456789"))
	if err != nil || res != (PartResult{Count: 5, Stored: true}) {
		t.Fatalf("UploadPart = %+v, %v", res, err)
	}
	if string(stdinGot) != "01234" {
		t.Errorf("remote stdin = %q, want exactly the 5 part bytes", stdinGot)
	}
	command := f.Recorded()[0]
	m := rndPattern.FindStringSubmatch(command)
	if m == nil {
		t.Fatalf("command lacks a 16-hex rnd assignment:\n%s", command)
	}
	if !strings.Contains(command, "\noff='7'\nlen='5'\nrnd='"+m[1]+"'\n"+stageFuncs+stageHeader+partUploadBody) {
		t.Errorf("command is not the fixed part template with off, len and rnd")
	}
	quotedIn(t, command, hostileChunkParent)
	if !strings.Contains(command, `mv -T -f "$tmp" "$final"`) || strings.Contains(command, "perl") {
		t.Errorf("mv -T target must use mv -T -f and no perl:\n%s", command)
	}
	for _, want := range []string{`tmp="$stage/part-$off-$len.$rnd.tmp"`, `final="$stage/part-$off-$len"`, `(umask 077 && cat > "$tmp")`, `[ "$wc_n" != "$len" ]`, `wc -c < "$1"`} {
		if !strings.Contains(command, want) {
			t.Errorf("command lacks %q", want)
		}
	}
	if _, err := r.UploadPart(context.Background(), hostileChunkParent, chunkTestKey, transferlink.Range{Off: 7, Len: 5}, nil); err != nil {
		t.Fatalf("UploadPart with nil source: %v", err)
	}
	second := f.Recorded()[1]
	if m2 := rndPattern.FindStringSubmatch(second); m2 == nil || m2[1] == m[1] {
		t.Errorf("per-attempt random suffix repeated: %v %v", m, m2)
	}
}

func TestUploadPartPerlRenameOnFallbackTargets(t *testing.T) {
	f := replyWith(0, "SSJACK-PART 5 stored\n")
	caps := gnuChunkCaps
	caps.MvT = false
	if _, err := chunkRunner(f, caps).UploadPart(context.Background(), "/srv/data", chunkTestKey, transferlink.Range{Off: 0, Len: 5}, strings.NewReader("hello")); err != nil {
		t.Fatal(err)
	}
	command := f.Recorded()[0]
	if strings.Contains(command, "mv -T") || !strings.Contains(command, core.PerlRenameCommand+` "$tmp" "$final"`) {
		t.Errorf("fallback target must rename with perl:\n%s", command)
	}
}

func TestUploadPartResults(t *testing.T) {
	r := chunkRunner(replyWith(0, "SSJACK-PART 3 short\n"), gnuChunkCaps)
	res, err := r.UploadPart(context.Background(), "/srv/data", chunkTestKey, transferlink.Range{Off: 0, Len: 5}, strings.NewReader("abc"))
	if err != nil || res != (PartResult{Count: 3}) {
		t.Fatalf("short part = %+v, %v", res, err)
	}
	for _, out := range []string{"SSJACK-PART 5 short\n", "SSJACK-PART 4 stored\n", "", "SSJACK-PART 5 stored\nextra\n"} {
		_, err := chunkRunner(replyWith(0, out), gnuChunkCaps).UploadPart(context.Background(), "/srv/data", chunkTestKey, transferlink.Range{Off: 0, Len: 5}, strings.NewReader("abcde"))
		expectClass(t, err, transfercore.ClassIntegrity)
	}
	for _, rg := range []transferlink.Range{{Off: -1, Len: 5}, {Off: 0, Len: 0}, {Off: 0, Len: -5}, {Off: 1<<63 - 1, Len: 1}} {
		f := &fakeRunner{}
		_, err := chunkRunner(f, gnuChunkCaps).UploadPart(context.Background(), "/srv/data", chunkTestKey, rg, strings.NewReader("a"))
		expectClass(t, err, transfercore.ClassInternal)
		if len(f.Recorded()) != 0 {
			t.Errorf("range %+v ran a command", rg)
		}
	}
}

func TestListStagingCommand(t *testing.T) {
	// A hostile duplicate is rejected rather than merged.
	dup := "SSJACK-LIST 1\n100 part-0-100\n40 part-100-60\n60 part-100-60\nSSJACK-END 3\n"
	_, err := chunkRunner(replyWith(0, dup), gnuChunkCaps).ListStaging(context.Background(), "/srv/data", chunkTestKey, 1000)
	expectClass(t, err, transfercore.ClassIntegrity)
	f := replyWith(0, "SSJACK-LIST 1\n100 part-0-100\n60 part-100-60\n5 part-9-9\nSSJACK-END 3\n")
	listing, err := chunkRunner(f, gnuChunkCaps).ListStaging(context.Background(), hostileChunkParent, chunkTestKey, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(listing.Parts) != 2 || listing.Parts[0] != (transferlink.Range{Off: 0, Len: 100}) || listing.Parts[1] != (transferlink.Range{Off: 100, Len: 60}) {
		t.Errorf("Parts = %v", listing.Parts)
	}
	if len(listing.Remove) != 1 || listing.Remove[0] != "part-9-9" {
		t.Errorf("Remove = %v", listing.Remove)
	}
	command := f.Recorded()[0]
	if !strings.Contains(command, "\nmax='8256'\n"+stageFuncs+stageHeader+listBody) {
		t.Errorf("command is not the fixed list template with the default bound:\n%s", command)
	}
	quotedIn(t, command, hostileChunkParent)
	over := replyWith(0, "SSJACK-LIST 1\nSSJACK-OVERFLOW\n")
	got, err := chunkRunner(over, gnuChunkCaps).ListStaging(context.Background(), "/srv/data", chunkTestKey, 1000)
	if err != nil || !got.Overflow {
		t.Fatalf("overflow = %+v, %v", got, err)
	}
	flood := replyWith(0, "SSJACK-LIST 1\n"+strings.Repeat("1 part-0-1\n", 100000))
	_, err = chunkRunner(flood, gnuChunkCaps).ListStaging(context.Background(), "/srv/data", chunkTestKey, 1000)
	expectClass(t, err, transfercore.ClassLimit)
	f2 := replyWith(0, "SSJACK-LIST 1\nSSJACK-END 0\n")
	small := newRemote(f2.Run, "t", transfercore.Limits{MaxBytes: 1 << 20, MaxEntries: 10, MaxPathBytes: 1024, MaxDepth: 64})
	small.SetCaps(gnuChunkCaps)
	if _, err := small.ListStaging(context.Background(), "/srv/data", chunkTestKey, 1000); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f2.Recorded()[0], "\nmax='68'\n") {
		t.Errorf("bound does not follow the byte limit:\n%s", f2.Recorded()[0])
	}
}

func TestRemoveStagingEntriesCommand(t *testing.T) {
	var stdinGot string
	f := &fakeRunner{Respond: func(_ string, stdin io.Reader, _, _ io.Writer) (int, error) {
		stdinGot = string(drainReader(t, stdin))
		return 0, nil
	}}
	r := chunkRunner(f, gnuChunkCaps)
	if err := r.RemoveStagingEntries(context.Background(), hostileChunkParent, chunkTestKey, []string{"part-0-50", "part-007-5"}); err != nil {
		t.Fatal(err)
	}
	if stdinGot != "part-0-50\npart-007-5\n" {
		t.Errorf("stdin = %q", stdinGot)
	}
	command := f.Recorded()[0]
	if !strings.HasSuffix(command, stageFuncs+stageHeader+removeEntriesBody) {
		t.Errorf("command is not the fixed template:\n%s", command)
	}
	quotedIn(t, command, hostileChunkParent)
	if err := r.RemoveStagingEntries(context.Background(), "/srv/data", chunkTestKey, nil); err != nil || len(f.Recorded()) != 1 {
		t.Errorf("empty name list must be a no-op, got %v and %d commands", err, len(f.Recorded()))
	}
	for _, names := range [][]string{
		{"marker"}, {"part-1-1/../x"}, {"../part-1-1"}, {"part-1-1\n"}, {"part-1-1.tmp"}, {"part-"}, {""}, {"part-1-1", "x"},
		{"part-" + strings.Repeat("1", 46)},
	} {
		before := len(f.Recorded())
		err := r.RemoveStagingEntries(context.Background(), "/srv/data", chunkTestKey, names)
		expectClass(t, err, transfercore.ClassInternal)
		if len(f.Recorded()) != before {
			t.Errorf("names %q ran a command", names)
		}
	}
	tooMany := make([]string, MaxListedParts(sampleLimits())+1)
	for i := range tooMany {
		tooMany[i] = "part-0-1"
	}
	expectClass(t, r.RemoveStagingEntries(context.Background(), "/srv/data", chunkTestKey, tooMany), transfercore.ClassInternal)
}

func TestAssembleStagingCommand(t *testing.T) {
	for _, hash := range []string{core.HashSha256sum, core.HashShasum, core.HashSha256q} {
		for _, exec := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/exec=%v", hash, exec), func(t *testing.T) {
				const parent = "/srv/it's a dir/ü ñ"
				var names string
				var command string
				f := &fakeRunner{Respond: func(cmd string, stdin io.Reader, stdout, _ io.Writer) (int, error) {
					command = cmd
					names = string(drainReader(t, stdin))
					m := rndPattern.FindStringSubmatch(cmd)
					if m == nil {
						t.Errorf("no rnd in command")
						return 1, nil
					}
					fmt.Fprintf(stdout, "150\n%s  %s/.ssjack-transfer-%s/assembled.%s.tmp\n", strings.Repeat("ab", 32), parent, chunkTestKey, m[1])
					return 0, nil
				}}
				caps := gnuChunkCaps
				caps.Hash = hash
				got, err := chunkRunner(f, caps).AssembleStaging(context.Background(), parent, chunkTestKey,
					[]transferlink.Range{{Off: 100, Len: 50}, {Off: 0, Len: 100}}, 150, exec)
				if err != nil {
					t.Fatal(err)
				}
				if names != "part-0-100\npart-100-50\n" {
					t.Errorf("stdin names = %q, want offset order", names)
				}
				m := rndPattern.FindStringSubmatch(command)
				wantPath := parent + "/.ssjack-transfer-" + chunkTestKey + "/assembled." + m[1] + ".tmp"
				if got.Path != wantPath || got.Size != 150 || got.SHA256[0] != 0xab || got.SHA256[31] != 0xab {
					t.Errorf("Assembled = %+v, want path %q", got, wantPath)
				}
				body := assembleBody
				if exec {
					body += assembleExecSuffix
				}
				body += assembleCheckBody + core.StatHashCommand(hash) + assembleDoneBody
				if !strings.Contains(command, "\nrnd='"+m[1]+"'\nsize='150'\n"+stageFuncs+stageHeader+body) {
					t.Errorf("command is not the fixed assembly template:\n%s", command)
				}
				if strings.Contains(command, `chmod +x "$asm"`) != exec {
					t.Errorf("chmod presence = %v, want %v", !exec, exec)
				}
				quotedIn(t, command, parent)
			})
		}
	}
}

func TestAssembleStagingChecksOutput(t *testing.T) {
	parts := []transferlink.Range{{Off: 0, Len: 150}}
	reply := func(size string, nameFor func(rnd string) string) *fakeRunner {
		return &fakeRunner{Respond: func(cmd string, stdin io.Reader, stdout, _ io.Writer) (int, error) {
			_, _ = io.Copy(io.Discard, stdin)
			m := rndPattern.FindStringSubmatch(cmd)
			fmt.Fprintf(stdout, "%s\n%s  %s\n", size, strings.Repeat("cd", 32), nameFor(m[1]))
			return 0, nil
		}}
	}
	good := func(rnd string) string {
		return "/srv/data/.ssjack-transfer-" + chunkTestKey + "/assembled." + rnd + ".tmp"
	}
	if _, err := chunkRunner(reply("150", good), gnuChunkCaps).AssembleStaging(context.Background(), "/srv/data", chunkTestKey, parts, 150, false); err != nil {
		t.Fatalf("good output refused: %v", err)
	}
	cases := map[string]*fakeRunner{
		"size mismatch": reply("149", good),
		"another path":  reply("150", func(rnd string) string { return "/srv/data/other" }),
		"another rnd": reply("150", func(string) string {
			return "/srv/data/.ssjack-transfer-" + chunkTestKey + "/assembled.0000000000000000.tmp"
		}),
		"newline in path": reply("150", func(rnd string) string { return good(rnd) + "\nextra" }),
		"empty":           replyWith(0, ""),
		"hash only":       replyWith(0, strings.Repeat("ab", 32)+"  /x\n"),
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := chunkRunner(f, gnuChunkCaps).AssembleStaging(context.Background(), "/srv/data", chunkTestKey, parts, 150, false)
			expectClass(t, err, transfercore.ClassIntegrity)
		})
	}
	t.Run("zero size", func(t *testing.T) {
		var names string
		f := &fakeRunner{Respond: func(cmd string, stdin io.Reader, stdout, _ io.Writer) (int, error) {
			names = string(drainReader(t, stdin))
			m := rndPattern.FindStringSubmatch(cmd)
			fmt.Fprintf(stdout, "0\n%s  %s\n", strings.Repeat("e3", 32), good(m[1]))
			return 0, nil
		}}
		got, err := chunkRunner(f, gnuChunkCaps).AssembleStaging(context.Background(), "/srv/data", chunkTestKey, nil, 0, false)
		if err != nil || got.Size != 0 || names != "" {
			t.Fatalf("got %+v, %v, stdin %q", got, err, names)
		}
	})
	bad := map[string]struct {
		parts []transferlink.Range
		size  int64
	}{
		"gap":              {[]transferlink.Range{{Off: 0, Len: 100}}, 150},
		"missing head":     {[]transferlink.Range{{Off: 50, Len: 100}}, 150},
		"overlap":          {[]transferlink.Range{{Off: 0, Len: 100}, {Off: 50, Len: 100}}, 150},
		"duplicate":        {[]transferlink.Range{{Off: 0, Len: 150}, {Off: 0, Len: 150}}, 150},
		"past the end":     {[]transferlink.Range{{Off: 0, Len: 200}}, 150},
		"zero length part": {[]transferlink.Range{{Off: 0, Len: 0}}, 0},
		"parts for empty":  {[]transferlink.Range{{Off: 0, Len: 1}}, 0},
	}
	for name, tc := range bad {
		t.Run(name, func(t *testing.T) {
			f := &fakeRunner{}
			_, err := chunkRunner(f, gnuChunkCaps).AssembleStaging(context.Background(), "/srv/data", chunkTestKey, tc.parts, tc.size, false)
			expectClass(t, err, transfercore.ClassInternal)
			if len(f.Recorded()) != 0 {
				t.Error("an invalid tiling ran a command")
			}
		})
	}
	t.Run("size over the limit", func(t *testing.T) {
		f := &fakeRunner{}
		_, err := chunkRunner(f, gnuChunkCaps).AssembleStaging(context.Background(), "/srv/data", chunkTestKey, []transferlink.Range{{Off: 0, Len: sampleLimits().MaxBytes + 1}}, sampleLimits().MaxBytes+1, false)
		expectClass(t, err, transfercore.ClassLimit)
		if len(f.Recorded()) != 0 {
			t.Error("over-limit assembly ran a command")
		}
	})
	t.Run("negative size", func(t *testing.T) {
		_, err := chunkRunner(&fakeRunner{}, gnuChunkCaps).AssembleStaging(context.Background(), "/srv/data", chunkTestKey, nil, -1, false)
		expectClass(t, err, transfercore.ClassLimit)
	})
}

func TestRemoveChunkStagingCommand(t *testing.T) {
	f := replyWith(0, "")
	if err := chunkRunner(f, gnuChunkCaps).RemoveChunkStaging(context.Background(), hostileChunkParent, chunkTestKey); err != nil {
		t.Fatal(err)
	}
	command := f.Recorded()[0]
	want := "set -eu\nparent=" + core.ShellQuote(hostileChunkParent) + "\nname=" + core.ShellQuote(".ssjack-transfer-"+chunkTestKey) +
		"\nkey=" + core.ShellQuote(chunkTestKey) + "\n" + stageFuncs + stageHeader + removeStagingBody
	if command != want {
		t.Errorf("command differs from the fixed template:\n%s", command)
	}
	quotedIn(t, command, hostileChunkParent)
	if strings.Index(command, "check_stage || rc=$?") > strings.Index(command, `rm -rf "$stage"`) {
		t.Error("the adoption check must precede rm -rf")
	}
	if strings.Count(removeStagingBody, "rm -rf") != 1 {
		t.Error("removal body must have exactly one rm -rf")
	}
}

func TestCollectStagingCommand(t *testing.T) {
	f := replyWith(0, "SSJACK-GC 3\n")
	n, err := chunkRunner(f, gnuChunkCaps).CollectStaging(context.Background(), hostileChunkParent, chunkTestKey)
	if err != nil || n != 3 {
		t.Fatalf("CollectStaging = %d, %v", n, err)
	}
	command := f.Recorded()[0]
	want := "set -eu\nparent=" + core.ShellQuote(hostileChunkParent) + "\nexcl=" + core.ShellQuote(".ssjack-transfer-"+chunkTestKey) + "\n" + stageFuncs + gcBody
	if command != want {
		t.Errorf("command differs from the fixed template:\n%s", command)
	}
	quotedIn(t, command, hostileChunkParent)
	f2 := replyWith(0, "SSJACK-GC 0\n")
	if _, err := chunkRunner(f2, gnuChunkCaps).CollectStaging(context.Background(), "/srv/data", ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f2.Recorded()[0], "\nexcl=''\n") {
		t.Errorf("empty exclusion must be an empty string:\n%s", f2.Recorded()[0])
	}
	for _, out := range []string{"", "SSJACK-GC 17\n", "SSJACK-GC x\n", "SSJACK-GC 1"} {
		_, err := chunkRunner(replyWith(0, out), gnuChunkCaps).CollectStaging(context.Background(), "/srv/data", "")
		if err == nil {
			t.Errorf("output %q accepted", out)
		}
	}
	for _, tc := range []struct{ parent, key string }{{"srv", ""}, {"/", ""}, {"/srv/a\nb", ""}, {"/srv/data", "XYZ"}, {"/srv/data", strings.ToUpper(chunkTestKey)}} {
		f := &fakeRunner{}
		_, err := chunkRunner(f, gnuChunkCaps).CollectStaging(context.Background(), tc.parent, tc.key)
		expectClass(t, err, transfercore.ClassRefusedPath)
		if len(f.Recorded()) != 0 {
			t.Errorf("%+v ran a command", tc)
		}
	}
	caps := gnuChunkCaps
	caps.Chunk = core.ChunkCaps{}
	_, err = chunkRunner(&fakeRunner{}, caps).CollectStaging(context.Background(), "/srv/data", "")
	expectClass(t, err, transfercore.ClassUnsupportedRemote)
}

func TestGCBodyBounds(t *testing.T) {
	for _, want := range []string{`"$removed" -ge 16`, `"$checked" -ge 256`, `"$name" = "$excl"`, `check_stage || rc=$?`, `stage_idle`} {
		if !strings.Contains(gcBody, want) {
			t.Errorf("gc body lacks %q", want)
		}
	}
	// Two adoption checks and two idleness checks, the last pair right before
	// the only rm -rf.
	if strings.Count(gcBody, "check_stage || rc=$?") != 2 || strings.Count(gcBody, "if ! stage_idle; then") != 2 || strings.Count(gcBody, "rm -rf") != 1 {
		t.Error("gc must check twice and remove once")
	}
	if strings.LastIndex(gcBody, "check_stage || rc=$?") > strings.Index(gcBody, "rm -rf") {
		t.Error("the repeated check must precede rm -rf")
	}
}

func TestDiskAvailableCommand(t *testing.T) {
	df := "Filesystem     1024-blocks   Used Available Capacity Mounted on\n/dev/sda1           100000  40000     60000      41% /\n"
	f := replyWith(0, df)
	avail, ok, err := chunkRunner(f, gnuChunkCaps).DiskAvailable(context.Background(), hostileChunkParent)
	if err != nil || !ok || avail != 60000*1024 {
		t.Fatalf("DiskAvailable = %d, %v, %v", avail, ok, err)
	}
	command := f.Recorded()[0]
	if command != "set -eu\nparent="+core.ShellQuote(hostileChunkParent)+"\n"+diskBody {
		t.Errorf("command differs from the fixed template:\n%s", command)
	}
	quotedIn(t, command, hostileChunkParent)
	for _, out := range []string{"", "garbage\n", "df: unrecognized option '-P'\n"} {
		_, ok, err := chunkRunner(replyWith(0, out), gnuChunkCaps).DiskAvailable(context.Background(), "/srv/data")
		if err != nil || ok {
			t.Errorf("output %q: ok=%v err=%v, want skip", out, ok, err)
		}
	}
	_, _, err = chunkRunner(replyWith(21, ""), gnuChunkCaps).DiskAvailable(context.Background(), "/srv/data")
	expectClass(t, err, transfercore.ClassRefusedPath)
	for _, parent := range []string{"srv", "/", "/srv/a\nb", "/srv/a\\b"} {
		f := &fakeRunner{}
		_, _, err := chunkRunner(f, gnuChunkCaps).DiskAvailable(context.Background(), parent)
		expectClass(t, err, transfercore.ClassRefusedPath)
		if len(f.Recorded()) != 0 {
			t.Errorf("%q ran a command", parent)
		}
	}
}

func TestStatSourceCommand(t *testing.T) {
	for mode, flavour := range map[core.MtimeMode]string{core.MtimeGNU: statSourceGNU, core.MtimeBSD: statSourceBSD} {
		f := replyWith(0, "1234 1700000000\n")
		caps := gnuChunkCaps
		caps.Chunk.Mtime = mode
		got, err := chunkRunner(f, caps).StatSource(context.Background(), "/srv/it's/ü ñ.bin")
		if err != nil || got != (SourceStat{Size: 1234, MTime: 1700000000}) {
			t.Fatalf("%s: StatSource = %+v, %v", mode, got, err)
		}
		command := f.Recorded()[0]
		if command != "set -eu\npath="+core.ShellQuote("/srv/it's/ü ñ.bin")+"\n"+statSourceBody+flavour {
			t.Errorf("%s: command differs from the fixed template:\n%s", mode, command)
		}
		quotedIn(t, command, "/srv/it's/ü ñ.bin")
	}
	for _, mode := range []core.MtimeMode{core.MtimeNone, ""} {
		f := &fakeRunner{}
		caps := gnuChunkCaps
		caps.Chunk.Mtime = mode
		_, err := chunkRunner(f, caps).StatSource(context.Background(), "/srv/data.bin")
		expectClass(t, err, transfercore.ClassUnsupportedRemote)
		if len(f.Recorded()) != 0 {
			t.Error("unsupported stat ran a command")
		}
	}
	for _, out := range []string{"", "1234\n", "1234 17x\n", "-1 5\n", "1 2\n3 4\n"} {
		_, err := chunkRunner(replyWith(0, out), gnuChunkCaps).StatSource(context.Background(), "/srv/data.bin")
		expectClass(t, err, transfercore.ClassIntegrity)
	}
	_, err := chunkRunner(replyWith(21, ""), gnuChunkCaps).StatSource(context.Background(), "/srv/data.bin")
	expectClass(t, err, transfercore.ClassRefusedPath)
	for _, path := range []string{"srv/x", "/", "/srv/a\nb", "/srv/a\\b"} {
		f := &fakeRunner{}
		_, err := chunkRunner(f, gnuChunkCaps).StatSource(context.Background(), path)
		expectClass(t, err, transfercore.ClassRefusedPath)
		if len(f.Recorded()) != 0 {
			t.Errorf("%q ran a command", path)
		}
	}
}

// writeN answers every command with n bytes of 'x'.
func writeN(n int) *fakeRunner {
	return &fakeRunner{Respond: func(_ string, _ io.Reader, stdout, _ io.Writer) (int, error) {
		_, _ = io.WriteString(stdout, strings.Repeat("x", n))
		return 0, nil
	}}
}

func TestReadRangeSelectsPrimitive(t *testing.T) {
	const path = "/srv/it's/ü ñ.bin"
	prologue := "set -eu\npath=" + core.ShellQuote(path) + "\n" + readRangeBody
	cases := []struct {
		name       string
		mode       core.ReadMode
		part       transferlink.Range
		grid, size int64
		want       string
	}{
		{"dd on the grid", core.ReadDD, transferlink.Range{Off: 200, Len: 100}, 100, 1000, "bs='100'\nskip='2'\n" + readRangeDD},
		{"dd first block", core.ReadDD, transferlink.Range{Off: 0, Len: 100}, 100, 1000, "bs='100'\nskip='0'\n" + readRangeDD},
		{"dd tail of file shorter than block", core.ReadDD, transferlink.Range{Off: 900, Len: 50}, 100, 950, "bs='100'\nskip='9'\n" + readRangeDD},
		{"dd tail of file full block", core.ReadDD, transferlink.Range{Off: 900, Len: 100}, 100, 1000, "bs='100'\nskip='9'\n" + readRangeDD},
		{"off the grid uses tail", core.ReadDD, transferlink.Range{Off: 250, Len: 100}, 100, 1000, "start='251'\nlen='100'\n" + readRangeTail},
		{"short mid-file part on the grid uses tail", core.ReadDD, transferlink.Range{Off: 200, Len: 50}, 100, 1000, "start='201'\nlen='50'\n" + readRangeTail},
		{"longer than a block uses tail", core.ReadDD, transferlink.Range{Off: 200, Len: 300}, 100, 1000, "start='201'\nlen='300'\n" + readRangeTail},
		{"tail mode is always tail", core.ReadTail, transferlink.Range{Off: 200, Len: 100}, 100, 1000, "start='201'\nlen='100'\n" + readRangeTail},
		{"huge grid uses tail", core.ReadDD, transferlink.Range{Off: 0, Len: 1000}, 100 << 20, 1000, "start='1'\nlen='1000'\n" + readRangeTail},
		{"no grid uses tail", core.ReadDD, transferlink.Range{Off: 0, Len: 10}, 0, 1000, "start='1'\nlen='10'\n" + readRangeTail},
		{"negative grid uses tail", core.ReadDD, transferlink.Range{Off: 0, Len: 10}, -5, 1000, "start='1'\nlen='10'\n" + readRangeTail},
		{"largest block on the grid", core.ReadDD, transferlink.Range{Off: 64 << 20, Len: 1000}, 64 << 20, 64<<20 + 1000, "bs='67108864'\nskip='1'\n" + readRangeDD},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := writeN(int(tc.part.Len))
			caps := gnuChunkCaps
			caps.Chunk.Read = tc.mode
			var sink countSink
			n, err := chunkRunner(f, caps).ReadRange(context.Background(), path, tc.part, tc.grid, tc.size, &sink)
			if err != nil || n != tc.part.Len || sink.n != tc.part.Len {
				t.Fatalf("ReadRange = %d, %v (sink %d)", n, err, sink.n)
			}
			command := f.Recorded()[0]
			if command != prologue+tc.want {
				t.Errorf("command differs:\n got %q\nwant %q", command, prologue+tc.want)
			}
			quotedIn(t, command, path)
		})
	}
}

type countSink struct{ n int64 }

func (c *countSink) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

func TestReadRangeRefusals(t *testing.T) {
	part := transferlink.Range{Off: 100, Len: 100}
	t.Run("short read is an integrity error", func(t *testing.T) {
		var sink countSink
		n, err := chunkRunner(writeN(60), gnuChunkCaps).ReadRange(context.Background(), "/srv/data.bin", part, 100, 1000, &sink)
		expectClass(t, err, transfercore.ClassIntegrity)
		if n != 60 {
			t.Errorf("count = %d, want the 60 bytes received", n)
		}
	})
	t.Run("long read is an integrity error", func(t *testing.T) {
		_, err := chunkRunner(writeN(150), gnuChunkCaps).ReadRange(context.Background(), "/srv/data.bin", part, 100, 1000, io.Discard)
		expectClass(t, err, transfercore.ClassIntegrity)
	})
	t.Run("remote refusal", func(t *testing.T) {
		_, err := chunkRunner(replyWith(21, ""), gnuChunkCaps).ReadRange(context.Background(), "/srv/data.bin", part, 100, 1000, io.Discard)
		expectClass(t, err, transfercore.ClassRefusedPath)
	})
	for _, mode := range []core.ReadMode{core.ReadNone, ""} {
		f := &fakeRunner{}
		caps := gnuChunkCaps
		caps.Chunk.Read = mode
		_, err := chunkRunner(f, caps).ReadRange(context.Background(), "/srv/data.bin", part, 100, 1000, io.Discard)
		expectClass(t, err, transfercore.ClassUnsupportedRemote)
		if len(f.Recorded()) != 0 {
			t.Error("unsupported read ran a command")
		}
	}
	invalid := map[string]struct {
		part transferlink.Range
		size int64
		dst  io.Writer
		path string
	}{
		"zero length":    {transferlink.Range{Off: 0, Len: 0}, 1000, io.Discard, "/srv/a"},
		"negative off":   {transferlink.Range{Off: -1, Len: 5}, 1000, io.Discard, "/srv/a"},
		"past the end":   {transferlink.Range{Off: 990, Len: 20}, 1000, io.Discard, "/srv/a"},
		"negative size":  {part, -1, io.Discard, "/srv/a"},
		"nil writer":     {part, 1000, nil, "/srv/a"},
		"relative path":  {part, 1000, io.Discard, "srv/a"},
		"newline path":   {part, 1000, io.Discard, "/srv/a\nb"},
		"overflow range": {transferlink.Range{Off: 1<<63 - 10, Len: 100}, 1<<63 - 1, io.Discard, "/srv/a"},
	}
	for name, tc := range invalid {
		t.Run(name, func(t *testing.T) {
			f := &fakeRunner{}
			_, err := chunkRunner(f, gnuChunkCaps).ReadRange(context.Background(), tc.path, tc.part, 100, tc.size, tc.dst)
			if err == nil {
				t.Fatal("invalid call accepted")
			}
			if len(f.Recorded()) != 0 {
				t.Error("invalid call ran a command")
			}
		})
	}
}

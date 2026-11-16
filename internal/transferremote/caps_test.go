package transferremote

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

func TestCapsSelectVariants(t *testing.T) {
	tests := []struct {
		name   string
		report string
		stat   string
		tree   string
	}{
		{
			name:   "sha256sum",
			report: "SSJACK-CAPS sha256sum t gnu names\n",
			stat:   `sha256sum "$path"`,
			tree:   `xargs -0 sha256sum`,
		},
		{
			name:   "shasum",
			report: "SSJACK-CAPS shasum t gnu names\n",
			stat:   "out=$(shasum -a 256 < \"$path\") || exit 24\nhash=${out%% *}\n[ \"$out\" = \"$hash  -\" ] || exit 24\nprintf '%s  %s\\n' \"$hash\" \"$path\"",
			tree:   `xargs -0 -n 1 sh -c '[ "$#" -gt 0 ] || exit 0; f="$1"; out=$(shasum -a 256 < "$f") || exit 24; hash=${out%% *}; [ "$out" = "$hash  -" ] || exit 24; printf "%s  %s\n" "$hash" "$f"' _`,
		},
		{
			name:   "sha256q",
			report: "SSJACK-CAPS sha256q t gnu names\n",
			stat:   "hash=$(sha256 -q \"$path\") || exit 24\nprintf '%s  %s\\n' \"$hash\" \"$path\"",
			tree:   `xargs -0 -n 1 sh -c '[ "$#" -gt 0 ] || exit 0; f="$1"; hash=$(sha256 -q "$f") || exit 24; printf "%s  %s\n" "$hash" "$f"' _`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeRunner{respond: func(command string, _ io.Reader, stdout, _ io.Writer) (int, error) {
				if strings.Contains(command, "SSJACK-CAPS") {
					_, _ = io.WriteString(stdout, tt.report)
				}
				return 0, nil
			}}
			r := New(f.run, "t", sampleLimits()).(*remoteRunner)
			ctx := context.Background()
			if err := r.Probe(ctx); err != nil {
				t.Fatal(err)
			}
			probe := f.recorded()[0]
			if !regexp.MustCompile(`'/\.ssjack-probe-[0-9a-f]{16}'`).MatchString(probe) {
				t.Errorf("probe lacks random scratch path with leading slash: %s", probe)
			}
			if !strings.Contains(probe, `elif out="$(shasum -a 256 < "$d/h" 2>/dev/null)" && [ "$out" = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  -" ]; then`) {
				t.Errorf("probe lacks exact abc stdin shasum check:\n%s", probe)
			}
			for _, want := range []string{
				"mkdir -m 700",
				`trap 'rm -rf "$d"' 0`,
				`if mv -T "$d/mv-file" "$d/mv-file-dest"; then`,
				`if mv -T "$d/mv-dir-source" "$d/mv-dir-dest"; then`,
				"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
				"xargs -0 sh -c",
				`tar -x --no-same-owner --no-same-permissions -f "$d/archive.tar"`,
			} {
				if !strings.Contains(probe, want) {
					t.Errorf("probe lacks %q", want)
				}
			}

			_, _, _ = r.StatFile(ctx, "/srv/file.bin")
			_, _ = r.PreflightTree(ctx, "/srv/tree")
			_ = r.TarIn(ctx, "/srv/tree", strings.NewReader(""))
			_ = r.PublishFile(ctx, "/srv/staging", "/srv/dest", false)
			_ = r.PublishFile(ctx, "/srv/staging", "/srv/dest", true)
			_ = r.PublishDir(ctx, "/srv/staging", "/srv/dest", false)
			_ = r.PublishDir(ctx, "/srv/staging", "/srv/dest", true)
			commands := f.recorded()
			if len(commands) != 11 {
				t.Fatalf("got %d commands, want 11", len(commands))
			}
			if !strings.HasSuffix(commands[1], tt.stat+"\n") {
				t.Errorf("StatFile command lacks selected hash tail %q:\n%s", tt.stat, commands[1])
			}
			if !strings.HasSuffix(commands[4], tt.tree+"\n") {
				t.Errorf("tree command lacks selected hash tail %q:\n%s", tt.tree, commands[4])
			}
			if !strings.Contains(commands[6], "tar -x --no-same-owner --no-same-permissions -f -") ||
				strings.Contains(commands[6], "tar -x -o") {
				t.Errorf("TarIn command does not use GNU long flags:\n%s", commands[6])
			}
			for _, index := range []int{7, 8, 9, 10} {
				if !strings.Contains(commands[index], "mv -T") {
					t.Errorf("publish command %d lacks GNU mv -T:\n%s", index, commands[index])
				}
			}
		})
	}
}

func TestTarInCanonicalEmptyArchive(t *testing.T) {
	const root = "/srv/tree"
	f := &fakeRunner{respond: func(command string, stdin io.Reader, _, _ io.Writer) (int, error) {
		if stdin != nil {
			t.Errorf("canonical empty archive stdin = %T, want nil", stdin)
		}
		return 0, nil
	}}
	if err := New(f.run, "t", sampleLimits()).TarIn(context.Background(), root, bytes.NewReader(make([]byte, 1024))); err != nil {
		t.Fatalf("TarIn canonical empty archive = %v, want nil", err)
	}
	commands := f.recorded()
	want := `set -eu
root='/srv/tree'
if [ ! -d "$root" ] || [ -L "$root" ]; then
	exit 21
fi
`
	if len(commands) != 1 || commands[0] != want {
		t.Fatalf("commands = %#v, want only root-check script %q", commands, want)
	}
	if strings.Contains(commands[0], "tar ") {
		t.Errorf("canonical empty archive command runs tar:\\n%s", commands[0])
	}
}

func TestTarInNonCanonicalEmptyStreamsPreserveGNUCommandAndBytes(t *testing.T) {
	for _, size := range []int{0, 1023, 1025} {
		t.Run(fmt.Sprintf("%d-zero-bytes", size), func(t *testing.T) {
			payload := make([]byte, size)
			var drained []byte
			f := &fakeRunner{respond: func(command string, stdin io.Reader, _, _ io.Writer) (int, error) {
				if stdin != nil {
					drained = drainReader(t, stdin)
				}
				return 0, nil
			}}
			if err := New(f.run, "t", sampleLimits()).TarIn(context.Background(), "/srv/tree", bytes.NewReader(payload)); err != nil {
				t.Fatalf("TarIn = %v, want nil", err)
			}
			if !bytes.Equal(drained, payload) {
				t.Errorf("forwarded %d bytes, want exact %d-byte payload", len(drained), size)
			}
			commands := f.recorded()
			want := fmt.Sprintf(tarInTemplate, shellQuote("/srv/tree"))
			if len(commands) != 1 || commands[0] != want {
				t.Errorf("commands = %#v, want unchanged GNU script %q", commands, want)
			}
		})
	}
}

func TestTarInNilSourcePreservesGNUCommand(t *testing.T) {
	f := &fakeRunner{respond: func(command string, stdin io.Reader, _, _ io.Writer) (int, error) {
		if stdin != nil {
			t.Errorf("nil source stdin = %T, want nil", stdin)
		}
		return 0, nil
	}}
	if err := New(f.run, "t", sampleLimits()).TarIn(context.Background(), "/srv/tree", nil); err != nil {
		t.Fatalf("TarIn nil source = %v, want nil", err)
	}
	commands := f.recorded()
	want := fmt.Sprintf(tarInTemplate, shellQuote("/srv/tree"))
	if len(commands) != 1 || commands[0] != want {
		t.Fatalf("commands = %#v, want unchanged GNU script %q", commands, want)
	}
}

func TestProbeSelectsWCFilenameCapability(t *testing.T) {
	probe := fmt.Sprintf(probeTemplate, shellQuote("/.ssjack-probe-0123456789abcdef"))
	utf8Fixture := `wc_path="$d/wc name ' $(printf '\303\274 \303\261')"`
	if !strings.Contains(probe, utf8Fixture) {
		t.Errorf("probe does not exercise wc with the funky UTF-8 filename (literal or octal escaped)")
	}
	for _, want := range []string{
		"SSJACK-CAPS ",
		"wc_path=",
		`wc -c "$wc_path"`,
		`while [ "${count# }" != "$count" ]; do count=${count# }; done`,
		`while [ "${out# }" != "$out" ]; do out=${out# }; done`,
		`printf 'SSJACK-CAPS %s %s gnu %s\n' "$hash" "$rename" "$wc"`,
	} {
		if !strings.Contains(probe, want) {
			t.Errorf("probe lacks wc capability check %q", want)
		}
	}
}

func TestCapsAcceptsAllCapabilityCombinations(t *testing.T) {
	for _, hash := range []string{hashSha256sum, hashShasum, hashSha256q} {
		for _, rename := range []string{"t", "p"} {
			for _, wc := range []string{"names", "stdin"} {
				t.Run(hash+"/"+rename+"/"+wc, func(t *testing.T) {
					report := fmt.Sprintf("SSJACK-CAPS %s %s gnu %s\n", hash, rename, wc)
					f := &fakeRunner{respond: func(command string, _ io.Reader, stdout, _ io.Writer) (int, error) {
						if strings.Contains(command, "SSJACK-CAPS") {
							_, err := io.WriteString(stdout, report)
							return 0, err
						}
						return 0, nil
					}}
					r := New(f.run, "t", sampleLimits()).(*remoteRunner)
					if err := r.Probe(context.Background()); err != nil {
						t.Fatalf("Probe(%q) = %v", report, err)
					}
					got := r.capabilities()
					if got.hash != hash || got.mvT != (rename == "t") || got.wcNames != (wc == "names") || !got.tarGNU {
						t.Errorf("capabilities = %#v, want hash %q, mvT %t, wcNames %t, tarGNU true", got, hash, rename == "t", wc == "names")
					}
				})
			}
		}
	}
}

func TestCapsRejectMalformedReports(t *testing.T) {
	reports := []string{
		"",
		"garbage\n",
		"SSJACK-CAPS sha256sum t gnu\n", // missing wc token
		"SSJACK-CAPS bogus t gnu names\n",
		"SSJACK-CAPS sha256sum x gnu names\n",
		"SSJACK-CAPS sha256sum n gnu names\n",
		"SSJACK-CAPS sha256sum t o names\n",
		"SSJACK-CAPS sha256sum t gnu unknown\n",
		"SSJACK-CAPS sha256sum t gnu names",
		"SSJACK-CAPS sha256sum t gnu names extra\n",
		"SSJACK-CAPS sha256sum t gnu names\nextra\n",
		"SSJACK-CAPS  sha256sum t gnu names\n",
		"SSJACK-CAPS sha256sum t gnu names\nSSJACK-CAPS sha256sum t gnu names\n",
	}
	for i, report := range reports {
		t.Run(fmt.Sprintf("report-%d", i), func(t *testing.T) {
			f := &fakeRunner{respond: func(command string, _ io.Reader, stdout, _ io.Writer) (int, error) {
				if strings.Contains(command, "SSJACK-CAPS") {
					_, _ = io.WriteString(stdout, report)
				}
				return 0, nil
			}}
			err := New(f.run, "t", sampleLimits()).Probe(context.Background())
			expectClass(t, err, transfercore.ClassUnsupportedRemote)
			expectCode(t, err, 20)
		})
	}
	t.Run("valid report with failure code", func(t *testing.T) {
		f := &fakeRunner{respond: func(command string, _ io.Reader, stdout, _ io.Writer) (int, error) {
			if strings.Contains(command, "SSJACK-CAPS") {
				_, _ = io.WriteString(stdout, "SSJACK-CAPS sha256sum t gnu names\n")
			}
			return 20, nil
		}}
		err := New(f.run, "t", sampleLimits()).Probe(context.Background())
		expectClass(t, err, transfercore.ClassUnsupportedRemote)
		expectCode(t, err, 20)
	})
}

func TestCapsPublishExitCodeMapping(t *testing.T) {
	operations := []struct {
		name string
		run  func(*remoteRunner) error
	}{
		{"publish-file-no-overwrite", func(r *remoteRunner) error {
			return r.PublishFile(context.Background(), "/srv/staging", "/srv/dest", false)
		}},
		{"publish-file-overwrite", func(r *remoteRunner) error {
			return r.PublishFile(context.Background(), "/srv/staging", "/srv/dest", true)
		}},
		{"publish-dir-no-overwrite", func(r *remoteRunner) error {
			return r.PublishDir(context.Background(), "/srv/staging", "/srv/dest", false)
		}},
		{"publish-dir-overwrite", func(r *remoteRunner) error {
			return r.PublishDir(context.Background(), "/srv/staging", "/srv/dest", true)
		}},
	}
	cases := []struct {
		code int
		want transfercore.Class
	}{
		{20, transfercore.ClassUnsupportedRemote},
		{21, transfercore.ClassRefusedPath},
		{22, transfercore.ClassExists},
		{23, transfercore.ClassIntegrity},
		{24, transfercore.ClassRemoteFailed},
		{25, transfercore.ClassRemoteFailed},
		{126, transfercore.ClassUnsupportedRemote},
		{127, transfercore.ClassUnsupportedRemote},
	}
	for _, op := range operations {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("%s-code-%d", op.name, tc.code), func(t *testing.T) {
				f := &fakeRunner{respond: func(command string, _ io.Reader, stdout, _ io.Writer) (int, error) {
					if strings.Contains(command, "SSJACK-CAPS") {
						_, _ = io.WriteString(stdout, "SSJACK-CAPS sha256sum t gnu names\n")
						return 0, nil
					}
					return tc.code, nil
				}}
				r := New(f.run, "t", sampleLimits()).(*remoteRunner)
				if err := r.Probe(context.Background()); err != nil {
					t.Fatal(err)
				}
				err := op.run(r)
				expectClass(t, err, tc.want)
				expectCode(t, err, tc.code)
			})
		}
	}
}

func TestCapsGNUCommandBaselines(t *testing.T) {
	f := &fakeRunner{}
	r := New(f.run, "t", sampleLimits()).(*remoteRunner)
	ctx := context.Background()
	_, _, _ = r.StatFile(ctx, "/srv/file.bin")
	_ = r.TarIn(ctx, "/srv/tree", strings.NewReader(""))
	_ = r.PublishFile(ctx, "/srv/staging", "/srv/dest", false)
	commands := f.recorded()
	want := []string{
		"set -eu\npath='/srv/file.bin'\nif [ -L \"$path\" ] || [ ! -f \"$path\" ]; then\n\texit 21\nfi\nwc -c < \"$path\"\nsha256sum \"$path\"\n",
		"set -eu\nroot='/srv/tree'\nif [ ! -d \"$root\" ] || [ -L \"$root\" ]; then\n\texit 21\nfi\ncd \"$root\" || exit 21\ntar -x --no-same-owner --no-same-permissions -f - || exit 24\n",
		"set -eu\nsrc='/srv/staging'\ndst='/srv/dest'\nif [ -L \"$dst\" ] || [ -e \"$dst\" ]; then\n\texit 22\nfi\nif ln \"$src\" \"$dst\"; then\n\trm -f \"$src\" || exit 24\n\texit 0\nfi\nif [ -e \"$dst\" ] || [ -L \"$dst\" ]; then\n\texit 22\nfi\nif mv -T \"$src\" \"$dst\"; then\n\texit 0\nfi\nif [ -e \"$dst\" ] || [ -L \"$dst\" ]; then\n\texit 22\nfi\nexit 24\n",
	}
	if len(commands) != len(want) {
		t.Fatalf("got %d commands, want %d", len(commands), len(want))
	}
	for i := range want {
		if commands[i] != want[i] {
			t.Errorf("command %d differs from GNU baseline:\n got: %q\nwant: %q", i, commands[i], want[i])
		}
	}
}

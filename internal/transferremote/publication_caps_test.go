package transferremote

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

func TestPerlPublicationCapsRenderFixedCommandsAndQuotedPaths(t *testing.T) {
	staging := "/srv/staging path ' $(touch should-not-run)"
	dest := "/srv/destination path ' $(touch should-not-run)"
	f := &fakeRunner{respond: func(command string, _ io.Reader, stdout, _ io.Writer) (int, error) {
		if strings.Contains(command, "SSJACK-CAPS") {
			_, err := io.WriteString(stdout, "SSJACK-CAPS sha256sum p gnu names\n")
			return 0, err
		}
		return 0, nil
	}}
	r := New(f.run, "t", sampleLimits()).(*remoteRunner)
	ctx := context.Background()
	if err := r.Probe(ctx); err != nil {
		t.Fatalf("Probe = %v", err)
	}
	if got := r.capabilities(); got.mvT {
		t.Fatalf("capabilities = %#v, want Perl publication", got)
	}
	if err := r.PublishFile(ctx, staging, dest, false); err != nil {
		t.Fatalf("PublishFile = %v", err)
	}
	if err := r.PublishFile(ctx, staging, dest, true); err != nil {
		t.Fatalf("PublishFile overwrite = %v", err)
	}
	if err := r.PublishDir(ctx, staging, dest, false); err != nil {
		t.Fatalf("PublishDir = %v", err)
	}
	if err := r.PublishDir(ctx, staging, dest, true); err != nil {
		t.Fatalf("PublishDir overwrite = %v", err)
	}
	commands := f.recorded()
	if len(commands) != 5 {
		t.Fatalf("recorded %d commands, want probe + four publications", len(commands))
	}
	for i, command := range commands[1:] {
		if !strings.Contains(command, perlRenameCommand) {
			t.Errorf("publication %d lacks fixed Perl rename command:\n%s", i, command)
		}
		if strings.Contains(command, "mv -T") {
			t.Errorf("publication %d unexpectedly uses mv -T:\n%s", i, command)
		}
		if !strings.Contains(command, perlRenameCommand+` "$src" "$dst"`) {
			t.Errorf("publication %d lacks Perl rename argv:\n%s", i, command)
		}
		quotedIn(t, command, staging)
		quotedIn(t, command, dest)
	}
	if !strings.Contains(commands[1], perlLinkCommand+` "$src" "$dst"`) {
		t.Errorf("no-overwrite file publication lacks Perl link argv:\n%s", commands[1])
	}
	if got := strings.Count(commands[4], perlRenameCommand); got != 4 {
		t.Errorf("directory overwrite has %d Perl renames, want 4:\n%s", got, commands[4])
	}
	if !strings.Contains(commands[0], `perl -e 'exit(rename($ARGV[0], $ARGV[1]) ? 0 : 1)' -- "$1" "$2"`) {
		t.Errorf("probe lacks fixed Perl rename argv operation:\n%s", commands[0])
	}
	if !strings.Contains(commands[0], `perl -e 'exit(link($ARGV[0], $ARGV[1]) ? 0 : 1)' -- "$1" "$2"`) {
		t.Errorf("probe lacks fixed Perl link argv operation:\n%s", commands[0])
	}
}

func TestPerlPublicationExitCodeMapping(t *testing.T) {
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
		{21, transfercore.ClassRefusedPath},
		{22, transfercore.ClassExists},
		{24, transfercore.ClassRemoteFailed},
		{25, transfercore.ClassRemoteFailed},
	}
	for _, op := range operations {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("%s-code-%d", op.name, tc.code), func(t *testing.T) {
				f := &fakeRunner{respond: func(command string, _ io.Reader, stdout, _ io.Writer) (int, error) {
					if strings.Contains(command, "SSJACK-CAPS") {
						_, err := io.WriteString(stdout, "SSJACK-CAPS sha256sum p gnu names\n")
						return 0, err
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

func TestGNUPublicationTemplatesRemainUnchanged(t *testing.T) {
	caps := remoteCaps{hash: hashSha256sum, mvT: true, tarGNU: true, wcNames: true}
	for name, template := range map[string]string{
		"file-no-overwrite": publishFileTemplate,
		"file-overwrite":    publishFileOverwriteTemplate,
		"dir-no-overwrite":  publishDirTemplate,
		"dir-overwrite":     publishDirOverwriteTemplate,
	} {
		t.Run(name, func(t *testing.T) {
			if got := publicationTemplate(template, caps); got != template {
				t.Fatalf("GNU publication template changed:\n got: %q\nwant: %q", got, template)
			}
		})
	}
	f := &fakeRunner{}
	r := New(f.run, "t", sampleLimits()).(*remoteRunner)
	ctx := context.Background()
	if err := r.PublishFile(ctx, "/srv/staging", "/srv/dest", false); err != nil {
		t.Fatal(err)
	}
	if err := r.PublishFile(ctx, "/srv/staging", "/srv/dest", true); err != nil {
		t.Fatal(err)
	}
	if err := r.PublishDir(ctx, "/srv/staging", "/srv/dest", false); err != nil {
		t.Fatal(err)
	}
	if err := r.PublishDir(ctx, "/srv/staging", "/srv/dest", true); err != nil {
		t.Fatal(err)
	}
	commands := f.recorded()
	if len(commands) != 4 {
		t.Fatalf("recorded %d publications, want 4", len(commands))
	}
	want := []string{
		fmt.Sprintf(publishFileTemplate, shellQuote("/srv/staging"), shellQuote("/srv/dest")),
		fmt.Sprintf(publishFileOverwriteTemplate, shellQuote("/srv/staging"), shellQuote("/srv/dest")),
		fmt.Sprintf(publishDirTemplate, shellQuote("/srv/staging"), shellQuote("/srv/dest")),
		fmt.Sprintf(publishDirOverwriteTemplate, shellQuote("/srv/staging"), shellQuote("/srv/dest"), shellQuote("/srv/"+testAsideName(t, commands[3]))),
	}
	for i := range want {
		if commands[i] != want[i] {
			t.Errorf("GNU publication %d differs from original rendered template:\n got: %q\nwant: %q", i, commands[i], want[i])
		}
	}
	if strings.Contains(commands[3], perlRenameCommand) {
		t.Errorf("GNU directory overwrite changed publication primitive:\n%s", commands[3])
	}
}

func TestProbeSelectsMvTOnlyForCorrectRenameSemantics(t *testing.T) {
	if !strings.Contains(probeTemplate, `if [ -e "$d/mv-cap-source" ] || [ -L "$d/mv-cap-source" ] || [ ! -f "$d/mv-cap-dest" ]; then
		rename='p'
	else`) {
		t.Fatal("probe does not select GNU mv after verifying source disappearance and destination file")
	}
	if !strings.Contains(probeTemplate, `if mv -T "$d/mv-cap-nest-source" "$d/mv-cap-existing-dir"; then
		rename='p'
	fi
	[ -f "$d/mv-cap-nest-source" ] && [ -d "$d/mv-cap-existing-dir" ] && [ ! -e "$d/mv-cap-existing-dir/mv-cap-nest-source" ]`) {
		t.Fatal("probe does not reject mv -T when file-to-directory move succeeds or alters paths")
	}
}

func TestPublicationProbeChecksSelectedRenameAndPerlLinkSemantics(t *testing.T) {
	for _, want := range []string{
		`rename='t'`,
		`command -v perl >/dev/null || exit 20`,
		`rename_entry() {`,
		`link_entry() {`,
		`mkdir "$d/mv-dir-empty-source" "$d/mv-dir-empty-dest"`,
		`[ ! -e "$d/mv-dir-empty-source" ] && [ -f "$d/mv-dir-empty-dest/source" ]`,
		`mkdir "$d/mv-dir-source" "$d/mv-dir-dest"`,
		`[ -f "$d/mv-dir-dest/sentinel" ]`,
		`[ ! -e "$d/mv-file-dest/mv-file" ]`,
		`ln -s "$d/symlink-sentinel" "$d/symlink-dest"`,
		`[ ! -L "$d/symlink-dest" ]`,
		`if link_entry "$d/link-source" "$d/link-dir"; then`,
		`[ ! -e "$d/link-dir/link-source" ]`,
		`if link_entry "$d/link-symlink-source" "$d/link-symlink-dest"; then`,
		`[ -f "$d/link-symlink-source" ] && [ -L "$d/link-symlink-dest" ]`,
	} {
		if !strings.Contains(probeTemplate, want) {
			t.Errorf("probe template lacks functional check %q", want)
		}
	}
	if strings.Contains(perlRenameCommand, "$d") || strings.Contains(perlLinkCommand, "$d") {
		t.Fatal("Perl program literals contain probe paths")
	}
	probeCommand := fmt.Sprintf(probeTemplate, shellQuote("/.ssjack-probe-0123456789abcdef"))
	for _, want := range []string{
		`perl -e 'exit(rename($ARGV[0], $ARGV[1]) ? 0 : 1)' -- "$d/perl-cap-source" "$d/perl-cap-dest"`,
		`perl -e 'exit(link($ARGV[0], $ARGV[1]) ? 0 : 1)' -- "$1" "$2"`,
	} {
		if !strings.Contains(probeCommand, want) {
			t.Errorf("probe lacks fixed Perl source with argv paths %q", want)
		}
	}
}

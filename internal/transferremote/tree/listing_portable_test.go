package tree

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferremote/core"
	"github.com/PHPCraftdream/ssjack/internal/transferremote/fileops"
)

func TestPortableListingCommandsAndGNUBaselines(t *testing.T) {
	const root = "/srv/remote names/дерево целиком"
	const path = root + "/draft v2.bin"

	portableStat := fmt.Sprintf(fileops.StatFileTemplate, core.ShellQuote(path), core.StatHashCommand(core.HashShasum))
	if !strings.Contains(portableStat, `shasum -a 256 < "$path"`) || strings.Contains(portableStat, `shasum -a 256 "$path"`) {
		t.Errorf("portable stat must hash stdin rather than pass a filename:\n%s", portableStat)
	}
	if !strings.Contains(portableStat, `[ "$out" = "$hash  -" ]`) {
		t.Errorf("portable stat does not validate the canonical stdin marker:\n%s", portableStat)
	}

	portableHash := TreeHashTail(core.HashShasum)
	if !strings.Contains(portableHash, `shasum -a 256 < "$f"`) || strings.Contains(portableHash, `shasum -a 256 "$f"`) {
		t.Errorf("portable tree hash must use stdin rather than a filename operand: %s", portableHash)
	}
	if !strings.Contains(portableHash, `[ "$out" = "$hash  -" ]`) {
		t.Errorf("portable tree hash does not validate the canonical stdin marker: %s", portableHash)
	}

	portableSizes := fmt.Sprintf(TreePortableSizesTemplate, core.ShellQuote(root), core.ExitRefusedPath)
	if strings.Contains(portableSizes, "%!") {
		t.Errorf("portable size template contains fmt formatting damage:\n%s", portableSizes)
	}
	if !strings.Contains(portableSizes, `wc -c < "$f"`) || strings.Contains(portableSizes, `wc -c "$f"`) {
		t.Errorf("portable sizes must use wc stdin rather than a filename operand:\n%s", portableSizes)
	}
	if !strings.Contains(portableSizes, `printf "%s %s\n" "$size" "$f"`) {
		t.Errorf("portable sizes do not format the count and original path canonically:\n%s", portableSizes)
	}

	const gnuRoot = "/srv/tree"
	const gnuPath = "/srv/file.bin"
	gnuStat := fmt.Sprintf(fileops.StatFileTemplate, core.ShellQuote(gnuPath), core.StatHashCommand(core.HashSha256sum))
	wantStat := "set -eu\npath='/srv/file.bin'\nif [ -L \"$path\" ] || [ ! -f \"$path\" ]; then\n\texit 21\nfi\nwc -c < \"$path\"\nsha256sum \"$path\"\n"
	if gnuStat != wantStat {
		t.Errorf("GNU stat command changed:\n got: %q\nwant: %q", gnuStat, wantStat)
	}
	gnuTree := fmt.Sprintf(TreeFilesTemplate, core.ShellQuote(gnuRoot), core.ExitRefusedPath, TreeHashTail(core.HashSha256sum))
	wantTree := "set -eu\nroot='/srv/tree'\nif [ ! -d \"$root\" ] || [ -L \"$root\" ]; then\n\texit 21\nfi\nfind \"$root\" -type f -print0 | xargs -0 sha256sum\n"
	if gnuTree != wantTree {
		t.Errorf("GNU tree command changed:\n got: %q\nwant: %q", gnuTree, wantTree)
	}
	gnuSizes := fmt.Sprintf(TreeSizesTemplate, core.ShellQuote(gnuRoot), core.ExitRefusedPath)
	wantSizes := "set -eu\nroot='/srv/tree'\nif [ ! -d \"$root\" ] || [ -L \"$root\" ]; then\n\texit 21\nfi\nfind \"$root\" -type f -print0 | xargs -0 -n 1 wc -c\n"
	if gnuSizes != wantSizes {
		t.Errorf("GNU sizes command changed:\n got: %q\nwant: %q", gnuSizes, wantSizes)
	}
}

func TestPortableListingParsersPreservePathBytesAndRefuseUnsafeNames(t *testing.T) {
	const root = "/srv/remote names/дерево целиком"
	const relDir = "資料 dir"
	const relFile = "draft v2.bin"
	const fullDir = root + "/" + relDir
	const fullFile = root + "/" + relFile
	limits := sampleLimits()
	hash := sha256.Sum256([]byte("portable payload"))

	dirs, err := parseDirListing([]byte(root+"\x00"+fullDir+"\x00"), root, limits, transfercore.ClassRefusedPath)
	if err != nil || len(dirs) != 1 || dirs[0] != relDir {
		t.Fatalf("parseDirListing = (%q, %v), want exact relative UTF-8 path %q", dirs, err, relDir)
	}
	files, err := parseFileListing([]byte(hex.EncodeToString(hash[:])+"  "+fullFile+"\n"), root, limits, transfercore.ClassRefusedPath)
	if err != nil || len(files) != 1 || files[0].Path != relFile || files[0].SHA256 != hash {
		t.Fatalf("parseFileListing = (%+v, %v), want exact path %q and hash", files, err, relFile)
	}
	sizes, err := parseSizeListing([]byte("      17 "+fullFile+"\n"), root, limits, transfercore.ClassRefusedPath)
	if err != nil || len(sizes) != 1 || sizes[relFile] != 17 {
		t.Fatalf("parseSizeListing = (%v, %v), want BSD-padded count 17 for %q", sizes, err, relFile)
	}
	if _, err := parseSizeListing([]byte("17 /srv/remote names/?????? ???????/draft v2.bin\n"), root, limits, transfercore.ClassRefusedPath); err == nil {
		t.Errorf("parseSizeListing accepted mangled nonmatching UTF-8 path")
	}

	badDirNames := []string{"/srv/elsewhere/a", root + "/bad\\name", root + "/bad\x01name"}
	for _, name := range badDirNames {
		_, err := parseDirListing([]byte(name+"\x00"), root, limits, transfercore.ClassRefusedPath)
		if err == nil {
			t.Errorf("parseDirListing accepted unsafe/mismatched path %q", name)
		}
	}
	badFileNames := []string{"/srv/elsewhere/a", root + "/bad\\name", root + "/bad\x01name"}
	for _, name := range badFileNames {
		line := hex.EncodeToString(hash[:]) + "  " + name + "\n"
		_, err := parseFileListing([]byte(line), root, limits, transfercore.ClassRefusedPath)
		if err == nil {
			t.Errorf("parseFileListing accepted unsafe/mismatched path %q", name)
		}
	}
	badSizeNames := []string{"/srv/elsewhere/a", "/srv/remote names/?????? ???????/draft v2.bin", root + "/bad\\name", root + "/bad\x01name"}
	for _, name := range badSizeNames {
		_, err := parseSizeListing([]byte("17 "+name+"\n"), root, limits, transfercore.ClassRefusedPath)
		if err == nil {
			t.Errorf("parseSizeListing accepted unsafe/mismatched path %q", name)
		}
	}
}

func TestPreflightTreePortableListingsPreserveOriginalPaths(t *testing.T) {
	const root = "/srv/remote names/дерево целиком"
	const relDir = "資料 dir"
	const relFile = "draft v2.bin"
	const fullDir = root + "/" + relDir
	const fullFile = root + "/" + relFile
	payload := []byte("portable payload bytes")
	hash := sha256.Sum256(payload)
	dirsOut := root + "\x00" + fullDir + "\x00"
	hashesOut := hex.EncodeToString(hash[:]) + "  " + fullFile + "\n"
	// BSD wc commonly pads the count field for a single-file invocation.
	sizesOut := fmt.Sprintf("      %d %s\n", len(payload), fullFile)
	f := &fakeRunner{Respond: func(command string, _ io.Reader, stdout, _ io.Writer) (int, error) {
		switch {
		case strings.Contains(command, "read -r x"):
		case strings.Contains(command, "-type d -print0"):
			_, _ = io.WriteString(stdout, dirsOut)
		case strings.Contains(command, "-type f -print0") && strings.Contains(command, "shasum -a 256"):
			_, _ = io.WriteString(stdout, hashesOut)
		case strings.Contains(command, "wc -c < \"$f\""):
			_, _ = io.WriteString(stdout, sizesOut)
		default:
			t.Errorf("unexpected listing command: %s", command)
		}
		return 0, nil
	}}
	r := newRemoteFull(f.Run, "t", sampleLimits())
	r.SetCaps(core.Caps{Hash: core.HashShasum, MvT: true, TarGNU: true, WcNames: false})
	manifest, err := r.PreflightTree(context.Background(), root)
	if err != nil {
		t.Fatalf("PreflightTree = %v, want nil", err)
	}
	if len(manifest.Dirs) != 1 || manifest.Dirs[0] != relDir {
		t.Errorf("manifest dirs = %q, want exact path %q", manifest.Dirs, relDir)
	}
	if len(manifest.Files) != 1 {
		t.Fatalf("manifest files = %d entries, want 1", len(manifest.Files))
	}
	entry := manifest.Files[0]
	if entry.Path != relFile || entry.Size != int64(len(payload)) || entry.SHA256 != hash {
		t.Errorf("manifest entry = %+v, want path %q, size %d and hash %x", entry, relFile, len(payload), hash)
	}
}

func TestSHA256sumWithStdinWcPreservesUnicodeManifestPaths(t *testing.T) {
	const root = "/srv/remote names/дерево целиком"
	const path = root + "/draft v2.bin"
	payloadHash := sha256.Sum256([]byte("unicode file contents"))
	hashText := hex.EncodeToString(payloadHash[:])
	f := &fakeRunner{Respond: func(command string, _ io.Reader, stdout, _ io.Writer) (int, error) {
		switch {
		case strings.Contains(command, "SSJACK-CAPS"):
			_, _ = io.WriteString(stdout, "SSJACK-CAPS sha256sum p gnu stdin\n")
		case strings.Contains(command, "-type d -print0"):
			_, _ = io.WriteString(stdout, root+"\x00")
		case strings.Contains(command, "-type f -print0") && !strings.Contains(command, "wc -c"):
			_, _ = fmt.Fprintf(stdout, "%s  %s\n", hashText, path)
		case strings.Contains(command, "wc -c < \"$f\""):
			_, _ = fmt.Fprintf(stdout, "131072 %s\n", path)
		case strings.Contains(command, "wc -c"):
			_, _ = io.WriteString(stdout, "  131072 /srv/remote names/?????? ???????/draft v2.bin\n")
		}
		return 0, nil
	}}
	r := newRemoteFull(f.Run, "t", sampleLimits())
	if err := r.Probe(context.Background()); err != nil {
		t.Fatalf("Probe = %v", err)
	}
	manifest, err := r.PreflightTree(context.Background(), root)
	if err != nil {
		t.Fatalf("PreflightTree = %v", err)
	}
	if len(manifest.Files) != 1 || manifest.Files[0].Path != "draft v2.bin" || manifest.Files[0].Size != 131072 || manifest.Files[0].SHA256 != payloadHash {
		t.Fatalf("manifest = %+v, want exact Unicode path, size 131072 and digest %x", manifest, payloadHash)
	}
	for _, command := range f.Recorded() {
		if strings.Contains(command, "xargs -0 -n 1 wc -c") {
			t.Fatalf("stdin wc capability selected a direct filename wc command:\n%s", command)
		}
	}

	mangled := &fakeRunner{Respond: func(command string, _ io.Reader, stdout, _ io.Writer) (int, error) {
		switch {
		case strings.Contains(command, "SSJACK-CAPS"):
			_, _ = io.WriteString(stdout, "SSJACK-CAPS sha256sum p gnu names\n")
		case strings.Contains(command, "-type d -print0"):
			_, _ = io.WriteString(stdout, root+"\x00")
		case strings.Contains(command, "-type f -print0") && !strings.Contains(command, "wc -c"):
			_, _ = fmt.Fprintf(stdout, "%s  %s\n", hashText, path)
		case strings.Contains(command, "wc -c"):
			_, _ = io.WriteString(stdout, "  131072 /srv/remote names/?????? ???????/draft v2.bin\n")
		}
		return 0, nil
	}}
	rMangled := newRemoteFull(mangled.Run, "t", sampleLimits())
	if err := rMangled.Probe(context.Background()); err != nil {
		t.Fatalf("Probe(mangled wc filename) = %v", err)
	}
	_, err = rMangled.PreflightTree(context.Background(), root)
	testWantErr(t, err, transfercore.ClassRefusedPath, msgListingMalformed, -1)
}
func TestSizeAndPublicationCapabilitiesAreIndependentOfHash(t *testing.T) {
	const root = "/srv/remote names/дерево целиком"
	const path = root + "/draft v2.bin"
	payload := []byte("portable payload")
	hashBytes := sha256.Sum256(payload)
	hashText := hex.EncodeToString(hashBytes[:])
	dirsOut := root + "\x00"
	hashesOut := hashText + "  " + path + "\n"
	sizesOut := fmt.Sprintf("      %d %s\n", len(payload), path)

	for _, hash := range []string{core.HashSha256sum, core.HashShasum, core.HashSha256q} {
		for _, wc := range []string{"names", "stdin"} {
			for _, rename := range []string{"t", "p"} {
				hash, wc, rename := hash, wc, rename
				t.Run(hash+"/"+wc+"/"+rename, func(t *testing.T) {
					report := fmt.Sprintf("SSJACK-CAPS %s %s gnu %s\n", hash, rename, wc)
					f := &fakeRunner{Respond: func(command string, _ io.Reader, stdout, _ io.Writer) (int, error) {
						switch {
						case strings.Contains(command, "SSJACK-CAPS"):
							_, _ = io.WriteString(stdout, report)
						case strings.Contains(command, `wc -c < "$path"`):
							_, _ = fmt.Fprintf(stdout, "%d\n%s  %s\n", len(payload), hashText, path)
						case strings.Contains(command, "-type d -print0"):
							_, _ = io.WriteString(stdout, dirsOut)
						case strings.Contains(command, "wc -c"):
							_, _ = io.WriteString(stdout, sizesOut)
						case strings.Contains(command, "-type f -print0") && !strings.Contains(command, "wc -c"):
							_, _ = io.WriteString(stdout, hashesOut)
						}
						return 0, nil
					}}
					r := newRemoteFull(f.Run, "t", sampleLimits())
					if err := r.Probe(context.Background()); err != nil {
						t.Fatalf("Probe = %v", err)
					}
					if gotSize, gotHash, err := r.StatFile(context.Background(), path); err != nil || gotSize != int64(len(payload)) || gotHash != hashBytes {
						t.Fatalf("StatFile = (%d, %x, %v); want (%d, %x, nil)", gotSize, gotHash, err, len(payload), hashBytes)
					}
					manifest, err := r.PreflightTree(context.Background(), root)
					if err != nil {
						t.Fatalf("PreflightTree = %v", err)
					}
					if len(manifest.Files) != 1 || manifest.Files[0].Path != "draft v2.bin" || manifest.Files[0].Size != int64(len(payload)) || manifest.Files[0].SHA256 != hashBytes {
						t.Fatalf("manifest = %+v, want exact path, size and digest", manifest)
					}
					if err := r.PublishFile(context.Background(), "/srv/staging", "/srv/dest", false); err != nil {
						t.Fatal(err)
					}
					if err := r.PublishFile(context.Background(), "/srv/staging", "/srv/dest", true); err != nil {
						t.Fatal(err)
					}
					if err := r.PublishDir(context.Background(), "/srv/staging", "/srv/dest", false); err != nil {
						t.Fatal(err)
					}
					if err := r.PublishDir(context.Background(), "/srv/staging", "/srv/dest", true); err != nil {
						t.Fatal(err)
					}
					commands := f.Recorded()
					if len(commands) != 10 {
						t.Fatalf("recorded %d commands, want probe, stat, four preflight and four publication commands", len(commands))
					}
					if !strings.HasSuffix(commands[1], core.StatHashCommand(hash)+"\n") {
						t.Errorf("StatFile selected wrong independent hash command:\n%s", commands[1])
					}
					if !strings.HasSuffix(commands[4], TreeHashTail(hash)+"\n") {
						t.Errorf("tree listing selected wrong independent hash command:\n%s", commands[4])
					}
					var wantSizes string
					if wc == "names" {
						wantSizes = `set -eu
root='/srv/remote names/дерево целиком'
if [ ! -d "$root" ] || [ -L "$root" ]; then
	exit 21
fi
find "$root" -type f -print0 | xargs -0 -n 1 wc -c
`
					} else {
						wantSizes = `set -eu
root='/srv/remote names/дерево целиком'
if [ ! -d "$root" ] || [ -L "$root" ]; then
	exit 21
fi
find "$root" -type f -print0 | xargs -0 -n 1 sh -c '[ "$#" -gt 0 ] || exit 0; f="$1"; size=$(wc -c < "$f") || exit 24; printf "%s %s\n" "$size" "$f"' _
`
					}
					if commands[5] != wantSizes {
						t.Errorf("wc=%s size command differs:\n got: %q\nwant: %q", wc, commands[5], wantSizes)
					}
					for i, command := range commands[6:] {
						if rename == "t" && !strings.Contains(command, "mv -T") {
							t.Errorf("publication %d with rename=%s lacks mv -T: %s", i, rename, command)
						}
						if rename == "p" && !strings.Contains(command, core.PerlRenameCommand) {
							t.Errorf("publication %d with rename=%s lacks Perl rename: %s", i, rename, command)
						}
					}
				})
			}
		}
	}
}

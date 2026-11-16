package transferremote

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
)

func TestPortableListingCommandsAndGNUBaselines(t *testing.T) {
	const root = "/srv/remote names/дерево целиком"
	const path = root + "/draft v2.bin"

	portableStat := fmt.Sprintf(statFileTemplate, shellQuote(path), statHashCommand(hashShasum))
	if !strings.Contains(portableStat, `shasum -a 256 < "$path"`) || strings.Contains(portableStat, `shasum -a 256 "$path"`) {
		t.Errorf("portable stat must hash stdin rather than pass a filename:\n%s", portableStat)
	}
	if !strings.Contains(portableStat, `[ "$out" = "$hash  -" ]`) {
		t.Errorf("portable stat does not validate the canonical stdin marker:\n%s", portableStat)
	}

	portableHash := treeHashTail(hashShasum)
	if !strings.Contains(portableHash, `shasum -a 256 < "$f"`) || strings.Contains(portableHash, `shasum -a 256 "$f"`) {
		t.Errorf("portable tree hash must use stdin rather than a filename operand: %s", portableHash)
	}
	if !strings.Contains(portableHash, `[ "$out" = "$hash  -" ]`) {
		t.Errorf("portable tree hash does not validate the canonical stdin marker: %s", portableHash)
	}

	portableSizes := fmt.Sprintf(treePortableSizesTemplate, shellQuote(root), exitRefusedPath)
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
	gnuStat := fmt.Sprintf(statFileTemplate, shellQuote(gnuPath), statHashCommand(hashSha256sum))
	wantStat := "set -eu\npath='/srv/file.bin'\nif [ -L \"$path\" ] || [ ! -f \"$path\" ]; then\n\texit 21\nfi\nwc -c < \"$path\"\nsha256sum \"$path\"\n"
	if gnuStat != wantStat {
		t.Errorf("GNU stat command changed:\n got: %q\nwant: %q", gnuStat, wantStat)
	}
	gnuTree := fmt.Sprintf(treeFilesTemplate, shellQuote(gnuRoot), exitRefusedPath, treeHashTail(hashSha256sum))
	wantTree := "set -eu\nroot='/srv/tree'\nif [ ! -d \"$root\" ] || [ -L \"$root\" ]; then\n\texit 21\nfi\nfind \"$root\" -type f -print0 | xargs -0 sha256sum\n"
	if gnuTree != wantTree {
		t.Errorf("GNU tree command changed:\n got: %q\nwant: %q", gnuTree, wantTree)
	}
	gnuSizes := fmt.Sprintf(treeSizesTemplate, shellQuote(gnuRoot), exitRefusedPath)
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
	badSizeNames := []string{"/srv/elsewhere/a", root + "/bad\\name", root + "/bad\x01name"}
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
	f := &fakeRunner{respond: func(command string, _ io.Reader, stdout, _ io.Writer) (int, error) {
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
	r := New(f.run, "t", sampleLimits()).(*remoteRunner)
	r.caps.Store(&remoteCaps{hash: hashShasum, mvT: true, tarGNU: true})
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

func TestPortableSizeCommandIsSelectedForNonGNUHash(t *testing.T) {
	const root = "/srv/remote names/дерево целиком"
	f := &fakeRunner{respond: func(command string, _ io.Reader, stdout, _ io.Writer) (int, error) {
		if strings.Contains(command, "read -r x") || strings.Contains(command, "-type d -print0") || strings.Contains(command, "-type f -print0") || strings.Contains(command, "wc -c < \"$f\"") {
			return 0, nil
		}
		return 0, nil
	}}
	r := New(f.run, "t", sampleLimits()).(*remoteRunner)
	r.caps.Store(&remoteCaps{hash: hashShasum, mvT: true, tarGNU: true})
	if _, err := r.PreflightTree(context.Background(), root); err != nil {
		t.Fatalf("PreflightTree = %v, want nil", err)
	}
	commands := f.recorded()
	if len(commands) != 4 {
		t.Fatalf("recorded %d commands, want tree check plus three listings", len(commands))
	}
	last := commands[3]
	if strings.Contains(last, "%!") || !strings.Contains(last, `printf "%s %s\n" "$size" "$f"`) {
		t.Errorf("non-GNU size command is malformed:\n%s", last)
	}
}

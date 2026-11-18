package tree

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"
	"testing"

	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/transferremote/core"
)

func TestParseDirListing(t *testing.T) {
	const root = "/dest/root"
	limits := sampleLimits()

	dirs, err := parseDirListing([]byte(root+"\x00"+root+"/a\x00"+root+"/b b\x00"), root, limits, transfercore.ClassRefusedPath)
	if err != nil {
		t.Fatalf("parseDirListing = %v, want nil", err)
	}
	if len(dirs) != 2 || dirs[0] != "a" || dirs[1] != "b b" {
		t.Errorf("dirs = %v, want [a b b]", dirs)
	}

	dirs, err = parseDirListing(nil, root, limits, transfercore.ClassRefusedPath)
	if dirs != nil || err != nil {
		t.Errorf("empty data = (%v, %v), want (nil, nil)", dirs, err)
	}

	cases := []struct {
		name string
		data string
		bad  transfercore.Class
	}{
		{"missing trailing NUL", root + "\x00" + root + "/a", transfercore.ClassIntegrity},
		{"outside root", root + "\x00other/x\x00", transfercore.ClassRefusedPath},
		{"control char", root + "\x00" + root + "/a\x01b\x00", transfercore.ClassRefusedPath},
	}
	for _, c := range cases {
		_, err := parseDirListing([]byte(c.data), root, limits, c.bad)
		expectClass(t, err, c.bad)
	}

	dup := []byte(root + "\x00" + root + "/a\x00" + root + "/a\x00")
	_, err = parseDirListing(dup, root, limits, transfercore.ClassRefusedPath)
	testWantErr(t, err, transfercore.ClassRefusedPath, msgListingDuplicate, -1)

	small := sampleLimits()
	small.MaxEntries = 1
	_, err = parseDirListing([]byte(root+"\x00"+root+"/a\x00"+root+"/b\x00"), root, small, transfercore.ClassRefusedPath)
	testWantErr(t, err, transfercore.ClassLimit, msgTreeLimit, -1)

	dirs, err = parseDirListing([]byte(root+"\x00"+root+"/a\x00"), root, limits, transfercore.ClassRefusedPath)
	if err != nil || len(dirs) != 1 || dirs[0] != "a" {
		t.Errorf("bare root not skipped: dirs=%v err=%v", dirs, err)
	}
}

func TestParseFileListing(t *testing.T) {
	const root = "/dest/root"
	limits := sampleLimits()
	h1 := sha256.Sum256([]byte("one"))
	h2 := sha256.Sum256([]byte("two files"))
	line := func(h [32]byte, name string) string {
		return hex.EncodeToString(h[:]) + "  " + name
	}
	good := line(h1, root+"/f1") + "\n" + line(h2, root+"/dir with space/f 2") + "\n"

	entries, err := parseFileListing([]byte(good), root, limits, transfercore.ClassRefusedPath)
	if err != nil {
		t.Fatalf("parseFileListing = %v, want nil", err)
	}
	if len(entries) != 2 || entries[0].SHA256 != h1 || entries[1].Path != "dir with space/f 2" || entries[1].SHA256 != h2 {
		t.Errorf("entries = %+v, want decoded hashes for f1 and spaced name", entries)
	}

	entries, err = parseFileListing([]byte(line(h1, "-")+"\n"), root, limits, transfercore.ClassRefusedPath)
	if err != nil || len(entries) != 0 {
		t.Errorf("phantom `-` line = (%v, %v), want (0 entries, nil)", entries, err)
	}

	cases := []struct {
		name string
		data string
	}{
		{"backslash escape", "\\abc  x\n"},
		{"too short", "shortline\n"},
		{"bad hex", strings.Repeat("z", 64) + "  " + root + "/f\n"},
		{"single space separator", hex.EncodeToString(h1[:]) + " " + root + "/f\n"},
		{"outside root", line(h1, "/elsewhere/f") + "\n"},
		{"empty line", "\n"},
	}
	for _, c := range cases {
		_, err := parseFileListing([]byte(c.data), root, limits, transfercore.ClassIntegrity)
		expectClass(t, err, transfercore.ClassIntegrity)
	}

	_, err = parseFileListing([]byte(line(h1, root+"/a\tb")+"\n"), root, limits, transfercore.ClassIntegrity)
	expectClass(t, err, transfercore.ClassRefusedPath)

	_, err = parseFileListing([]byte(line(h1, root+"/f")+"\n"+line(h1, root+"/f")+"\n"), root, limits, transfercore.ClassRefusedPath)
	expectClass(t, err, transfercore.ClassRefusedPath)

	small := sampleLimits()
	small.MaxEntries = 1
	_, err = parseFileListing([]byte(good), root, small, transfercore.ClassRefusedPath)
	testWantErr(t, err, transfercore.ClassLimit, msgTreeLimit, -1)
}

func TestParseSizeListing(t *testing.T) {
	const root = "/dest/root"
	limits := sampleLimits()

	sizes, err := parseSizeListing([]byte("12 "+root+"/a\n      4096 "+root+"/b b\n"), root, limits, transfercore.ClassRefusedPath)
	if err != nil {
		t.Fatalf("parseSizeListing = %v, want nil", err)
	}
	if sizes["a"] != 12 || sizes["b b"] != 4096 || len(sizes) != 2 {
		t.Errorf("sizes = %v, want {a:12, b b:4096}", sizes)
	}

	sizes, err = parseSizeListing([]byte("0\n"), root, limits, transfercore.ClassRefusedPath)
	if err != nil || len(sizes) != 0 {
		t.Errorf("bare count line = (%v, %v), want (empty, nil)", sizes, err)
	}
	sizes, err = parseSizeListing([]byte("12\n12\n"), root, limits, transfercore.ClassRefusedPath)
	if err != nil || len(sizes) != 0 {
		t.Errorf("digits-only lines = (%v, %v), want (empty, nil)", sizes, err)
	}

	_, err = parseSizeListing([]byte("12 "+root+"/a\n12 "+root+"/a\n"), root, limits, transfercore.ClassRefusedPath)
	expectClass(t, err, transfercore.ClassRefusedPath)
	for _, data := range []string{"abc x\n", "12 /elsewhere/a\n", "-5 " + root + "/a\n"} {
		_, err := parseSizeListing([]byte(data), root, limits, transfercore.ClassRefusedPath)
		expectClass(t, err, transfercore.ClassRefusedPath)
	}
}

// testTreeStreams builds the dirs, sha256 and size listing streams for a fixture.
func testTreeStreams(root string, dirs []string, files map[string][]byte) (dirsS, shaS, sizesS string) {
	var d, s, z strings.Builder
	d.WriteString(root + "\x00")
	for _, rel := range dirs {
		d.WriteString(root + "/" + rel + "\x00")
	}
	rels := make([]string, 0, len(files))
	for rel := range files {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	for _, rel := range rels {
		h := sha256.Sum256(files[rel])
		full := root + "/" + rel
		s.WriteString(hex.EncodeToString(h[:]) + "  " + full + "\n")
		z.WriteString(fmt.Sprintf("%d %s\n", len(files[rel]), full))
	}
	return d.String(), s.String(), z.String()
}

// testStreamResponder dispatches on command content like a scripted remote.
func testStreamResponder(dirsOut, shaOut, sizesOut string, checkCode int) func(string, io.Reader, io.Writer, io.Writer) (int, error) {
	return func(command string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
		switch {
		case strings.Contains(command, "read -r x"):
			if checkCode != 0 {
				return checkCode, nil
			}
		case strings.Contains(command, "-type d -print0"):
			fmt.Fprint(stdout, dirsOut)
		case strings.Contains(command, "xargs -0 sha256sum"):
			fmt.Fprint(stdout, shaOut)
		case strings.Contains(command, "wc -c"):
			fmt.Fprint(stdout, sizesOut)
		}
		return 0, nil
	}
}

func TestPreflightTreeFake(t *testing.T) {
	const root = "/srv/tree"
	dirs := []string{"sub", "sub/deep"}
	files := map[string][]byte{
		"a":          []byte("payload one"),
		"sub/b":      []byte("second file data"),
		"sub/deep/c": []byte("c!"),
	}
	dirsS, shaS, sizesS := testTreeStreams(root, dirs, files)

	f := &fakeRunner{Respond: testStreamResponder(dirsS, shaS, sizesS, 0)}
	m, err := newRemote(f.Run, "t", sampleLimits()).PreflightTree(context.Background(), root)
	if err != nil {
		t.Fatalf("PreflightTree = %v, want nil", err)
	}
	if len(m.Dirs) != 2 || m.Dirs[0] != "sub" || m.Dirs[1] != "sub/deep" {
		t.Errorf("dirs = %v, want [sub sub/deep]", m.Dirs)
	}
	if len(m.Files) != 3 {
		t.Fatalf("files = %d entries, want 3", len(m.Files))
	}
	for _, e := range m.Files {
		want := sha256.Sum256(files[e.Path])
		if e.SHA256 != want || e.Size != int64(len(files[e.Path])) {
			t.Errorf("entry %s: size %d hash %x, want size %d hash %x", e.Path, e.Size, e.SHA256, len(files[e.Path]), want)
		}
	}

	// Size missing for one file (the wc -c line names an unknown path instead).
	fMissing := &fakeRunner{Respond: testStreamResponder(dirsS, shaS, "7 "+root+"/ghost\n", 0)}
	_, err = newRemote(fMissing.Run, "t", sampleLimits()).PreflightTree(context.Background(), root)
	expectClass(t, err, transfercore.ClassRefusedPath)

	// Extra size entry for an unknown file.
	fExtra := &fakeRunner{Respond: testStreamResponder(dirsS, shaS, sizesS+"7 "+root+"/ghost\n", 0)}
	_, err = newRemote(fExtra.Run, "t", sampleLimits()).PreflightTree(context.Background(), root)
	expectClass(t, err, transfercore.ClassRefusedPath)

	// Non-regular check refuses with exit 21.
	fCheck := &fakeRunner{Respond: testStreamResponder("", "", "", 21)}
	_, err = newRemote(fCheck.Run, "t", sampleLimits()).PreflightTree(context.Background(), root)
	testWantErr(t, err, transfercore.ClassRefusedPath, core.MsgRefused, 21)

	// Over-limit tree.
	small := sampleLimits()
	small.MaxEntries = 1
	_, err = newRemote(f.Run, "t", small).PreflightTree(context.Background(), root)
	expectClass(t, err, transfercore.ClassLimit)
}

func TestVerifyTreeFake(t *testing.T) {
	const root = "/srv/tree"
	dirs := []string{"sub"}
	files := map[string][]byte{"a": []byte("payload"), "sub/b": []byte("bee")}
	dirsS, shaS, _ := testTreeStreams(root, dirs, files)
	m := transfercore.Manifest{Dirs: dirs}
	for rel, data := range files {
		h := sha256.Sum256(data)
		m.Files = append(m.Files, transfercore.Entry{Path: rel, Size: int64(len(data)), SHA256: h})
	}
	m.Normalize()

	ok := &fakeRunner{Respond: testStreamResponder(dirsS, shaS, "", 0)}
	if err := newRemote(ok.Run, "t", sampleLimits()).VerifyTree(context.Background(), root, m); err != nil {
		t.Fatalf("VerifyTree = %v, want nil", err)
	}

	flip := "b" + shaS[1:] // flip one hash byte of the first sha line
	if shaS[0] == 'b' {
		flip = "c" + shaS[1:]
	}
	lines := strings.SplitN(shaS, "\n", 2)
	extraDirs := strings.Replace(dirsS, root+"\x00", root+"\x00"+root+"/ghost\x00", 1)
	cases := []struct {
		name string
		dirs string
		sha  string
		code int
	}{
		{"flipped hash", dirsS, flip, 0},
		{"extra file line", dirsS, shaS + shaS, 0},
		{"missing file line", dirsS, lines[1], 0},
		{"extra dir", extraDirs, shaS, 0},
		{"non-regular exit 23", dirsS, shaS, 23},
		{"malformed sha line", dirsS, "zz  \n", 0},
	}
	for _, c := range cases {
		f := &fakeRunner{Respond: testStreamResponder(c.dirs, c.sha, "", c.code)}
		err := newRemote(f.Run, "t", sampleLimits()).VerifyTree(context.Background(), root, m)
		if err == nil {
			t.Errorf("%s: VerifyTree = nil, want integrity error", c.name)
			continue
		}
		if c.code == 23 {
			testWantErr(t, err, transfercore.ClassIntegrity, core.MsgIntegrity, 23)
		} else {
			expectClass(t, err, transfercore.ClassIntegrity)
		}
	}
}

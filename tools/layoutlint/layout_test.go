package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"reflect"
	"strings"
	"testing"
	"testing/iotest"
)

func TestCountLines(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want int
	}{
		{"empty", "", 0},
		{"single newline", "\n", 1},
		{"no final newline", "a", 1},
		{"one terminated line", "a\n", 1},
		{"two lines no final newline", "a\nb", 2},
		{"two terminated lines", "a\nb\n", 2},
		{"blank lines", "\n\n", 2},
		{"crlf", "a\r\nb\r\n", 2},
		{"crlf no final newline", "a\r\nb", 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CountLines(strings.NewReader(tc.in))
			if err != nil || got != tc.want {
				t.Fatalf("CountLines(%q) = %d, %v; want %d", tc.in, got, err, tc.want)
			}
		})
	}
}

func TestCountLinesAcrossBuffers(t *testing.T) {
	big := strings.Repeat("x\n", 100000)
	cases := []struct {
		name string
		r    io.Reader
		want int
	}{
		{"plain", strings.NewReader(big), 100000},
		{"one byte reads", iotest.OneByteReader(strings.NewReader(big[:1000])), 500},
		{"data with eof", iotest.DataErrReader(strings.NewReader(big)), 100000},
		{"unterminated tail", strings.NewReader(big + "tail"), 100001},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CountLines(tc.r)
			if err != nil || got != tc.want {
				t.Fatalf("got %d, %v; want %d", got, err, tc.want)
			}
		})
	}
}

func TestCountLinesReadError(t *testing.T) {
	boom := errors.New("boom")
	if _, err := CountLines(iotest.ErrReader(boom)); !errors.Is(err, boom) {
		t.Fatalf("err = %v; want boom", err)
	}
}

func TestIsCode(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"a.go", true}, {"a_test.go", true}, {"pkg/test_a.py", true}, {"a.ps1", true},
		{"a.sh", true}, {"a.ts", true}, {"a.mts", true}, {"a.cts", true}, {"a.tsx", true},
		{"a.js", true}, {"a.mjs", true}, {"a.cjs", true}, {"a.jsx", true}, {"a.rs", true},
		{"a.GO", true}, {"dir/.eslintrc.js", true},
		{"README.md", false}, {"a.json", false}, {"a.yml", false}, {"a.yaml", false},
		{"a.txt", false}, {"a.go.txt", false}, {"Makefile", false}, {"go", false},
		{"a.c", false}, {"a.html", false}, {"dir.go/file.txt", false},
		{"node_modules/x.js", false}, {"a/node_modules/b/c.js", false},
		{"dist/x.js", false}, {"web/dist/x.ts", false},
		{"vendor/a.go", false}, {"a/vendor/b/c.go", false},
		{"x/golden/a.go", false}, {"golden/a.go", false},
		{"testdata/a.go", false}, {"internal/x/testdata/deep/a.go", false},
		{"fixtures/a.go", true}, {"a/fixtures/b.go", true},
		{"distribution/a.go", true}, {"a/dist.go", true}, {"x/testdata.go", true},
	}
	cfg := DefaultConfig()
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			if got := cfg.IsCode(tc.path); got != tc.want {
				t.Fatalf("IsCode(%q) = %v; want %v", tc.path, got, tc.want)
			}
		})
	}
}

func counts(m map[string]int) LineCounter {
	return func(p string) (int, error) { return m[p], nil }
}

func numbered(dir, ext string, n int) []string {
	var out []string
	for i := 0; i < n; i++ {
		out = append(out, path.Join(dir, fmt.Sprintf("f%d.%s", i, ext)))
	}
	return out
}

func concat(parts ...[]string) []string {
	var out []string
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func TestCheckFileLimit(t *testing.T) {
	cases := []struct {
		name  string
		lines int
		bad   bool
	}{
		{"zero lines", 0, false},
		{"one line", 1, false},
		{"999 lines", 999, false},
		{"1000 lines", 1000, false},
		{"1001 lines", 1001, true},
		{"5000 lines", 5000, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep, err := Check(DefaultConfig(), []string{"d/a.go"}, counts(map[string]int{"d/a.go": tc.lines}))
			if err != nil {
				t.Fatal(err)
			}
			if tc.bad != (len(rep.Violations) == 1) {
				t.Fatalf("violations = %v", rep.Violations)
			}
			if tc.bad {
				want := fmt.Sprintf("d/a.go: %d lines (limit 1000)", tc.lines)
				if got := rep.Violations[0].String(); got != want {
					t.Fatalf("got %q; want %q", got, want)
				}
			}
		})
	}
}

func TestCheckFolderLimit(t *testing.T) {
	cases := []struct {
		name  string
		paths []string
		want  []string
	}{
		{"seven files ok", numbered("d", "go", 7), nil},
		{"eight files over", numbered("d", "go", 8), []string{"d: 8 code files (limit 7)"}},
		{"tests count as code",
			concat(numbered("d", "go", 4), []string{"d/a_test.go", "d/b_test.go", "d/c_test.go", "d/d_test.go"}),
			[]string{"d: 8 code files (limit 7)"}},
		{"python tests count as code",
			concat(numbered("d", "py", 7), []string{"d/test_x.py"}),
			[]string{"d: 8 code files (limit 7)"}},
		{"subfolders do not count", concat(numbered("d", "go", 7), numbered("d/sub", "go", 7)), nil},
		{"parent and child split", concat(numbered("d", "go", 4), numbered("d/sub", "go", 4)), nil},
		{"non code not counted",
			concat(numbered("d", "go", 7), numbered("d", "md", 10), numbered("d", "json", 5)), nil},
		{"excluded dirs not counted",
			concat(numbered("d", "go", 7), numbered("d/testdata", "go", 20), numbered("d/vendor", "go", 20)), nil},
		{"excluded dir never reported", numbered("node_modules", "js", 30), nil},
		{"fixtures are checked", numbered("a/fixtures", "go", 8), []string{"a/fixtures: 8 code files (limit 7)"}},
		{"root folder", numbered("", "go", 8), []string{".: 8 code files (limit 7)"}},
		{"duplicate paths counted once", concat(numbered("d", "go", 7), []string{"d/f0.go", "d/f1.go"}), nil},
		{"two crowded folders sorted", concat(numbered("z", "go", 8), numbered("a", "ts", 9)),
			[]string{"a: 9 code files (limit 7)", "z: 8 code files (limit 7)"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep, err := Check(DefaultConfig(), tc.paths, counts(nil))
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, v := range rep.Violations {
				got = append(got, v.String())
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %q; want %q", got, tc.want)
			}
		})
	}
}

func TestCheckSkippedPathsAreNotCounted(t *testing.T) {
	count := func(p string) (int, error) {
		if p == "d/f3.go" {
			return 0, ErrSkip
		}
		return 1, nil
	}
	rep, err := Check(DefaultConfig(), numbered("d", "go", 8), count)
	if err != nil || len(rep.Violations) != 0 || rep.CodeFiles != 7 {
		t.Fatalf("rep = %+v, err = %v", rep, err)
	}
}

func TestCheckCountsOnlyCodeFiles(t *testing.T) {
	paths := []string{"a.go", "b.md", "testdata/c.go", "d/e.json"}
	rep, err := Check(DefaultConfig(), paths, counts(nil))
	if err != nil || rep.CodeFiles != 1 {
		t.Fatalf("rep = %+v, err = %v", rep, err)
	}
}

func TestCheckCounterErrorIsFatal(t *testing.T) {
	boom := errors.New("boom")
	_, err := Check(DefaultConfig(), []string{"a.go"}, func(string) (int, error) { return 0, boom })
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v; want boom", err)
	}
}

func TestCheckDeterministicOrder(t *testing.T) {
	paths := concat(numbered("m", "go", 8), numbered("b", "py", 8), []string{"m/big.go", "a.go", "z/huge.ts"})
	lines := map[string]int{"m/big.go": 2000, "z/huge.ts": 1001, "a.go": 1001}
	want, err := Check(DefaultConfig(), paths, counts(lines))
	if err != nil {
		t.Fatal(err)
	}
	wantText := []string{
		"a.go: 1001 lines (limit 1000)",
		"b: 8 code files (limit 7)",
		"m: 9 code files (limit 7)",
		"m/big.go: 2000 lines (limit 1000)",
		"z/huge.ts: 1001 lines (limit 1000)",
	}
	var got []string
	for _, v := range want.Violations {
		got = append(got, v.String())
	}
	if !reflect.DeepEqual(got, wantText) {
		t.Fatalf("got %q; want %q", got, wantText)
	}
	for shift := 1; shift < len(paths); shift++ {
		rotated := concat(paths[shift:], paths[:shift])
		again, err := Check(DefaultConfig(), rotated, counts(lines))
		if err != nil || !reflect.DeepEqual(again, want) {
			t.Fatalf("shift %d: %+v, %v", shift, again, err)
		}
	}
}

func TestFormat(t *testing.T) {
	cases := []struct {
		name string
		rep  Report
		want string
	}{
		{"clean", Report{CodeFiles: 3},
			"layoutlint: 0 violations (0 oversized files, 0 crowded folders) in 3 code files\n"},
		{"mixed", Report{CodeFiles: 20, Violations: []Violation{
			{"a.go", FileTooLong, 1001, 1000}, {"d", FolderTooCrowded, 8, 7}}},
			"a.go: 1001 lines (limit 1000)\nd: 8 code files (limit 7)\n" +
				"layoutlint: 2 violations (1 oversized files, 1 crowded folders) in 20 code files\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Format(tc.rep); got != tc.want {
				t.Fatalf("got %q; want %q", got, tc.want)
			}
		})
	}
}

// The linter must obey its own rules.
func TestOwnLayout(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, e := range entries {
		paths = append(paths, "tools/layoutlint/"+e.Name())
	}
	count := func(p string) (int, error) {
		f, err := os.Open(path.Base(p))
		if err != nil {
			return 0, err
		}
		defer f.Close()
		return CountLines(f)
	}
	rep, err := Check(DefaultConfig(), paths, count)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Violations) != 0 {
		t.Fatalf("own layout violations: %v", rep.Violations)
	}
}

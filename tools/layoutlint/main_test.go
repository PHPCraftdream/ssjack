package main

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type fakeSource struct {
	files    []string
	lines    map[string]int
	filesErr error
	linesErr error
}

func (f fakeSource) Files() ([]string, error) { return f.files, f.filesErr }

func (f fakeSource) Lines(p string) (int, error) {
	if f.linesErr != nil {
		return 0, f.linesErr
	}
	return f.lines[p], nil
}

func dirtySource() fakeSource {
	return fakeSource{
		files: []string{"a.go", "README.md", "d/x.go"},
		lines: map[string]int{"a.go": 1001, "d/x.go": 10},
	}
}

func cleanSource() fakeSource {
	return fakeSource{files: []string{"a.go"}, lines: map[string]int{"a.go": 1000}}
}

func TestRunExitCodes(t *testing.T) {
	boom := errors.New("boom")
	cases := []struct {
		name string
		args []string
		src  fakeSource
		want int
	}{
		{"report with violations", []string{"-report"}, dirtySource(), 0},
		{"report clean", []string{"-report"}, cleanSource(), 0},
		{"strict with violations", []string{"-strict"}, dirtySource(), 1},
		{"strict clean", []string{"-strict"}, cleanSource(), 0},
		{"no mode", nil, cleanSource(), 2},
		{"both modes", []string{"-report", "-strict"}, cleanSource(), 2},
		{"unknown flag", []string{"-nope"}, cleanSource(), 2},
		{"positional argument", []string{"-report", "extra"}, cleanSource(), 2},
		{"report list error", []string{"-report"}, fakeSource{filesErr: boom}, 2},
		{"strict list error", []string{"-strict"}, fakeSource{filesErr: boom}, 2},
		{"report read error", []string{"-report"}, fakeSource{files: []string{"a.go"}, linesErr: boom}, 2},
		{"strict read error", []string{"-strict"}, fakeSource{files: []string{"a.go"}, linesErr: boom}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if got := run(tc.args, &out, &errOut, tc.src); got != tc.want {
				t.Fatalf("exit = %d; want %d (stdout %q, stderr %q)", got, tc.want, out.String(), errOut.String())
			}
			if tc.want == 2 && out.Len() != 0 {
				t.Fatalf("stdout on error: %q", out.String())
			}
		})
	}
}

func TestRunOutput(t *testing.T) {
	for _, mode := range []string{"-report", "-strict"} {
		t.Run(strings.TrimPrefix(mode, "-"), func(t *testing.T) {
			var out, errOut bytes.Buffer
			run([]string{mode}, &out, &errOut, dirtySource())
			want := "a.go: 1001 lines (limit 1000)\n" +
				"layoutlint: 1 violations (1 oversized files, 0 crowded folders) in 2 code files\n"
			if out.String() != want || errOut.Len() != 0 {
				t.Fatalf("stdout %q, stderr %q", out.String(), errOut.String())
			}
			if strings.Contains(out.String(), "\x1b") {
				t.Fatal("color escape in output")
			}
		})
	}
}

func TestParseLsFiles(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"two paths", "a.go\x00b/c.go\x00", []string{"a.go", "b/c.go"}},
		{"no trailing nul", "a.go", []string{"a.go"}},
		{"spaces and unicode", "a b.go\x00é.py\x00", []string{"a b.go", "é.py"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseLsFiles([]byte(tc.in)); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %q; want %q", got, tc.want)
			}
		})
	}
}

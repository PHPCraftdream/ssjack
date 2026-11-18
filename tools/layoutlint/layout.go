package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
)

// ErrSkip is returned by a LineCounter for a path that must not be checked
// (deleted from the working copy, or not a regular file).
var ErrSkip = errors.New("skip path")

// LineCounter returns the physical line count of a slash-separated repo path.
type LineCounter func(path string) (int, error)

// Kind is the violated rule.
type Kind int

const (
	// FileTooLong is a code file over the line limit.
	FileTooLong Kind = iota
	// FolderTooCrowded is a folder with too many direct code files.
	FolderTooCrowded
)

// Violation is one broken rule.
type Violation struct {
	Path  string
	Kind  Kind
	Count int
	Limit int
}

// String renders the violation as one report line.
func (v Violation) String() string {
	if v.Kind == FileTooLong {
		return fmt.Sprintf("%s: %d lines (limit %d)", v.Path, v.Count, v.Limit)
	}
	return fmt.Sprintf("%s: %d code files (limit %d)", v.Path, v.Count, v.Limit)
}

// Report is the outcome of Check.
type Report struct {
	Violations []Violation
	CodeFiles  int
}

// IsCode reports whether a slash-separated path is checked code.
func (c Config) IsCode(p string) bool {
	if !c.CodeExtensions[strings.ToLower(strings.TrimPrefix(path.Ext(p), "."))] {
		return false
	}
	dir := path.Dir(p)
	if dir == "." {
		return true
	}
	for _, segment := range strings.Split(dir, "/") {
		if c.ExcludedDirs[segment] {
			return false
		}
	}
	return true
}

// CountLines counts physical lines like wc -l, plus an unterminated last line.
func CountLines(r io.Reader) (int, error) {
	buf := make([]byte, 64*1024)
	lines := 0
	var last byte = '\n'
	for {
		n, err := r.Read(buf)
		if n > 0 {
			lines += bytes.Count(buf[:n], []byte{'\n'})
			last = buf[n-1]
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}
	}
	if last != '\n' {
		lines++
	}
	return lines, nil
}

// Check applies the rules to tracked paths. Output order is deterministic.
func Check(cfg Config, paths []string, count LineCounter) (Report, error) {
	seen := make(map[string]bool, len(paths))
	var code []string
	for _, p := range paths {
		if !seen[p] && cfg.IsCode(p) {
			code = append(code, p)
		}
		seen[p] = true
	}
	sort.Strings(code)

	var rep Report
	perDir := map[string]int{}
	for _, p := range code {
		n, err := count(p)
		if errors.Is(err, ErrSkip) {
			continue
		}
		if err != nil {
			return Report{}, fmt.Errorf("%s: %w", p, err)
		}
		rep.CodeFiles++
		perDir[path.Dir(p)]++
		if n > cfg.MaxFileLines {
			rep.Violations = append(rep.Violations, Violation{p, FileTooLong, n, cfg.MaxFileLines})
		}
	}
	for dir, n := range perDir {
		if n > cfg.MaxFilesPerDir {
			rep.Violations = append(rep.Violations, Violation{dir, FolderTooCrowded, n, cfg.MaxFilesPerDir})
		}
	}
	sort.Slice(rep.Violations, func(i, j int) bool {
		a, b := rep.Violations[i], rep.Violations[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Kind < b.Kind
	})
	return rep, nil
}

// Format renders one line per violation, then the summary line.
func Format(rep Report) string {
	var b strings.Builder
	var files, folders int
	for _, v := range rep.Violations {
		b.WriteString(v.String())
		b.WriteByte('\n')
		if v.Kind == FileTooLong {
			files++
		} else {
			folders++
		}
	}
	fmt.Fprintf(&b, "layoutlint: %d violations (%d oversized files, %d crowded folders) in %d code files\n",
		len(rep.Violations), files, folders, rep.CodeFiles)
	return b.String()
}

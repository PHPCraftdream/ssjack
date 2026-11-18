// Command layoutlint checks the code layout rules in docs/LAYOUT.md.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Exit codes.
const (
	exitOK        = 0
	exitViolation = 1
	exitError     = 2
)

// source supplies tracked paths and their line counts.
type source interface {
	Files() ([]string, error)
	Lines(path string) (int, error)
}

func main() {
	src, err := newGitSource()
	if err != nil {
		fmt.Fprintln(os.Stderr, "layoutlint:", err)
		os.Exit(exitError)
	}
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, src))
}

func run(args []string, stdout, stderr io.Writer, src source) int {
	flags := flag.NewFlagSet("layoutlint", flag.ContinueOnError)
	flags.SetOutput(stderr)
	report := flags.Bool("report", false, "print all violations and exit 0")
	strict := flags.Bool("strict", false, "print all violations and exit 1 if any")
	if err := flags.Parse(args); err != nil {
		return exitError
	}
	if flags.NArg() != 0 || *report == *strict {
		fmt.Fprintln(stderr, "layoutlint: exactly one of -report or -strict is required")
		return exitError
	}
	paths, err := src.Files()
	if err != nil {
		fmt.Fprintln(stderr, "layoutlint:", err)
		return exitError
	}
	rep, err := Check(DefaultConfig(), paths, src.Lines)
	if err != nil {
		fmt.Fprintln(stderr, "layoutlint:", err)
		return exitError
	}
	if _, err := io.WriteString(stdout, Format(rep)); err != nil {
		fmt.Fprintln(stderr, "layoutlint:", err)
		return exitError
	}
	if *strict && len(rep.Violations) > 0 {
		return exitViolation
	}
	return exitOK
}

// gitSource reads tracked files of the repository containing the cwd.
type gitSource struct{ top string }

func newGitSource() (gitSource, error) {
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return gitSource{}, fmt.Errorf("git rev-parse: %w", err)
	}
	return gitSource{top: strings.TrimSpace(string(out))}, nil
}

func (g gitSource) Files() ([]string, error) {
	out, err := exec.Command("git", "-C", g.top, "ls-files", "-z").Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %w", err)
	}
	return parseLsFiles(out), nil
}

// parseLsFiles splits NUL-terminated git ls-files -z output.
func parseLsFiles(out []byte) []string {
	var paths []string
	for _, p := range bytes.Split(out, []byte{0}) {
		if len(p) > 0 {
			paths = append(paths, string(p))
		}
	}
	return paths
}

func (g gitSource) Lines(p string) (int, error) {
	full := filepath.Join(g.top, filepath.FromSlash(p))
	info, err := os.Stat(full)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, ErrSkip
	}
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() {
		return 0, ErrSkip
	}
	f, err := os.Open(full)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return CountLines(f)
}

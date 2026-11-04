package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func sourceBuildCommand(t *testing.T, root string, args ...string) *exec.Cmd {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	if runtime.GOOS == "windows" {
		return exec.CommandContext(ctx, "powershell.exe", append([]string{"-NoProfile", "-NonInteractive", "-File", filepath.Join(root, "build.ps1")}, args...)...)
	}
	return exec.CommandContext(ctx, "sh", append([]string{filepath.Join(root, "build.sh")}, args...)...)
}

func TestSourceBuildHelpAndInvalidOptionsHaveNoInstallationEffects(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	help, invalid := []string{"--help"}, []string{"--install-dir", "relative-path"}
	if runtime.GOOS == "windows" {
		help, invalid = []string{"-Help"}, []string{"-InstallDir", "relative-path"}
	}
	cwd := t.TempDir()
	for _, tc := range []struct {
		args []string
		ok   bool
		want string
	}{{help, true, "Usage:"}, {invalid, false, "absolute"}} {
		command := sourceBuildCommand(t, root, tc.args...)
		command.Dir = cwd
		output, err := command.CombinedOutput()
		if (err == nil) != tc.ok || !strings.Contains(string(output), tc.want) {
			t.Fatalf("source build help/options: %v: %s", err, output)
		}
	}
	entries, err := os.ReadDir(cwd)
	if err != nil || len(entries) != 0 {
		t.Fatal("informational or invalid build invocation created files")
	}
}

func TestSourceBuildFailureNeverStartsInstaller(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	tools, installed := filepath.Join(base, "tools"), filepath.Join(base, "installed")
	for _, dir := range []string{tools, installed} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	goName, binaryName, fakeGo := "go", "ssjack", "#!/bin/sh\nexit 17\n"
	args := []string{"--install-dir", installed}
	if runtime.GOOS == "windows" {
		goName, binaryName, fakeGo = "go.cmd", "ssjack.exe", "@exit /b 17\r\n"
		args = []string{"-InstallDir", installed, "-NoPathUpdate"}
	}
	if err := os.WriteFile(filepath.Join(tools, goName), []byte(fakeGo), 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(installed, binaryName)
	previous := []byte("synthetic previous executable; must not be probed or replaced")
	if err := os.WriteFile(target, previous, 0600); err != nil {
		t.Fatal(err)
	}
	command := sourceBuildCommand(t, root, args...)
	command.Dir = base
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if !strings.EqualFold(name, "PATH") {
			command.Env = append(command.Env, entry)
		}
	}
	command.Env = append(command.Env, "PATH="+tools+string(os.PathListSeparator)+os.Getenv("PATH"))
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "Build failed") {
		t.Fatalf("failing toolchain did not stop source install: %v: %s", err, output)
	}
	after, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(previous, after) {
		t.Fatal("failed build changed the previous executable")
	}
	entries, err := os.ReadDir(installed)
	if err != nil || len(entries) != 1 || entries[0].Name() != binaryName {
		t.Fatal("failed build started installer staging or replacement")
	}
}

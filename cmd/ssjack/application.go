package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/PHPCraftdream/ssjack/internal/application"
	"github.com/PHPCraftdream/ssjack/internal/remote"
)

func registeredClawwright(directory, entry, container, user, profile string, runner remote.StreamRunner) (*application.Options, error) {
	if directory == "" {
		if entry != "" || container != "" || user != "" {
			return nil, errors.New("Clawwright entry and Incus route require --clawwright-directory")
		}
		return nil, nil
	}
	if err := application.ValidateRoute(container, user); err != nil {
		return nil, err
	}
	root, err := filepath.Abs(directory)
	if err != nil {
		return nil, errors.New("invalid Clawwright directory")
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, errors.New("Clawwright directory is unavailable")
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return nil, errors.New("Clawwright deployment requires a directory")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		return nil, errors.New("native Node.js executable was not found on PATH")
	}
	node, err = filepath.Abs(node)
	if err != nil {
		return nil, errors.New("native Node.js executable path is invalid")
	}
	if runtime.GOOS == "windows" && !strings.EqualFold(filepath.Ext(node), ".exe") {
		return nil, errors.New("Clawwright requires native node.exe, not a command shim")
	}
	if entry == "" {
		installed, err := exec.LookPath("clawwright")
		if err != nil {
			return nil, errors.New("Clawwright was not found on PATH; use --clawwright-entry")
		}
		entry, err = installedClawwrightEntry(installed)
		if err != nil {
			return nil, err
		}
	} else if !filepath.IsAbs(entry) {
		entry = filepath.Join(root, entry)
	}
	entry, err = filepath.Abs(entry)
	if err != nil {
		return nil, errors.New("Clawwright entry path is invalid")
	}
	entry, err = filepath.EvalSymlinks(entry)
	if err != nil {
		return nil, errors.New("Clawwright entry is unavailable")
	}
	info, err = os.Stat(entry)
	if err != nil || !info.Mode().IsRegular() || !strings.EqualFold(filepath.Ext(entry), ".js") {
		return nil, errors.New("Clawwright entry must be a regular JavaScript file")
	}
	if err := validateClawwrightPackage(entry); err != nil {
		return nil, err
	}
	return &application.Options{
		Directory: root,
		Command:   []string{node, entry},
		Profile:   profile,
		Runner:    runner,
		Container: container,
		User:      user,
	}, nil
}

func installedClawwrightEntry(executable string) (string, error) {
	if runtime.GOOS == "windows" {
		return filepath.Join(filepath.Dir(executable), "node_modules", "@phpcraftdream", "clawwright", "dist", "entry", "bin.js"), nil
	}
	entry, err := filepath.EvalSymlinks(executable)
	if err != nil || filepath.Base(entry) != "bin.js" {
		return "", errors.New("unsupported Clawwright launcher; use --clawwright-entry for its checked JavaScript entry")
	}
	return entry, nil
}

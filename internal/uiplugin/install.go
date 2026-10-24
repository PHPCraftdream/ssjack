package uiplugin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	ssjackui "storagehost/plugins/ssjack-ui"
)

const EnvDirectories = "CLAUDE_CODE_PLUGIN_DIRS"

var assetNames = []string{
	".claude-plugin/plugin.json",
	"hooks/hooks.json",
	"hooks/register.tsx",
	"hooks/format.ts",
}

// Install publishes an immutable runtime copy inside this project.
func Install(root string) (string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	parent := root
	for _, name := range []string{".claude", "ssjack-ui"} {
		parent = filepath.Join(parent, name)
		if err := ensureDirectory(parent); err != nil {
			return "", err
		}
	}
	assets := make(map[string][]byte, len(assetNames))
	hash := sha256.New()
	for _, name := range assetNames {
		data, err := fs.ReadFile(ssjackui.Files, name)
		if err != nil {
			return "", err
		}
		assets[name] = data
		hash.Write([]byte(name))
		hash.Write([]byte{0})
		hash.Write(data)
		hash.Write([]byte{0})
	}
	destination := filepath.Join(parent, hex.EncodeToString(hash.Sum(nil)))
	if _, err := os.Lstat(destination); err == nil {
		return destination, verify(destination, assets)
	} else if !os.IsNotExist(err) {
		return "", err
	}
	staging, err := os.MkdirTemp(parent, ".install-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(staging)
	for _, name := range assetNames {
		path := filepath.Join(staging, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return "", err
		}
		if err := os.WriteFile(path, assets[name], 0600); err != nil {
			return "", err
		}
	}
	if err := os.Rename(staging, destination); err != nil {
		// Another launcher may have published the same content concurrently.
		if verifyErr := verify(destination, assets); verifyErr != nil {
			return "", fmt.Errorf("failed to install ssjack UI plugin: %w", err)
		}
	}
	return destination, nil
}

func ensureDirectory(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if err := os.Mkdir(path, 0700); err != nil && !os.IsExist(err) {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("managed UI path is not a regular directory: %s", path)
	}
	return nil
}

func verify(root string, assets map[string][]byte) error {
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("invalid UI plugin directory")
	}
	for _, name := range assetNames {
		path := root
		parts := strings.Split(name, "/")
		for _, part := range parts[:len(parts)-1] {
			path = filepath.Join(path, part)
			info, err := os.Lstat(path)
			if err != nil {
				return err
			}
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("invalid UI plugin asset directory")
			}
		}
		path = filepath.Join(root, filepath.FromSlash(name))
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("UI plugin asset is not a regular file")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !bytes.Equal(data, assets[name]) {
			return errors.New("managed ssjack UI assets were modified; refusing to overwrite them")
		}
	}
	return nil
}

// Environment enables this plugin only for the harness being launched.
func Environment(base []string, directory string) []string {
	out := make([]string, 0, len(base)+1)
	var existing string
	for _, entry := range base {
		name, value, ok := strings.Cut(entry, "=")
		matches := name == EnvDirectories || (runtime.GOOS == "windows" && strings.EqualFold(name, EnvDirectories))
		if ok && matches {
			existing = value
		} else {
			out = append(out, entry)
		}
	}
	directories := make([]string, 0)
	seen := make(map[string]bool)
	for _, path := range append(filepath.SplitList(existing), directory) {
		if path == "" {
			continue
		}
		key := filepath.Clean(path)
		if runtime.GOOS == "windows" {
			key = strings.ToLower(key)
		}
		if !seen[key] {
			directories = append(directories, path)
			seen[key] = true
		}
	}
	return append(out, EnvDirectories+"="+strings.Join(directories, string(os.PathListSeparator)))
}

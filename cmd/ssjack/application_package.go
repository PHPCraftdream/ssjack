package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf8"

	"github.com/PHPCraftdream/ssjack/internal/apptransport"
)

// validateClawwrightPackage checks declared compatibility, not code provenance or isolation.
func validateClawwrightPackage(entry string) error {
	entryDirectory := filepath.Dir(entry)
	distribution := filepath.Dir(entryDirectory)
	root := filepath.Dir(distribution)
	relative, err := filepath.Rel(root, entry)
	if err != nil {
		return errors.New("invalid Clawwright package layout")
	}
	relative = filepath.ToSlash(relative)
	if runtime.GOOS == "windows" {
		relative = strings.ToLower(relative)
	}
	if relative != "dist/entry/bin.js" {
		return errors.New("use a checked Clawwright package with dist/entry/bin.js")
	}
	path := filepath.Join(root, "package.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64*1024 {
		return errors.New("Clawwright package metadata is missing or invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return errors.New("Clawwright package metadata is unavailable")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 64*1024+1))
	if err != nil || len(data) > 64*1024 || !utf8.Valid(data) {
		return errors.New("Clawwright package metadata is invalid")
	}
	var metadata struct {
		Name    string `json:"name"`
		Runtime struct {
			Requirements struct {
				Optional     bool     `json:"optional"`
				Protocol     int      `json:"protocol"`
				ChunkSize    int      `json:"chunkSize"`
				Capabilities []string `json:"capabilities"`
				Cancellation string   `json:"cancellation"`
			} `json:"requirements"`
		} `json:"ssjackRuntime"`
	}
	if json.Unmarshal(data, &metadata) != nil {
		return errors.New("Clawwright package metadata is invalid")
	}
	requirements := metadata.Runtime.Requirements
	if metadata.Name != "@phpcraftdream/clawwright" || !requirements.Optional ||
		requirements.Protocol != apptransport.Protocol || requirements.ChunkSize != apptransport.ChunkSize ||
		requirements.Cancellation != "connection-only" {
		return errors.New("selected Clawwright package does not declare compatible ssjack transport; use a checked candidate")
	}
	capabilities := make(map[string]bool)
	for _, capability := range requirements.Capabilities {
		capabilities[capability] = true
	}
	for _, required := range []string{"exec", "stdin", "binary", "backpressure", "cancel"} {
		if !capabilities[required] {
			return errors.New("selected Clawwright package lacks required ssjack transport capabilities")
		}
	}
	return nil
}

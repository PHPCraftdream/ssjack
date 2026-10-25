package diagnostic

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"storagehost/internal/uiplugin"
)

type Finding struct {
	Status string
	Check  string
	Detail string
}

type Paths struct {
	Root           string
	Vault          string
	Executable     string
	PathExecutable string
}

func Inspect(paths Paths) []Finding {
	var out []Finding
	info, err := os.Lstat(paths.Vault)
	switch {
	case err != nil:
		out = append(out, Finding{"FAIL", "vault file", "missing or inaccessible; create it with ssjack vault init"})
	case !info.Mode().IsRegular():
		out = append(out, Finding{"FAIL", "vault file", "must be a regular file, not a symlink or directory"})
	case runtime.GOOS == "windows":
		out = append(out, Finding{"WARN", "vault permissions", "inspect the Windows directory/file DACL; Unix mode bits do not establish privacy"})
	case info.Mode().Perm()&0077 != 0:
		out = append(out, Finding{"FAIL", "vault permissions", "group or other users have permissions; expected 0600"})
	default:
		out = append(out, Finding{"OK", "vault permissions", "private Unix permissions"})
	}
	if paths.PathExecutable == "" {
		out = append(out, Finding{"WARN", "binary resolution", "ssjack is not on PATH; the launcher prepends its own binary directory for the harness"})
	} else if !sameFile(paths.Executable, paths.PathExecutable) {
		out = append(out, Finding{"WARN", "binary resolution", "current PATH resolves another binary; the launcher prepends its own binary directory"})
	} else {
		out = append(out, Finding{"OK", "binary resolution", "PATH resolves this executable"})
	}
	out = append(out, inspectMCP(filepath.Join(paths.Root, ".mcp.json"), paths.Executable))
	if err := uiplugin.Check(paths.Root); os.IsNotExist(err) {
		out = append(out, Finding{"WARN", "UI assets", "not installed for this build; normal agent startup installs them automatically"})
	} else if err != nil {
		out = append(out, Finding{"FAIL", "UI assets", "managed assets are invalid, modified, or inaccessible; no files were changed"})
	} else {
		out = append(out, Finding{"OK", "UI assets", "managed assets match this build"})
	}
	return out
}

func sameFile(a, b string) bool {
	left, err := os.Stat(a)
	if err != nil {
		return false
	}
	right, err := os.Stat(b)
	return err == nil && os.SameFile(left, right)
}

func inspectMCP(path, executable string) Finding {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return Finding{"WARN", "MCP registration", "absent; normal agent startup creates the secret-free registration"}
	}
	if err != nil {
		return Finding{"FAIL", "MCP registration", "cannot read the registration"}
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil || len(data) > 65536 {
		return Finding{"FAIL", "MCP registration", "invalid registration size"}
	}
	var config struct {
		Servers map[string]struct {
			Type    string            `json:"type"`
			Command string            `json:"command"`
			Args    []string          `json:"args"`
			Env     map[string]string `json:"env"`
		} `json:"mcpServers"`
	}
	if json.Unmarshal(data, &config) != nil {
		return Finding{"FAIL", "MCP registration", "invalid JSON at the required MCP boundary"}
	}
	entry, ok := config.Servers["ssjack"]
	if !ok || entry.Type != "stdio" || len(entry.Args) != 1 || entry.Args[0] != "mcp" {
		return Finding{"FAIL", "MCP registration", "expected an ssjack stdio entry with args [mcp]"}
	}
	if entry.Command != "ssjack" && !sameFile(entry.Command, executable) {
		return Finding{"FAIL", "MCP registration", "entry points to a different executable"}
	}
	for _, key := range []string{"SSJACK_ENV_TOKEN", "SSJACK_BOOTSTRAP_FILE"} {
		if _, exists := entry.Env[key]; exists {
			return Finding{"FAIL", "MCP registration", "bootstrap capabilities must not be persisted in MCP settings"}
		}
	}
	return Finding{"OK", "MCP registration", "secret-free stdio registration"}
}

func Failed(findings []Finding) error {
	for _, finding := range findings {
		if finding.Status == "FAIL" {
			return errors.New("readiness checks found failures; no settings were changed")
		}
	}
	return nil
}

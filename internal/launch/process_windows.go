package launch

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

func harnessCommand(ctx context.Context, args []string) (*exec.Cmd, error) {
	path, err := exec.LookPath(args[0])
	if err != nil {
		return nil, err
	}
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".cmd" && ext != ".bat" {
		return exec.CommandContext(ctx, path, args[1:]...), nil
	}
	// Batch files require cmd; reject ambiguous shell arguments.
	parts := append([]string{path}, args[1:]...)
	for i, part := range parts {
		if strings.ContainsAny(part, "\"%!&|<>^\r\n") {
			return nil, errors.New("these arguments require a native harness executable rather than .cmd/.bat")
		}
		parts[i] = "\"" + part + "\""
	}
	shell := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	cmd := exec.CommandContext(ctx, shell)
	cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: syscall.EscapeArg(shell) + " /d /s /c \"" + strings.Join(parts, " ") + "\""}
	return cmd, nil
}

package launch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"storagehost/internal/broker"
	"storagehost/internal/hooks"
	"storagehost/internal/uiplugin"
	"storagehost/internal/wire"
)

type Options struct {
	Root         string
	Executable   string
	Command      []string
	BootstrapTTL time.Duration
	Handler      broker.Handler
	Stdin        io.Reader
	Stdout       io.Writer
	Stderr       io.Writer
}

func Environment(base []string, bootstrap broker.Bootstrap, executable string) []string {
	out := make([]string, 0, len(base)+5)
	path := ""
	for _, item := range base {
		name, value, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}
		switch {
		case strings.EqualFold(name, broker.EnvToken), strings.EqualFold(name, broker.EnvFile),
			strings.EqualFold(name, broker.EnvSession), strings.EqualFold(name, broker.EnvEndpoint), strings.EqualFold(name, broker.EnvPin):
			continue
		case strings.EqualFold(name, "PATH"):
			path = value
		default:
			out = append(out, item)
		}
	}
	out = append(out, "PATH="+filepath.Dir(executable)+string(os.PathListSeparator)+path)
	return append(out, broker.EnvToken+"="+bootstrap.Token, broker.EnvSession+"="+bootstrap.Session,
		broker.EnvEndpoint+"="+bootstrap.Endpoint, broker.EnvPin+"="+bootstrap.Pin)
}

func EnsureMCP(root string) error {
	entry := map[string]any{"type": "stdio", "command": "ssjack", "args": []string{"mcp"}}
	path := filepath.Join(root, ".mcp.json")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if os.IsExist(err) {
		data, readErr := os.ReadFile(path)
		if readErr != nil || len(data) > 64*1024 {
			return errors.New("failed to read the existing .mcp.json")
		}
		var config struct {
			Servers map[string]struct {
				Type    string   `json:"type"`
				Command string   `json:"command"`
				Args    []string `json:"args"`
			} `json:"mcpServers"`
		}
		if json.Unmarshal(data, &config) != nil {
			return errors.New("existing .mcp.json is invalid")
		}
		existing, ok := config.Servers["ssjack"]
		if !ok || (existing.Type != "" && existing.Type != "stdio") || existing.Command != "ssjack" || len(existing.Args) != 1 || existing.Args[0] != "mcp" {
			return errors.New("existing .mcp.json was not changed: add an ssjack stdio server with command=ssjack and args=[mcp]")
		}
		return nil
	}
	if err != nil {
		return err
	}
	err = json.NewEncoder(file).Encode(map[string]any{"mcpServers": map[string]any{"ssjack": entry}})
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func Run(ctx context.Context, opts Options) (int, error) {
	if len(opts.Command) == 0 || opts.Handler == nil || opts.BootstrapTTL <= 0 {
		return 1, errors.New("missing harness or session parameters")
	}
	root, err := filepath.Abs(opts.Root)
	if err != nil {
		return 1, err
	}
	if err := EnsureMCP(root); err != nil {
		return 1, err
	}
	pluginDirectory, err := uiplugin.Install(root)
	if err != nil {
		return 1, fmt.Errorf("failed to prepare ssjack UI: %w", err)
	}
	if err := hooks.RemoveDisplay(root); err != nil {
		return 1, err
	}
	session, err := wire.RandomToken()
	if err != nil {
		return 1, err
	}
	envToken, err := wire.RandomToken()
	if err != nil {
		return 1, err
	}
	keeper, err := broker.Listen(ctx, session, envToken, opts.BootstrapTTL, opts.Handler)
	if err != nil {
		return 1, err
	}
	defer keeper.Close()
	bootstrap := broker.Bootstrap{Session: session, Endpoint: keeper.Endpoint(), Pin: keeper.Pin(), Token: envToken}
	command, err := harnessCommand(ctx, opts.Command)
	if err != nil {
		return 1, err
	}
	command.Dir = root
	command.Env = uiplugin.Environment(Environment(os.Environ(), bootstrap, opts.Executable), pluginDirectory)
	command.Stdin, command.Stdout, command.Stderr = opts.Stdin, opts.Stdout, opts.Stderr
	if err := command.Start(); err != nil {
		return 1, fmt.Errorf("failed to start harness: %w", err)
	}
	err = command.Wait()
	if err == nil {
		return 0, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), nil
	}
	return 1, err
}

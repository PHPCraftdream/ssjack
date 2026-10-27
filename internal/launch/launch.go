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

	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/enrollment"
	"github.com/PHPCraftdream/ssjack/internal/hooks"
	"github.com/PHPCraftdream/ssjack/internal/uiplugin"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

type Options struct {
	Root         string
	Mode         broker.Mode
	Executable   string
	Command      []string
	BootstrapTTL time.Duration
	Handler      broker.Handler
	Metadata     *enrollment.Metadata
	Policy       *enrollment.Policy
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
			strings.EqualFold(name, broker.EnvSession), strings.EqualFold(name, broker.EnvEndpoint), strings.EqualFold(name, broker.EnvPin),
			strings.EqualFold(name, "SSJACK_APP_ENDPOINT"), strings.EqualFold(name, "SSJACK_APP_TOKEN"), strings.EqualFold(name, "SSJACK_APP_CERTIFICATE_SHA256"):
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
	if opts.Mode == "" {
		opts.Mode = broker.ModeFull
	}
	if opts.Metadata != nil && opts.Mode != broker.ModeDeclarative {
		return 1, errors.New("enrollment metadata is unavailable in full mode")
	}
	if opts.Policy != nil {
		if opts.Mode != broker.ModeDeclarative {
			return 1, errors.New("policy snapshot unavailable in full mode")
		}
		if opts.Metadata == nil {
			return 1, errors.New("policy snapshot requires enrollment metadata")
		}
		if opts.Policy.EnrollmentID() != opts.Metadata.EnrollmentID() || opts.Policy.DriverID() != opts.Metadata.DriverID() || opts.Policy.DriverProtocol() != opts.Metadata.DriverProtocol() {
			return 1, errors.New("policy snapshot identity mismatch")
		}
	}
	if len(opts.Command) == 0 || (opts.Handler == nil && opts.Mode != broker.ModeDeclarative) || opts.BootstrapTTL <= 0 || (opts.Mode != broker.ModeFull && opts.Mode != broker.ModeDeclarative) {
		return 1, errors.New("missing harness or session parameters")
	}
	dispatch := broker.Dispatch(opts.Mode, opts.Handler)
	if opts.Metadata != nil {
		var err error
		dispatch, err = broker.DispatchEnrollment(opts.Metadata)
		if err != nil {
			return 1, err
		}
		if opts.Policy != nil {
			dispatch, err = broker.DispatchPolicy(opts.Metadata, *opts.Policy)
			if err != nil {
				return 1, err
			}
		}
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
	keeper, err := broker.Listen(ctx, session, envToken, opts.BootstrapTTL, dispatch)
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

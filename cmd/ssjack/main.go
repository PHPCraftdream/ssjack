package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"storagehost/internal/bridge"
	"storagehost/internal/broker"
	"storagehost/internal/hooks"
	"storagehost/internal/launch"
	"storagehost/internal/remote"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code, err := run(ctx, os.Args[1:])
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ssjack:", err)
	}
	os.Exit(code)
}

func run(ctx context.Context, args []string) (int, error) {
	if len(args) > 0 && args[0] == "hook" {
		return runHook(args[1:])
	}
	if len(args) > 0 && args[0] == "install-hooks" {
		if len(args) != 1 {
			return 1, errors.New("install-hooks does not accept arguments")
		}
		executable, err := os.Executable()
		if err != nil {
			return 1, err
		}
		if err := hooks.Install(".", executable); err != nil {
			return 1, err
		}
		fmt.Fprintln(os.Stderr, "Installed ssjack display hooks in .claude/settings.local.json. Open /hooks or restart if they do not appear.")
		return 0, nil
	}
	if len(args) > 0 && args[0] == "mcp" {
		if len(args) != 1 {
			return 1, errors.New("mcp mode does not accept arguments")
		}
		return runMCP(ctx)
	}
	flags := flag.NewFlagSet("ssjack", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", "", "Explicit legacy Ktav target configuration instead of the encrypted vault")
	ttl := flags.Duration("bootstrap-timeout", 2*time.Minute, "Initial MCP attachment deadline")
	generatePath := flags.String("generate-key", "", "Create a derived Ed25519 key in a new encrypted container")
	protectPath := flags.String("protect-key", "", "Protect an existing encrypted SSH key in a new container")
	keyOutput := flags.String("key-output", "", "Output for --protect-key (default: input + .ssjack.ktav)")
	vaultPath := flags.String("vault", ".ssh/credentials.ssjack.ktav", "Encrypted credentials database for vault, ssh, and run commands")
	flags.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ssjack [options] <harness> [arguments...]\nExample: ssjack run storage claude -c\nGenerate key: ssjack --generate-key <new-file>\nProtect key: ssjack --protect-key <encrypted-key> [--key-output <new-file>]\nVault: ssjack [--vault <file>] vault init|list|passwd|add|edit|show|remove|public|import|export\nInteractive SSH: ssjack ssh <name>\nCoding agent: ssjack run <name> <harness> [arguments...]\nService mode: ssjack mcp\nUI cards: configured automatically at startup\nLegacy display hooks: ssjack install-hooks")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, nil
		}
		return 1, err
	}
	if *generatePath != "" || *protectPath != "" || *keyOutput != "" {
		if flags.NArg() != 0 || *configPath != "" {
			return 1, errors.New("key operations cannot launch a harness or shell")
		}
		return runKeyCommand(ctx, *generatePath, *protectPath, *keyOutput)
	}
	if flags.NArg() > 0 && flags.Arg(0) == "ssh" {
		if flags.NArg() != 2 || *configPath != "" {
			return 1, errors.New("usage: ssjack [--vault <file>] ssh <name>")
		}
		return runVaultShell(ctx, *vaultPath, flags.Arg(1))
	}
	if flags.NArg() > 0 && flags.Arg(0) == "vault" {
		if *configPath != "" {
			return 1, errors.New("vault commands do not use legacy --config")
		}
		return runVaultCommand(ctx, *vaultPath, flags.Args()[1:])
	}
	command := flags.Args()
	credentialName := ""
	if len(command) > 0 && command[0] == "run" {
		if len(command) < 3 || *configPath != "" {
			return 1, errors.New("usage: ssjack [--vault <file>] run <name> <harness> [arguments...]")
		}
		credentialName, command = command[1], command[2:]
	}
	if flags.NArg() == 0 || *ttl <= 0 || *ttl > 10*time.Minute {
		flags.Usage()
		return 1, errors.New("specify a harness and a bootstrap timeout greater than zero and at most 10 minutes")
	}
	runner, targets, err := loadAgentCredentials(*vaultPath, credentialName, *configPath)
	if err != nil {
		return 1, err
	}
	manager := remote.NewManager(ctx, targets, runner)
	defer manager.Close()
	executable, err := os.Executable()
	if err != nil {
		return 1, err
	}
	root, err := filepath.Abs(".")
	if err != nil {
		return 1, err
	}
	fmt.Fprintln(os.Stderr, "Keys unlocked. MCP access will attach once to this session.")
	return launch.Run(ctx, launch.Options{
		Root: root, Executable: executable, Command: command, BootstrapTTL: *ttl,
		Handler: manager.Handle, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
	})
}

func runHook(args []string) (int, error) {
	if len(args) != 1 {
		return 1, errors.New("usage: ssjack hook pre|post|failure")
	}
	input, err := io.ReadAll(io.LimitReader(os.Stdin, hooks.MaxInput+1))
	if err != nil {
		return 1, errors.New("failed to read hook event")
	}
	output, err := hooks.Run(args[0], input)
	if err != nil {
		return 1, err
	}
	if _, err := fmt.Fprintln(os.Stdout, string(output)); err != nil {
		return 1, err
	}
	return 0, nil
}

func runMCP(ctx context.Context) (int, error) {
	path, token := os.Getenv(broker.EnvFile), os.Getenv(broker.EnvToken)
	os.Unsetenv(broker.EnvFile)
	os.Unsetenv(broker.EnvToken)
	if path == "" || token == "" {
		return 1, errors.New("start the MCP bridge through an ssjack session")
	}
	client, err := broker.ConnectFile(ctx, path, token)
	token = ""
	if err != nil {
		return 1, err
	}
	defer client.Close()
	if err := bridge.NewServer(client).Run(ctx, &mcp.StdioTransport{}); err != nil {
		return 1, err
	}
	return 0, nil
}

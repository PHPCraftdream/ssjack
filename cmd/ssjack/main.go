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
	"golang.org/x/term"

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
	configPath := flags.String("config", ".ssh/ssjack.ktav", "Ktav file with approved SSH targets")
	ttl := flags.Duration("bootstrap-timeout", 2*time.Minute, "Initial MCP attachment deadline")
	flags.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: ssjack [options] <harness> [arguments...]\nExample: ssjack claude -c\nService mode: ssjack mcp\nUI cards: configured automatically at startup\nLegacy display hooks: ssjack install-hooks")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, nil
		}
		return 1, err
	}
	if flags.NArg() == 0 || *ttl <= 0 || *ttl > 10*time.Minute {
		flags.Usage()
		return 1, errors.New("specify a harness and a bootstrap timeout greater than zero and at most 10 minutes")
	}
	config, err := remote.LoadConfig(*configPath)
	if err != nil {
		return 1, err
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return 1, errors.New("an interactive terminal is required; passphrases from environment variables or pipes are not accepted")
	}
	fmt.Fprint(os.Stderr, "SSH key passphrase: ")
	passphrase, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return 1, errors.New("failed to read passphrase")
	}
	signers, err := remote.Unlock(config, passphrase)
	clear(passphrase)
	if err != nil {
		return 1, err
	}
	runner, err := remote.NewSSHRunner(config, signers)
	if err != nil {
		return 1, err
	}
	var targets []string
	for target := range config.Targets {
		targets = append(targets, target)
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
		Root: root, Executable: executable, Command: flags.Args(), BootstrapTTL: *ttl,
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

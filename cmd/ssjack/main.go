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

	project "github.com/PHPCraftdream/ssjack"
	"github.com/PHPCraftdream/ssjack/internal/application"
	"github.com/PHPCraftdream/ssjack/internal/bridge"
	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/buildinfo"
	"github.com/PHPCraftdream/ssjack/internal/hooks"
	"github.com/PHPCraftdream/ssjack/internal/launch"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/vault"
	"github.com/PHPCraftdream/ssjack/internal/wire"
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
	if handled, err := handleHelp(args, os.Stdout); handled {
		if err != nil {
			return 1, err
		}
		return 0, nil
	}
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
		fmt.Fprintln(os.Stderr, "Installed legacy display hooks. Normal startup uses the embedded UI plugin instead.")
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
	ttl := flags.Duration("bootstrap-timeout", 2*time.Minute, "Initial MCP attachment deadline")
	clawwrightDirectory := flags.String("clawwright-directory", "", "Register a Clawwright deployment directory")
	clawwrightEntry := flags.String("clawwright-entry", "", "Checked Clawwright JavaScript entry (default installed package on PATH)")
	clawwrightContainer := flags.String("clawwright-container", "", "Fixed Incus container route for Clawwright SSH commands")
	clawwrightUser := flags.String("clawwright-user", "", "Fixed guest user for the Clawwright Incus route")
	generatePath := flags.String("generate-key", "", "Create a derived Ed25519 key in a new encrypted container")
	protectPath := flags.String("protect-key", "", "Protect an existing SSH key in a new container")
	keyOutput := flags.String("key-output", "", "Output for --protect-key")
	vaultPath := flags.String("vault", ".ssh/credentials.ssjack.ktav", "Encrypted profile database")
	version := flags.Bool("version", false, "Print version, commit, and platform")
	licenses := flags.Bool("licenses", false, "Print project licenses and third-party notices")
	var profile string
	flags.StringVar(&profile, "profile", "main", "Named encrypted profile (default main)")
	flags.StringVar(&profile, "p", "main", "Short form of --profile")
	flags.Usage = func() { printRootHelp(os.Stderr) }
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, nil
		}
		return 1, err
	}
	if *version {
		fmt.Fprintln(os.Stdout, buildinfo.String())
		return 0, nil
	}
	if *licenses {
		if _, err := io.WriteString(os.Stdout, project.LicenseText()); err != nil {
			return 1, err
		}
		return 0, nil
	}
	if handled, err := handleHelp(flags.Args(), os.Stdout); handled {
		if err != nil {
			return 1, err
		}
		return 0, nil
	}
	if err := vault.ValidateName(profile); err != nil {
		return 1, err
	}
	if *generatePath != "" || *protectPath != "" || *keyOutput != "" {
		if flags.NArg() != 0 {
			return 1, errors.New("key-file operations cannot launch another command")
		}
		return runKeyCommand(ctx, *generatePath, *protectPath, *keyOutput)
	}
	command := flags.Args()
	if len(command) == 0 {
		flags.Usage()
		return 1, errors.New("specify a command; default profile is main")
	}
	switch command[0] {
	case "ssh":
		if len(command) != 1 {
			return 1, errors.New("usage: ssjack [-p PROFILE] ssh")
		}
		return runVaultShell(ctx, *vaultPath, profile)
	case "vault":
		return runVaultMaintenance(ctx, *vaultPath, profile, command[1:])
	case "list":
		if len(command) != 1 {
			return 1, errors.New("usage: ssjack list")
		}
		return runVaultCommand(ctx, *vaultPath, command)
	case "add":
		args := []string{"add", profile}
		if len(command) == 2 && command[1] == "--generate-key" {
			args = append(args, "--generate-key")
		} else if len(command) != 1 {
			return 1, errors.New("usage: ssjack [-p PROFILE] add [--generate-key]")
		}
		return runVaultCommand(ctx, *vaultPath, args)
	case "show", "edit", "remove":
		if len(command) != 1 {
			return 1, errors.New("select a profile with -p PROFILE before the command")
		}
		return runVaultCommand(ctx, *vaultPath, []string{command[0], profile})
	case "key":
		if len(command) == 2 && command[1] == "public" {
			return runVaultCommand(ctx, *vaultPath, []string{"public", profile})
		}
		if len(command) == 3 && (command[1] == "import" || command[1] == "export") {
			return runVaultCommand(ctx, *vaultPath, []string{command[1], profile, command[2]})
		}
		return 1, errors.New("usage: ssjack [-p PROFILE] key public | import FILE | export FILE")
	case "policy":
		return runPolicy(ctx, *vaultPath, profile, command[1:])
	case "doctor":
		if len(command) != 1 {
			return 1, errors.New("usage: ssjack doctor")
		}
		return runSafetyCommand(ctx, *vaultPath, command)
	case "check", "rotate":
		if len(command) != 1 {
			return 1, errors.New("select a profile with -p PROFILE before the command")
		}
		return runSafetyCommand(ctx, *vaultPath, []string{command[0], profile})
	case "hostkey":
		if len(command) == 2 && command[1] == "show" {
			return runSafetyCommand(ctx, *vaultPath, []string{"hostkey", "show", profile})
		}
		if len(command) == 3 && command[1] == "replace" {
			return runSafetyCommand(ctx, *vaultPath, []string{"hostkey", "replace", profile, command[2]})
		}
		return 1, errors.New("usage: ssjack [-p PROFILE] hostkey show | replace FILE")
	case "run":
		if len(command) < 2 {
			return 1, errors.New("usage: ssjack [-p PROFILE] run HARNESS [ARGUMENTS...]")
		}
		command = command[1:]
	}
	if *ttl <= 0 || *ttl > 10*time.Minute {
		return 1, errors.New("bootstrap timeout must be greater than zero and at most 10 minutes")
	}
	applicationOptions, err := registeredClawwright(*clawwrightDirectory, *clawwrightEntry, *clawwrightContainer, *clawwrightUser, profile, nil)
	if err != nil {
		return 1, err
	}
	runner, streamRunner, targets, err := loadAgentCredentials(*vaultPath, profile)
	if err != nil {
		return 1, err
	}
	manager := remote.NewManager(ctx, targets, runner)
	defer manager.Close()
	if applicationOptions != nil {
		applicationOptions.Runner = streamRunner
	}
	applicationManager, err := application.New(ctx, applicationOptions)
	if err != nil {
		return 1, err
	}
	defer applicationManager.Close()
	handler := func(ctx context.Context, request wire.Request) wire.Reply {
		if reply, handled := applicationManager.Handle(ctx, request); handled {
			return reply
		}
		return manager.Handle(ctx, request)
	}
	executable, err := os.Executable()
	if err != nil {
		return 1, err
	}
	root, err := filepath.Abs(".")
	if err != nil {
		return 1, err
	}
	fmt.Fprintln(os.Stderr, "Profile unlocked. MCP access will attach once to this session.")
	return launch.Run(ctx, launch.Options{Root: root, Executable: executable, Command: command, BootstrapTTL: *ttl, Handler: handler, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr})
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
	bootstrap := broker.Bootstrap{
		Session: os.Getenv(broker.EnvSession), Endpoint: os.Getenv(broker.EnvEndpoint),
		Pin: os.Getenv(broker.EnvPin), Token: os.Getenv(broker.EnvToken),
	}
	for _, name := range []string{broker.EnvFile, broker.EnvToken, broker.EnvSession, broker.EnvEndpoint, broker.EnvPin, "SSJACK_APP_ENDPOINT", "SSJACK_APP_TOKEN", "SSJACK_APP_CERTIFICATE_SHA256"} {
		os.Unsetenv(name)
	}
	if bootstrap.Endpoint == "" || bootstrap.Pin == "" || bootstrap.Session == "" || bootstrap.Token == "" {
		return 1, errors.New("start the MCP bridge through an ssjack session")
	}
	client, err := broker.ConnectBootstrap(ctx, bootstrap)
	bootstrap.Token = ""
	if err != nil {
		return 1, err
	}
	defer client.Close()
	if err := bridge.NewServer(client).Run(ctx, &mcp.StdioTransport{}); err != nil {
		return 1, err
	}
	return 0, nil
}

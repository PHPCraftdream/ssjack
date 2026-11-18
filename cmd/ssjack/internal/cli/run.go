package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	project "github.com/PHPCraftdream/ssjack"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/appstore"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/declarative"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/help"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/keys"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/launchguard"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/remotemcp"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/shell"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/startup"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/terminal"
	"github.com/PHPCraftdream/ssjack/cmd/ssjack/internal/transfercmd"
	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/buildinfo"
	"github.com/PHPCraftdream/ssjack/internal/hooks"
	"github.com/PHPCraftdream/ssjack/internal/launch"
	"github.com/PHPCraftdream/ssjack/internal/startupsecret"
	"github.com/PHPCraftdream/ssjack/internal/transfercore"
	"github.com/PHPCraftdream/ssjack/internal/vault"
)

// Private hooks kept for whitebox CLI tests.
var cliLoadAgentCredentials = loadKeeperCredentials
var cliLaunchRun = launch.Run

// Run unlocks the startup password channel (removing the environment copy
// first) and executes the command line under it.
func Run(ctx context.Context, args []string) (int, error) {
	value, present := os.LookupEnv(startupsecret.Environment)
	if present {
		if err := os.Unsetenv(startupsecret.Environment); err != nil {
			return 1, errors.New("cannot remove startup vault password from child environment")
		}
	}
	input := startupsecret.New(value, present)
	value = ""
	defer input.Close()
	return runWithStartupPassword(startup.WithInput(ctx, input), args)
}

// ReadVaultPassword prompts for the vault secret through the startup
// password channel when supplied and hidden terminal input otherwise.
func readVaultPassword(ctx context.Context, prompt string) ([]byte, error) {
	return startup.ReadVaultPassword(ctx, prompt, terminal.Secret)
}

func runWithStartupPassword(ctx context.Context, args []string) (code int, result error) {
	if handled, err := help.Handle(args, os.Stdout); handled {
		if err != nil {
			return 1, err
		}
		return 0, nil
	}
	if len(args) > 0 && args[0] == "declarative" {
		return declarative.Run(ctx, args[1:])
	}
	if len(args) > 0 && args[0] == "appstore" {
		return appstore.Run(ctx, args[1:])
	}
	if len(args) > 0 && args[0] == "hook" {
		return remotemcp.RunHook(args[1:])
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
		return remotemcp.Run(ctx)
	}
	flags := flag.NewFlagSet("ssjack", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	startup.Register(ctx, flags)
	ttl := flags.Duration("bootstrap-timeout", 2*time.Minute, "Initial MCP attachment deadline")
	modeFlag := flags.String("mode", "full", "Keeper mode: full or declarative (partial, deny-all)")
	noOutputFilter := flags.Bool("no-output-filter", false, "Disable only the MCP known-literal output guard for this trusted-terminal full-mode run")
	metadataPath := flags.String("enrollment-metadata", "", "Absolute path to declarative enrollment metadata")
	policyPath := flags.String("policy-snapshot", "", "Absolute path to human-installed deny-only policy snapshot")
	identityPath := flags.String("enrollment-identity", "", "Absolute path to declarative enrollment identity snapshot")
	var appDirectories appDirectoryFlags
	flags.Var(&appDirectories, "app", "Register an application directory containing ssjack-app.json (repeatable, full mode)")
	appRoute := flags.String("app-route", "", "Fixed Incus route incus:CONTAINER:USER for registered applications")
	var transferRootSpecs transfercmd.RootFlags
	flags.Var(&transferRootSpecs, "transfer-root", "Register a transfer root as [NAME=]DIR (repeatable, full mode)")
	transferMaxBytes := flags.Int64("transfer-max-bytes", transfercore.DefaultLimits().MaxBytes, "Maximum total bytes per transfer (full mode)")
	transferMaxEntries := flags.Int("transfer-max-entries", transfercore.DefaultLimits().MaxEntries, "Maximum entries per transfer (full mode)")
	generatePath := flags.String("generate-key", "", "Create a derived Ed25519 key in a new encrypted container")
	protectPath := flags.String("protect-key", "", "Protect an existing SSH key in a new container")
	keyOutput := flags.String("key-output", "", "Output for --protect-key")
	vaultPath := flags.String("vault", ".ssh/credentials.ssjack.ktav", "Encrypted profile database")
	interactive := flags.Bool("interactive", false, "Open the trusted-terminal connection picker and owner database editor")
	server := flags.String("server", "", "Select a named server from the directory database")
	account := flags.String("account", "", "Select a named SSH account on --server")
	version := flags.Bool("version", false, "Print version, commit, and platform")
	licenses := flags.Bool("licenses", false, "Print project licenses and third-party notices")
	var profile string
	flags.StringVar(&profile, "profile", "main", "Named encrypted profile (default main)")
	flags.StringVar(&profile, "p", "main", "Short form of --profile")
	flags.Usage = func() { help.PrintRootHelp(os.Stderr) }
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, nil
		}
		return 1, err
	}
	if err := startup.Validate(ctx); err != nil {
		return 1, err
	}
	metadataSupplied, policySupplied, identitySupplied := false, false, false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "enrollment-metadata" {
			metadataSupplied = true
		}
		if f.Name == "policy-snapshot" {
			policySupplied = true
		}
		if f.Name == "enrollment-identity" {
			identitySupplied = true
		}
	})
	command := flags.Args()
	if *noOutputFilter {
		if *modeFlag != string(broker.ModeFull) || len(command) < 2 || command[0] != "run" || *interactive || *version || *licenses || *generatePath != "" || *protectPath != "" || *keyOutput != "" {
			return 1, errors.New("--no-output-filter is only available for an explicit full-mode run HARNESS")
		}
		if err := launchguard.RequireTerminal(); err != nil {
			return 1, err
		}
	}
	transferFlagsSupplied := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "transfer-root" || f.Name == "transfer-max-bytes" || f.Name == "transfer-max-entries" {
			transferFlagsSupplied = true
		}
	})
	if transferFlagsSupplied && *modeFlag != string(broker.ModeFull) {
		return 1, errors.New("--transfer-root, --transfer-max-bytes and --transfer-max-entries are only available in full mode")
	}
	appFlagsSupplied := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "app" || f.Name == "app-route" {
			appFlagsSupplied = true
		}
	})
	if appFlagsSupplied && *modeFlag != string(broker.ModeFull) {
		return 1, errors.New("--app and --app-route are only available in full mode")
	}
	selectorProfile, named, selectionErr := startupSelection(flags, profile, *server, *account)
	if selectionErr != nil {
		return 1, selectionErr
	}
	if *interactive {
		conflict := len(command) != 0
		flags.Visit(func(f *flag.Flag) {
			if f.Name != "interactive" && f.Name != "vault" && f.Name != "server" && f.Name != "account" && f.Name != "vault-password" {
				conflict = true
			}
		})
		if conflict {
			return 1, errors.New("--interactive accepts only --vault, --server, --account and --vault-password; no command")
		}
		return shell.RunInteractive(ctx, *vaultPath, *server, *account)
	}
	if (metadataSupplied || policySupplied || identitySupplied) && (len(command) == 0 || command[0] != "run" || *version || *licenses || *generatePath != "" || *protectPath != "" || *keyOutput != "") {
		return 1, errors.New("--enrollment-metadata, --policy-snapshot, and --enrollment-identity are only available for declarative run")
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
	if handled, err := help.Handle(flags.Args(), os.Stdout); handled {
		if err != nil {
			return 1, err
		}
		return 0, nil
	}
	if err := vault.ValidateName(profile); err != nil {
		return 1, err
	}
	if named {
		if *modeFlag != string(broker.ModeFull) || *generatePath != "" || *protectPath != "" || *keyOutput != "" || !namedCommandAllowed(command) {
			return 1, errors.New("--server/--account select SSH, check, rotate, text-adapter or a full-mode harness; use --interactive for directory editing")
		}
		profile = selectorProfile
	}
	if *generatePath != "" || *protectPath != "" || *keyOutput != "" {
		if flags.NArg() != 0 {
			return 1, errors.New("key-file operations cannot launch another command")
		}
		return keys.RunKeyCommand(ctx, *generatePath, *protectPath, *keyOutput)
	}
	if len(command) == 0 {
		flags.Usage()
		return 1, errors.New("specify a command; default profile is main")
	}
	if command[0] == "run" {
		if len(command) < 2 {
			return 1, errors.New("usage: ssjack [-p PROFILE] run HARNESS [ARGUMENTS...]")
		}
		command = command[1:]
	} else if rc, handled, rerr := dispatchStartupCommand(ctx, flags, *vaultPath, *server, *account, profile, command); handled {
		return rc, rerr
	}
	if *modeFlag != string(broker.ModeFull) && *modeFlag != string(broker.ModeDeclarative) {
		return 1, errors.New("mode must be full or declarative")
	}
	metadata, policy, identity, err := loadEnrollment(enrollmentInputs{
		mode:             *modeFlag,
		metadataPath:     *metadataPath,
		policyPath:       *policyPath,
		identityPath:     *identityPath,
		metadataSupplied: metadataSupplied,
		policySupplied:   policySupplied,
		identitySupplied: identitySupplied,
	})
	if err != nil {
		return 1, err
	}
	if *ttl <= 0 || *ttl > 10*time.Minute {
		return 1, errors.New("bootstrap timeout must be greater than zero and at most 10 minutes")
	}
	var handler broker.Handler
	var remoteMCPDescriptor string
	var bootstrapOutput launch.OutputSetup
	if *modeFlag == string(broker.ModeFull) {
		session, cleanup, err := startFullMode(ctx, fullModeOptions{
			vaultPath:          *vaultPath,
			profile:            profile,
			appDirectories:     appDirectories,
			appRoute:           *appRoute,
			transferRoots:      transferRootSpecs,
			transferMaxBytes:   *transferMaxBytes,
			transferMaxEntries: *transferMaxEntries,
			noOutputFilter:     *noOutputFilter,
			named:              named,
			ttl:                *ttl,
		})
		defer cleanup(&code, &result)
		if err != nil {
			return 1, err
		}
		handler, remoteMCPDescriptor, bootstrapOutput = session.handler, session.remoteMCP, session.prepareOutput
	}
	executable, err := os.Executable()
	if err != nil {
		return 1, err
	}
	root, err := filepath.Abs(".")
	if err != nil {
		return 1, err
	}
	if *modeFlag == string(broker.ModeFull) {
		fmt.Fprintln(os.Stderr, "Profile unlocked. MCP access will attach once to this session.")
	} else {
		fmt.Fprintln(os.Stderr, "Starting declarative session. MCP access will attach once to this session.")
	}
	return cliLaunchRun(ctx, launch.Options{Root: root, Executable: executable, Command: command, BootstrapTTL: *ttl, Handler: handler, Mode: broker.Mode(*modeFlag), Metadata: metadata, Policy: policy, Identity: identity, RemoteMCP: remoteMCPDescriptor, PrepareOutput: bootstrapOutput, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr})
}

package application

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/PHPCraftdream/ssjack/internal/apptransport"
	"github.com/PHPCraftdream/ssjack/internal/broker"
	"github.com/PHPCraftdream/ssjack/internal/remote"
	"github.com/PHPCraftdream/ssjack/internal/wire"
)

const Name = "clawwright"

var (
	containerName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	userName      = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)
	commandName   = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
)

type Options struct {
	Directory string
	Command   []string
	Profile   string
	Runner    remote.StreamRunner
	Container string
	User      string
}

type Input struct {
	Application    string   `json:"application" jsonschema:"Registered application ID from app_list"`
	Arguments      []string `json:"arguments" jsonschema:"Finite Clawwright command and arguments, passed without a local shell"`
	Confirm        bool     `json:"confirm,omitempty" jsonschema:"Acknowledge a potentially mutating operation; harness authorization still applies"`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty" jsonschema:"Operation timeout, 1 to 3600 seconds; default 600"`
}

type Description struct {
	Name      string `json:"name"`
	Profile   string `json:"profile"`
	Container string `json:"container,omitempty"`
}

type ListOutput struct {
	Applications []Description `json:"applications"`
}

type Manager struct {
	jobs        *remote.Manager
	description Description
}

func ValidateRoute(container, user string) error {
	if container == "" && user == "" {
		return nil
	}
	if !containerName.MatchString(container) || !userName.MatchString(user) {
		return errors.New("an Incus route requires a local container name and an explicit guest user")
	}
	return nil
}

func New(parent context.Context, options *Options) (*Manager, error) {
	m := &Manager{}
	if options == nil {
		return m, nil
	}
	if options.Runner == nil || options.Profile == "" || options.Directory == "" || len(options.Command) == 0 {
		return nil, errors.New("incomplete registered application")
	}
	if err := ValidateRoute(options.Container, options.User); err != nil {
		return nil, err
	}
	root, err := filepath.Abs(options.Directory)
	if err != nil {
		return nil, errors.New("invalid registered application directory")
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, errors.New("registered application directory is unavailable")
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return nil, errors.New("registered application requires a directory")
	}
	program := append([]string(nil), options.Command...)
	for _, arg := range program {
		if strings.IndexByte(arg, 0) >= 0 {
			return nil, errors.New("invalid registered application command")
		}
	}
	if !filepath.IsAbs(program[0]) {
		return nil, errors.New("registered application executable must be absolute")
	}
	runner := routeRunner(options.Runner, options.Container, options.User)
	profile := options.Profile
	m.description = Description{Name: Name, Profile: profile, Container: options.Container}
	m.jobs = remote.NewManager(parent, []string{Name}, func(ctx context.Context, target, encoded string, stdout, stderr io.Writer) (int, error) {
		var arguments []string
		if target != Name || wire.Decode(encoded, &arguments) != nil {
			return -1, errors.New("invalid registered application operation")
		}
		if ctx.Err() != nil {
			return -1, ctx.Err()
		}
		scope, err := apptransport.Listen(ctx, profile, runner)
		if err != nil {
			if ctx.Err() != nil {
				return -1, ctx.Err()
			}
			return -1, errors.New("could not prepare the application transport")
		}
		defer scope.Close()
		bootstrap := scope.Bootstrap()
		out := newSecretWriter(stdout, bootstrap.Token)
		errOut := newSecretWriter(stderr, bootstrap.Token)
		args := append(append([]string(nil), program[1:]...), arguments...)
		command := exec.CommandContext(ctx, program[0], args...)
		command.Dir = root
		command.Env = apptransport.Environment(os.Environ(), bootstrap)
		command.Stdout, command.Stderr = out, errOut
		command.WaitDelay = 2 * time.Second
		err = command.Run()
		outErr, stderrErr := out.flush(), errOut.flush()
		if outErr != nil || stderrErr != nil {
			return -1, errors.New("registered application output could not be captured")
		}
		if ctx.Err() != nil {
			return -1, ctx.Err()
		}
		if err == nil {
			return 0, nil
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode(), nil
		}
		return -1, errors.New("registered application could not complete")
	})
	return m, nil
}

func (m *Manager) Close() {
	if m.jobs != nil {
		m.jobs.Close()
	}
}

func (m *Manager) Handle(ctx context.Context, request wire.Request) (wire.Reply, bool) {
	switch request.Operation {
	case "app_list":
		out := ListOutput{Applications: []Description{}}
		if m.jobs != nil {
			out.Applications = append(out.Applications, m.description)
		}
		return broker.Result(out, nil), true
	case "app_start", "app_read", "app_cancel":
		if m.jobs == nil {
			return broker.Result(nil, errors.New("no application registered; start the keeper with --clawwright-directory")), true
		}
	default:
		return wire.Reply{}, false
	}
	if request.Operation == "app_start" {
		var input Input
		if wire.Decode(request.Data, &input) != nil {
			return broker.Result(nil, errors.New("invalid application arguments")), true
		}
		if err := validateInput(input); err != nil {
			return broker.Result(nil, err), true
		}
		encoded, err := wire.Encode(input.Arguments)
		if err != nil {
			return broker.Result(nil, err), true
		}
		data, err := wire.Encode(remote.StartInput{Target: Name, Command: encoded, TimeoutSeconds: input.TimeoutSeconds})
		if err != nil {
			return broker.Result(nil, err), true
		}
		return m.jobs.Handle(ctx, wire.Request{Operation: "start", Data: data}), true
	}
	operation := "read"
	if request.Operation == "app_cancel" {
		operation = "cancel"
	}
	return m.jobs.Handle(ctx, wire.Request{Operation: operation, Data: request.Data}), true
}

func validateInput(input Input) error {
	if input.Application != Name || len(input.Arguments) == 0 || len(input.Arguments) > 128 || !commandName.MatchString(input.Arguments[0]) || input.TimeoutSeconds < 0 || input.TimeoutSeconds > 3600 {
		return errors.New("invalid registered application command or deadline")
	}
	if input.Arguments[0] == "mcp-serve" || input.Arguments[0] == "control-mcp" {
		return errors.New("application jobs accept finite CLI commands, not stdio MCP servers")
	}
	size := 0
	for _, argument := range input.Arguments {
		size += len(argument)
		if strings.IndexByte(argument, 0) >= 0 || argument == "--stdin" {
			return errors.New("application jobs require argv or a local file, not interactive input")
		}
	}
	if size > 8*1024 {
		return errors.New("application argument size limit exceeded")
	}
	if !input.Confirm && !observational(input.Arguments) {
		return errors.New("this application operation requires confirm=true and applicable operator authorization")
	}
	return nil
}

func observational(args []string) bool {
	switch args[0] {
	case "help", "version", "status", "inspect", "doctor", "plan":
		return true
	case "bootstrap":
		check := false
		for _, arg := range args[1:] {
			if arg == "--check" {
				check = true
			} else if arg != "--json" {
				return false
			}
		}
		return check
	}
	return false
}

func quote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func routeRunner(runner remote.StreamRunner, container, user string) remote.StreamRunner {
	if container == "" {
		return runner
	}
	return func(ctx context.Context, profile, command string, input io.Reader, stdout, stderr io.Writer) (int, error) {
		prefix := "/usr/bin/sudo -n /usr/bin/incus exec " + quote(container) + " -- /usr/sbin/runuser -u " + quote(user) + " -- /bin/sh -c " + quote(command)
		return runner(ctx, profile, prefix, input, stdout, stderr)
	}
}

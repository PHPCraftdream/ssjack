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

var (
	containerName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	userName      = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)
	commandName   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
)

// Options registers validated applications for one keeper session.
// Container and User, when set, route every registered application's
// transport commands through the fixed Incus route.
type Options struct {
	Apps      []App
	Profile   string
	Runner    remote.StreamRunner
	Guard     remote.GuardProvider
	Container string
	User      string
}

type Input struct {
	Application    string   `json:"application" jsonschema:"Registered application name from app_list"`
	Arguments      []string `json:"arguments" jsonschema:"Finite application command and arguments, passed without a local shell"`
	Confirm        bool     `json:"confirm,omitempty" jsonschema:"Acknowledge a potentially mutating operation; harness authorization still applies"`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty" jsonschema:"Operation timeout, 1 to 3600 seconds; default 600"`
}

type Description struct {
	Name      string `json:"name"`
	Profile   string `json:"profile"`
	Container string `json:"container,omitempty"`
}

// noApplicationHint is the fixed text of an empty application list.
const noApplicationHint = "no application is registered; the owner starts the keeper with --app DIR"

// MaxApplications bounds one keeper session's registrations.
const MaxApplications = 16

type ListOutput struct {
	Applications []Description `json:"applications"`
	// Hint explains an empty list; it carries no owner data.
	Hint string `json:"hint,omitempty"`
}

type registered struct {
	App
	observational map[string]bool
	refused       map[string]bool
}

type Manager struct {
	jobs         *remote.Manager
	apps         map[string]*registered
	descriptions []Description
}

// ValidateRoute checks a container and guest user pair; both empty means no route.
func ValidateRoute(container, user string) error {
	if container == "" && user == "" {
		return nil
	}
	if !containerName.MatchString(container) || !userName.MatchString(user) {
		return errors.New("an Incus route requires a local container name and an explicit guest user")
	}
	return nil
}

// ParseRoute parses incus:CONTAINER:USER; an empty spec means no route.
func ParseRoute(spec string) (container, user string, err error) {
	if spec == "" {
		return "", "", nil
	}
	parts := strings.Split(spec, ":")
	if len(parts) != 3 || parts[0] != "incus" {
		return "", "", errors.New("--app-route must be incus:CONTAINER:USER")
	}
	if err := ValidateRoute(parts[1], parts[2]); err != nil {
		return "", "", err
	}
	return parts[1], parts[2], nil
}

func nameSet(names []string) map[string]bool {
	set := make(map[string]bool, len(names))
	for _, name := range names {
		set[name] = true
	}
	return set
}

func directoryExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func register(app App) (*registered, error) {
	if !appName.MatchString(app.Name) || !filepath.IsAbs(app.Directory) || !filepath.IsAbs(app.Workdir) || !directoryExists(app.Directory) || !directoryExists(app.Workdir) {
		return nil, errors.New("registered application requires a name and absolute directories")
	}
	if !filepath.IsAbs(app.Executable) {
		return nil, errors.New("registered application executable must be absolute")
	}
	if strings.IndexByte(app.Executable, 0) >= 0 {
		return nil, errors.New("invalid registered application command")
	}
	for _, arg := range app.Args {
		if strings.IndexByte(arg, 0) >= 0 {
			return nil, errors.New("invalid registered application command")
		}
	}
	app.Args = append([]string(nil), app.Args...)
	return &registered{App: app, observational: nameSet(app.Observational), refused: nameSet(app.Refused)}, nil
}

func New(parent context.Context, options *Options) (*Manager, error) {
	m := &Manager{}
	if options == nil {
		return m, nil
	}
	if options.Runner == nil || options.Profile == "" || len(options.Apps) == 0 || len(options.Apps) > MaxApplications {
		return nil, errors.New("incomplete registered application")
	}
	if err := ValidateRoute(options.Container, options.User); err != nil {
		return nil, err
	}
	m.apps = make(map[string]*registered, len(options.Apps))
	names := make([]string, 0, len(options.Apps))
	for _, app := range options.Apps {
		entry, err := register(app)
		if err != nil {
			return nil, err
		}
		if m.apps[entry.Name] != nil {
			return nil, errors.New("registered application names must be unique")
		}
		m.apps[entry.Name] = entry
		names = append(names, entry.Name)
		m.descriptions = append(m.descriptions, Description{Name: entry.Name, Profile: options.Profile, Container: options.Container})
	}
	runner := routeRunner(options.Runner, options.Container, options.User)
	profile := options.Profile
	m.jobs = remote.NewGuardedManager(parent, names, func(ctx context.Context, target, encoded string, stdout, stderr io.Writer) (int, error) {
		var arguments []string
		app := m.apps[target]
		if app == nil || wire.Decode(encoded, &arguments) != nil {
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
		args := append(append([]string(nil), app.Args...), arguments...)
		command := exec.CommandContext(ctx, app.Executable, args...)
		command.Dir = app.Workdir
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
	}, options.Guard)
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
			out.Applications = append(out.Applications, m.descriptions...)
		} else {
			out.Hint = noApplicationHint
		}
		return broker.Result(out, nil), true
	case "app_start", "app_read", "app_cancel":
		if m.jobs == nil {
			return broker.Result(nil, errors.New("no application registered; start the keeper with --app DIR")), true
		}
	default:
		return wire.Reply{}, false
	}
	if request.Operation == "app_start" {
		var input Input
		if wire.Decode(request.Data, &input) != nil {
			return broker.Result(nil, errors.New("invalid application arguments")), true
		}
		if err := m.validateInput(input); err != nil {
			return broker.Result(nil, err), true
		}
		encoded, err := wire.Encode(input.Arguments)
		if err != nil {
			return broker.Result(nil, err), true
		}
		data, err := wire.Encode(remote.StartInput{Target: input.Application, Command: encoded, TimeoutSeconds: input.TimeoutSeconds})
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

// validateInput applies the fixed admission rules and the descriptor's
// command classes. Interactive stdin is refused for every application.
func (m *Manager) validateInput(input Input) error {
	app := m.apps[input.Application]
	if app == nil {
		return errors.New("unknown application; list registered applications with app_list")
	}
	if len(input.Arguments) == 0 || len(input.Arguments) > 128 || !commandName.MatchString(input.Arguments[0]) || input.TimeoutSeconds < 0 || input.TimeoutSeconds > 3600 {
		return errors.New("invalid registered application command or deadline")
	}
	if app.refused[input.Arguments[0]] {
		return errors.New("the application descriptor refuses this command")
	}
	size := 0
	for _, argument := range input.Arguments {
		size += len(argument)
		if strings.IndexByte(argument, 0) >= 0 || argument == "--stdin" || strings.HasPrefix(argument, "--stdin=") {
			return errors.New("application jobs require argv or a local file, not interactive input")
		}
	}
	if size > 8*1024 {
		return errors.New("application argument size limit exceeded")
	}
	if !input.Confirm && !app.observational[input.Arguments[0]] {
		return errors.New("this application operation requires confirm=true and applicable operator authorization")
	}
	return nil
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
